"""Terraform structural repository reconnaissance: path -> RepositoryModel.

Pipeline (each stage consumes only earlier stages; proposal §8)::

    recon.discover        raw artifacts (sorted, repository-relative)
    hcl.parse_terraform   observed facts per block (no evaluation)
    grouping              one TerraformConfiguration per directory
    sources               module sources; local ones resolved relative to the caller
    callgraph             STRUCTURAL call edges, SCCs, cycles
    roots.classify        the approved rule table -> roles, confidence, inferences
    instantiation         deployment contexts, module instances, desired instances
    diagnostics/summary

This is a separate, read-only path. It never fetches remote modules, never
reads state/plan contents or tfvars values, never evaluates expressions, and
is not wired into the production ``flowlens scan``.
"""
from __future__ import annotations

import posixpath
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from flowlens.repository import ids
from flowlens.repository.enums import (
    ArtifactKind,
    BackendKind,
    Confidence,
    ConfigurationRole,
    DeclarationMode,
    FactKind,
    InstantiationReason,
    InstantiationStatus,
    LifecycleStage,
    ModuleSourceKind,
    ParseStatus,
    ProvenanceKind,
    Severity,
)
from flowlens.repository.evidence import Evidence, Locator, ObservedFact
from flowlens.repository.hcl import (
    BLOCK_LABELS,
    MODULE_META_ARGS,
    HclBlock,
    ParsedFile,
    block_facts,
    dynamic_blocks,
    expression_text,
    literal_string,
    parse_error_fact,
    parse_terraform,
    var_file_names,
)
from flowlens.repository.model import (
    BackendEvidence,
    BlockSummary,
    Cardinality,
    Classification,
    ConfigurationLifecycle,
    DeploymentContext,
    DesiredResourceInstance,
    Diagnostic,
    InstantiationRecord,
    MetaArguments,
    ModuleCall,
    ModuleInstance,
    ModuleSource,
    RawArtifact,
    RepositoryAnchor,
    RepositoryModel,
    ResourceDeclaration,
    SourceFileRef,
    StateArtifact,
    TerraformConfiguration,
    VarFileArtifact,
)
from flowlens.repository.recon import DirectoryListing, DiscoveredFile, Discovery, directory_exists, discover, in_scan_root, load_directory
from flowlens.repository.redact import REDACTED
from flowlens.repository.roots import Call, ConfigInput, classify
from flowlens.repository.sources import SourceSpec, classify_source

#: Path segments treated as a (weak, never decisive) module name hint: M-HINT.
MODULE_HINT_SEGMENTS = frozenset({"modules", "module"})
_MAX_MODULE_DEPTH = 32
_VAR_KINDS = (ArtifactKind.TFVARS, ArtifactKind.AUTO_TFVARS, ArtifactKind.TFVARS_JSON)


def _autoloaded(path: str) -> bool:
    name = posixpath.basename(path)
    return name in ("terraform.tfvars", "terraform.tfvars.json") or name.endswith((".auto.tfvars", ".auto.tfvars.json"))


# --------------------------------------------------------------------------- per-configuration working state


@dataclass
class _Block:
    file: DiscoveredFile
    block: HclBlock
    facts: list[ObservedFact]

    def fact(self, kind: FactKind) -> ObservedFact | None:
        return next((f for f in self.facts if f.kind is kind), None)


@dataclass
class _Config:
    path: str
    listing: DirectoryListing
    dir_artifact: RawArtifact
    dir_fact: ObservedFact
    blocks: list[_Block] = field(default_factory=list)
    file_status: dict[str, ParseStatus] = field(default_factory=dict)   # artifact id -> status
    parse_errors: list[ObservedFact] = field(default_factory=list)
    hint_facts: list[ObservedFact] = field(default_factory=list)

    @property
    def id(self) -> str:
        return ids.configuration_id(self.path)

    @property
    def parse_status(self) -> ParseStatus:
        statuses = set(self.file_status.values())
        if statuses == {ParseStatus.COMPLETE}:
            return ParseStatus.COMPLETE
        if ParseStatus.COMPLETE in statuses:
            return ParseStatus.PARTIAL
        return ParseStatus.FAILED

    def of_kind(self, *kinds: str, include_override: bool = True) -> list[_Block]:
        return [b for b in self.blocks if b.block.kind in kinds and (include_override or b.file.kind is not ArtifactKind.TF_OVERRIDE)]


@dataclass
class _CallInfo:
    call: ModuleCall
    spec: SourceSpec | None
    source_id: str
    fact: ObservedFact
    resolved_target: str | None     # configuration path for a readable local source


class _Builder:
    def __init__(self, discovery: Discovery) -> None:
        self.discovery = discovery
        self.facts: dict[str, ObservedFact] = {}
        self.evidence: dict[str, Evidence] = {}
        self.diagnostics: dict[str, Diagnostic] = {}
        self.extra_artifacts: dict[str, RawArtifact] = {}
        self.configs: dict[str, _Config] = {}
        self.artifact_facts: dict[str, ObservedFact] = {}   # artifact id -> ARTIFACT_PRESENT fact
        self.var_names: dict[str, tuple[str, ...] | None] = {}

    # ---- small helpers

    def fact(self, f: ObservedFact) -> ObservedFact:
        self.facts.setdefault(f.id, f)
        return self.facts[f.id]

    def ev(self, e: Evidence) -> Evidence:
        self.evidence.setdefault(e.id, e)
        return self.evidence[e.id]

    def diag(self, code: str, severity: Severity, subject: str, message: str, evidence: Iterable[str] = ()) -> None:
        d = Diagnostic(code, severity, subject, message, tuple(evidence))
        self.diagnostics.setdefault(d.id, d)

    def presence(self, artifact: RawArtifact) -> ObservedFact:
        if artifact.id not in self.artifact_facts:
            payload = {"kind": artifact.kind.value if artifact.kind else None}
            self.artifact_facts[artifact.id] = self.fact(ObservedFact(artifact.id, Locator(), FactKind.ARTIFACT_PRESENT, payload))
        return self.artifact_facts[artifact.id]

    # ---- stage: configurations

    def add_configuration(self, listing: DirectoryListing) -> _Config:
        path = listing.path
        dir_art = RawArtifact(path, ArtifactKind.DIRECTORY)
        self.extra_artifacts[dir_art.id] = dir_art
        n_files = len(listing.config_files)
        dir_fact = self.fact(ObservedFact(dir_art.id, Locator(), FactKind.ARTIFACT_PRESENT,
                                          {"kind": "configuration_directory", "terraform_files": n_files}))
        cfg = _Config(path, listing, dir_art, dir_fact)
        for seg in sorted({s for s in path.split("/") if s in MODULE_HINT_SEGMENTS}):
            cfg.hint_facts.append(self.fact(ObservedFact(dir_art.id, Locator(labels=(seg,)), FactKind.PATH_SEGMENT, {"segment": seg})))
        for f in sorted(listing.config_files, key=lambda f: f.path):
            self._parse_file(cfg, f)
        self.configs[path] = cfg
        return cfg

    def _parse_file(self, cfg: _Config, f: DiscoveredFile) -> None:
        art = f.artifact
        if f.text is None:
            cfg.file_status[art.id] = ParseStatus.FAILED
            fact = self.fact(ObservedFact(art.id, Locator(), FactKind.PARSE_ERROR, {"error": f"not read ({art.read_status.value})"}))
            cfg.parse_errors.append(fact)
            return
        parsed: ParsedFile = parse_terraform(f.text, json_syntax=f.path.endswith(".json"))
        if not parsed.ok:
            cfg.file_status[art.id] = ParseStatus.FAILED
            fact = self.fact(parse_error_fact(art.id, parsed))
            cfg.parse_errors.append(fact)
            ev = self.ev(Evidence(ProvenanceKind.OBSERVED, "file.parse_failed", cfg.id, (fact.id,), Confidence.CERTAIN,
                                  detail=f"{f.path} failed to parse"))
            where = f" (line {parsed.error_line})" if parsed.error_line else ""
            self.diag("RI-PARSE-FAILED", Severity.WARNING, cfg.id, f"{f.path}{where}: failed to parse, skipped: {parsed.error}", (ev.id,))
            return
        cfg.file_status[art.id] = ParseStatus.COMPLETE
        for construct in parsed.unsupported:
            self.diag("RI-UNSUPPORTED-CONSTRUCT", Severity.INFO, art.id, f"{f.path}: {construct} is not modeled")
        for block in parsed.blocks:
            if block.kind not in BLOCK_LABELS:
                self.diag("RI-UNSUPPORTED-CONSTRUCT", Severity.INFO, art.id,
                          f"{f.path}: block kind {block.kind!r} recorded as present but not modeled")
            cfg.blocks.append(_Block(f, block, [self.fact(x) for x in block_facts(art.id, block)]))
        if f.kind is ArtifactKind.TF_OVERRIDE:
            self.diag("RI-OVERRIDE-FILE-UNMERGED", Severity.INFO, cfg.id,
                      f"{f.path}: override file recorded; its blocks are merge overrides, not new declarations "
                      "(merge semantics are not applied)")

    # ---- stage: module calls and sources

    def module_calls(self, cfg: _Config) -> list[tuple[_Block, str, SourceSpec | None, str | None]]:
        """(block, name, spec, raw source) for each non-override module block, first definition wins."""
        seen: dict[str, _Block] = {}
        out = []
        for b in sorted(cfg.of_kind("module", include_override=False), key=lambda b: (b.file.path, b.block.line_start or 0)):
            name = b.block.labels[0] if b.block.labels else ""
            if name in seen:
                self.diag("RI-DUPLICATE-MODULE-CALL", Severity.WARNING, cfg.id,
                          f"{b.file.path}: module {name!r} is already declared in {seen[name].file.path}; kept the first")
                continue
            seen[name] = b
            raw = literal_string(b.block.body.get("source"))
            spec = classify_source(cfg.path, raw) if raw is not None else None
            out.append((b, name, spec, raw))
        return out

    def load_out_of_scan(self) -> None:
        """Follow local sources that leave the scan root (but not the anchor)
        until every reachable local source directory is loaded."""
        pending = sorted(self.configs)
        while pending:
            path = pending.pop(0)
            for _b, _name, spec, _raw in self.module_calls(self.configs[path]):
                if spec is None or spec.kind is not ModuleSourceKind.LOCAL:
                    continue
                target = spec.locator
                if target in self.configs or ids.is_outside(target) or in_scan_root(self.discovery, target):
                    continue
                listing = load_directory(self.discovery, target)
                if listing is not None and listing.config_files:
                    self.add_configuration(listing)
                    self.diag("RI-SOURCE-OUT-OF-SCAN", Severity.INFO, ids.configuration_id(target),
                              f"{target}: outside the scan root, loaded because {path} calls it")
                    pending.append(target)
            pending.sort()


def _meta(body, *, module: bool = False, block: HclBlock | None = None) -> MetaArguments:
    return MetaArguments(
        count=expression_text(body["count"]) if "count" in body else None,
        for_each=expression_text(body["for_each"]) if "for_each" in body else None,
        dynamic_blocks=tuple(n for n, _ in dynamic_blocks(block)) if block is not None and not module else (),
        depends_on="depends_on" in body,
        lifecycle="lifecycle" in body,
        provider=expression_text(body["provider"]) if "provider" in body and not module else None,
    )


# --------------------------------------------------------------------------- public API


def analyze_repository(path: str | Path) -> RepositoryModel:
    """Build the RepositoryModel for the Terraform repository at `path`."""
    discovery = discover(path)
    b = _Builder(discovery)
    for d in discovery.diagnostics:
        b.diagnostics.setdefault(d.id, d)

    # 1. configurations (one per directory with .tf/.tf.json material), plus out-of-scan local sources
    for rel_dir in discovery.configuration_dirs():
        b.add_configuration(discovery.directories[rel_dir])
    b.load_out_of_scan()
    for d in discovery.diagnostics:
        b.diagnostics.setdefault(d.id, d)

    # 2. presence artifacts: var files, lock files, state, .terraform/
    var_files: list[VarFileArtifact] = []
    state_artifacts: list[StateArtifact] = []
    for listing in discovery.sorted_directories():
        for f in listing.files:
            if f.kind in _VAR_KINDS:
                names: tuple[str, ...] | None = None
                if f.text is not None:
                    try:
                        names = var_file_names(f.text, json_syntax=f.path.endswith(".json"))
                    except Exception as exc:
                        b.diag("RI-VARFILE-UNPARSEABLE", Severity.WARNING, f.artifact.id,
                               f"{f.path}: variable names could not be read ({type(exc).__name__})")
                b.var_names[f.artifact.id] = names
                var_files.append(VarFileArtifact(f.path, variable_names=names or ()))
                b.presence(f.artifact)
            elif f.kind in (ArtifactKind.LOCKFILE, ArtifactKind.TFSTATE):
                b.presence(f.artifact)
                if f.kind is ArtifactKind.TFSTATE:
                    state_artifacts.append(StateArtifact(f.path))
        if listing.dot_terraform is not None:
            b.presence(listing.dot_terraform)

    # 3. declarations, module calls, sources
    declarations: dict[str, ResourceDeclaration] = {}
    decls_by_cfg: dict[str, list[ResourceDeclaration]] = defaultdict(list)
    calls_by_cfg: dict[str, list[_CallInfo]] = defaultdict(list)
    source_variants: dict[str, dict[str, set]] = defaultdict(lambda: {"version": set(), "ref": set()})
    sources: dict[str, ModuleSource] = {}
    structural_calls: list[Call] = []
    for path in sorted(b.configs):
        cfg = b.configs[path]
        first: dict[tuple, _Block] = {}
        for blk in sorted(cfg.of_kind("resource", "data", include_override=False), key=lambda x: (x.file.path, x.block.line_start or 0)):
            if len(blk.block.labels) < 2:
                continue
            mode = DeclarationMode.MANAGED if blk.block.kind == "resource" else DeclarationMode.DATA
            key = (mode, blk.block.labels[0], blk.block.labels[1])
            if key in first:
                addr = f"{'data.' if mode is DeclarationMode.DATA else ''}{key[1]}.{key[2]}"
                b.diag("RI-DUPLICATE-DECLARATION", Severity.WARNING, cfg.id,
                       f"{blk.file.path}: {addr} is already declared in {first[key].file.path}; kept the first")
                continue
            first[key] = blk
            decl_id = ids.declaration_id(path, mode, key[1], key[2])
            present = blk.fact(FactKind.BLOCK_PRESENT)
            assert present is not None
            ev = b.ev(Evidence(ProvenanceKind.OBSERVED, "decl.block_present", decl_id, (present.id,), Confidence.CERTAIN,
                               detail=f"{blk.file.path} declares {blk.block.kind} {key[1]}.{key[2]}"))
            decl = ResourceDeclaration(path, mode, key[1], key[2], _meta(blk.block.body, block=blk.block), ev.id)
            declarations[decl.id] = decl
            decls_by_cfg[path].append(decl)

        for blk, name, spec, raw in b.module_calls(cfg):
            src_fact = blk.fact(FactKind.MODULE_SOURCE_LITERAL)
            assert src_fact is not None
            call_id = ids.module_call_id(path, name)
            call_ev = b.ev(Evidence(ProvenanceKind.OBSERVED, "call.module_block", call_id, (src_fact.id,), Confidence.CERTAIN,
                                    detail=f"{blk.file.path} declares module {name}"))
            resolved_target: str | None = None
            if spec is None:
                expr = expression_text(blk.block.body.get("source")) if "source" in blk.block.body else "<missing>"
                spec = SourceSpec(ModuleSourceKind.OTHER, expr, expr)
                b.diag("RI-SOURCE-NOT-LITERAL", Severity.WARNING, call_id,
                       f"{blk.file.path}: module {name} source is not a literal string ({expr}); the call stays a declaration")
                ms = ModuleSource(ModuleSourceKind.OTHER, expr, raw_source=expr)
            elif spec.kind is ModuleSourceKind.LOCAL:
                target = spec.locator
                if target in b.configs:
                    resolved_target = target
                elif ids.is_outside(target):
                    b.diag("RI-SOURCE-OUTSIDE-ANCHOR", Severity.WARNING, call_id,
                           f"{blk.file.path}: module {name} source {spec.raw!r} resolves outside the repository anchor; not read")
                else:
                    why = "directory has no Terraform files" if directory_exists(discovery, target) else "directory does not exist"
                    b.diag("RI-SOURCE-UNREADABLE", Severity.WARNING, call_id,
                           f"{blk.file.path}: module {name} source {spec.raw!r} -> {target}: {why}; the call stays a declaration")
                ms = ModuleSource(ModuleSourceKind.LOCAL, target, raw_source=target, resolved=resolved_target is not None)
            else:
                if "version" in blk.block.body:
                    version = literal_string(blk.block.body["version"]) or expression_text(blk.block.body["version"])
                    source_variants[ModuleSource(spec.kind, spec.locator).id]["version"].add(version)
                ms = ModuleSource(spec.kind, spec.locator, raw_source=spec.raw)
                source_variants[ms.id]["ref"].add(spec.ref)
                b.diag("RI-SOURCE-NOT-FETCHED", Severity.INFO, call_id,
                       f"{blk.file.path}: module {name} uses a {spec.kind.value} source, not fetched (contents UNKNOWN): {spec.raw}")
            sources.setdefault(ms.id, ms)
            evidence_id = call_ev.id
            if resolved_target is not None:
                st = b.ev(Evidence(ProvenanceKind.STRUCTURAL, "call.resolves_to", call_id, (src_fact.id,), Confidence.CERTAIN,
                                   detail=f"{raw!r} from {path} resolves to {resolved_target}"))
                evidence_id = st.id
                structural_calls.append(Call(path, resolved_target, name, src_fact))
            body = blk.block.body
            call = ModuleCall(path, name, ms.id, _meta(body, module=True), evidence_id,
                              inputs=tuple(k for k in body if k not in MODULE_META_ARGS))
            calls_by_cfg[path].append(_CallInfo(call, spec, ms.id, src_fact, resolved_target))

    # version/ref are per call; keep them on the source only when every call agrees
    for sid, variants in sorted(source_variants.items()):
        ms = sources[sid]
        versions = {v for v in variants["version"] if v is not None}
        refs = {r for r in variants["ref"] if r is not None}
        if len(versions) > 1 or len(refs) > 1:
            b.diag("RI-MODULE-SOURCE-VARIANTS", Severity.INFO, sid,
                   f"{sid}: called with differing version/ref constraints; recorded per call only")
        sources[sid] = ModuleSource(ms.kind, ms.locator, raw_source=ms.raw_source,
                                    version_constraint=next(iter(versions)) if len(versions) == 1 else None,
                                    ref=next(iter(refs)) if len(refs) == 1 else None)

    # 4. classification inputs and the rule table
    inputs: dict[str, ConfigInput] = {}
    for path in sorted(b.configs):
        cfg = b.configs[path]
        listing = cfg.listing
        backend_kinds = (FactKind.BACKEND_BLOCK, FactKind.CLOUD_BLOCK)
        backend_facts = [f for blk in cfg.of_kind("terraform") for f in blk.facts if f.kind in backend_kinds]
        var_arts = listing.of_kind(*_VAR_KINDS)
        inputs[path] = ConfigInput(
            path=path,
            parse_status=cfg.parse_status,
            directory_fact=cfg.dir_fact,
            parse_errors=tuple(cfg.parse_errors),
            backend_facts=tuple(backend_facts),
            state_facts=tuple(b.presence(f.artifact) for f in listing.of_kind(ArtifactKind.TFSTATE)),
            autoload_var_facts=tuple(b.presence(f.artifact) for f in var_arts if _autoloaded(f.path)),
            lock_facts=tuple(b.presence(f.artifact) for f in listing.of_kind(ArtifactKind.LOCKFILE)),
            dottf_facts=(b.presence(listing.dot_terraform),) if listing.dot_terraform is not None else (),
            provider_facts=tuple(f for blk in cfg.of_kind("provider") for f in blk.facts if f.kind is FactKind.PROVIDER_CONFIG),
            variable_facts=tuple(f for blk in cfg.of_kind("variable") for f in blk.facts if f.kind is FactKind.VARIABLE_DECLARED),
            var_files=tuple((b.presence(f.artifact), b.var_names.get(f.artifact.id)) for f in var_arts),
            hint_facts=tuple(cfg.hint_facts),
        )
        if len(backend_facts) > 1:
            b.diag("RI-DUPLICATE-BACKEND", Severity.WARNING, cfg.id, f"{path}: {len(backend_facts)} backend/cloud blocks declared")
    decisions = classify(inputs, structural_calls, b.facts)
    for d in decisions.values():
        for e in d.evidence:
            b.ev(e)

    # 5. backend evidence, deployment contexts
    backends: dict[str, BackendEvidence] = {}
    backend_by_cfg: dict[str, str] = {}
    for path in sorted(b.configs):
        r_backend = next((e for e in decisions[path].evidence if e.claim == "R-BACKEND"), None)
        for fact in inputs[path].backend_facts:
            p = dict(fact.payload)
            kind = BackendKind.CLOUD if fact.kind is FactKind.CLOUD_BLOCK else BackendKind.BACKEND
            names = [n for n in str(p.get("attribute_names") or "").split(",") if n]
            be = BackendEvidence(path, kind, p.get("backend_type") if kind is BackendKind.BACKEND else None,  # type: ignore[arg-type]
                                 dict.fromkeys(names, REDACTED), partial_config=not names,
                                 evidence=r_backend.id if r_backend else None)
            if be.id not in backends:
                backends[be.id] = be
                backend_by_cfg.setdefault(path, be.id)
    var_ids_by_dir: dict[str, list[str]] = defaultdict(list)
    for vf in var_files:
        var_ids_by_dir[posixpath.dirname(vf.path) or "."].append(vf.id)

    contexts: dict[str, DeploymentContext] = {}
    for path in sorted(decisions):
        d = decisions[path]
        if d.has_root_context:
            ctx = DeploymentContext(path, d.role, d.confidence, var_files=tuple(var_ids_by_dir.get(path, ())),
                                    backend=backend_by_cfg.get(path))
            contexts[path] = ctx

    # 6. instantiation walk per root context
    module_instances: dict[str, ModuleInstance] = {}
    resource_instances: dict[str, DesiredResourceInstance] = {}
    instances_by_cfg: dict[str, set[str]] = defaultdict(set)

    def walk(ctx: DeploymentContext, cfg_path: str, prefix: str, expansions: tuple[tuple[str, str], ...], stack: tuple[str, ...]) -> None:
        for info in sorted(calls_by_cfg.get(cfg_path, []), key=lambda i: i.call.name):
            call = info.call
            module_path = f"{prefix}module.{call.name}"
            exp = expansions + (((module_path, call.meta.expansion_expression or ""),) if call.meta.expands else ())
            src = sources[info.source_id]
            if src.kind is ModuleSourceKind.LOCAL:
                target = info.resolved_target
                if target is None:
                    b.diag("RI-INSTANCE-DEFERRED", Severity.INFO, call.id,
                           f"{ctx.id}::{module_path}: not instantiated ({InstantiationReason.SOURCE_UNREADABLE.value})")
                    continue
                if decisions[target].role is ConfigurationRole.UNKNOWN:
                    b.diag("RI-INSTANCE-DEFERRED", Severity.INFO, call.id,
                           f"{ctx.id}::{module_path}: not instantiated, source {target} could not be parsed "
                           f"({InstantiationReason.PARSE_FAILED.value})")
                    continue
                if target in stack:
                    b.diag("RI-MODULE-CYCLE-CUT", Severity.INFO, call.id,
                           f"{ctx.id}::{module_path}: {target} is already on the call path; cycle cut here")
                    continue
                if len(stack) > _MAX_MODULE_DEPTH:
                    b.diag("RI-MODULE-DEPTH", Severity.WARNING, call.id,
                           f"{ctx.id}::{module_path}: nesting deeper than {_MAX_MODULE_DEPTH}")
                    continue
            else:
                target = None
            card = Cardinality.unknown(" x ".join(e for _, e in exp)) if exp else None
            mi = ModuleInstance(ctx.id, module_path, call.id, src.id, source_configuration=ids.configuration_id(target) if target else None,
                                expanded_by=tuple(p for p, _ in exp), cardinality=card)
            module_instances[mi.id] = mi
            if target is None:
                continue  # remote source: contents UNKNOWN, never fetched
            instances_by_cfg[target].add(mi.id)
            for decl in decls_by_cfg.get(target, []):
                ri = DesiredResourceInstance.derive(ctx, decl, mi)
                resource_instances[ri.id] = ri
            walk(ctx, target, module_path + ".", exp, (*stack, target))

    for path in sorted(contexts):
        ctx = contexts[path]
        for decl in decls_by_cfg.get(path, []):
            ri = DesiredResourceInstance.derive(ctx, decl)
            resource_instances[ri.id] = ri
        walk(ctx, path, "", (), (path,))

    # 7. configurations with lifecycle + classification; decision diagnostics
    configurations: list[TerraformConfiguration] = []
    ambiguities = []
    cycles_reported: set[str] = set()
    for path in sorted(b.configs):
        cfg, d = b.configs[path], decisions[path]
        status, reason = d.status, d.reason
        instances = tuple(sorted(instances_by_cfg.get(path, ())))
        ctx_ids = (contexts[path].id,) if path in contexts else ()
        if status in (InstantiationStatus.RESOLVED_INSTANCES, InstantiationStatus.RESOLVED_BOTH) and not instances:
            # defensive: the walk never reached a configuration the rule table expected to be instantiated
            b.diag("RI-INSTANCE-DEFERRED", Severity.WARNING, cfg.id, f"{path}: expected module instances, none were reached")
            if status is InstantiationStatus.RESOLVED_BOTH:
                status = InstantiationStatus.RESOLVED_ROOT
            else:
                status, reason = InstantiationStatus.DEFERRED, InstantiationReason.CALLER_DEFERRED
        record = InstantiationRecord(status, reason, d.inference.id if reason is not None else None,
                                     ctx_ids if status not in (InstantiationStatus.DEFERRED, InstantiationStatus.NOT_APPLICABLE) else (),
                                     instances if status not in (InstantiationStatus.DEFERRED, InstantiationStatus.NOT_APPLICABLE) else ())
        kinds = Counter(blk.block.kind for blk in cfg.blocks)
        configurations.append(TerraformConfiguration(
            path,
            files=tuple(SourceFileRef(aid, st) for aid, st in sorted(cfg.file_status.items())),
            parse_status=cfg.parse_status,
            block_summary=BlockSummary.of(kinds),
            lifecycle=ConfigurationLifecycle(LifecycleStage.INSTANTIATED, record),
            classification=Classification(d.role, d.confidence, d.root_role, d.module_role, d.inference.id),
            outside_scan_root=cfg.listing.outside_scan_root,
        ))
        if d.ambiguity is not None:
            ambiguities.append(d.ambiguity)
        n_decl = len(decls_by_cfg.get(path, []))
        if d.role is ConfigurationRole.AMBIGUOUS:
            b.diag("RI-AMBIGUOUS-CONFIGURATION", Severity.WARNING, cfg.id,
                   f"{path}: AMBIGUOUS ({d.rule_id}); instantiation deferred ({reason.value if reason else '-'}); "
                   f"{n_decl} resource declarations kept, not instantiated", d.inference.supporting + d.inference.contrary)
        elif d.role is ConfigurationRole.UNKNOWN:
            b.diag("RI-UNKNOWN-CLASSIFICATION", Severity.WARNING, cfg.id,
                   f"{path}: UNKNOWN (no file could be parsed); instantiation deferred (PARSE_FAILED)", d.inference.supporting)
        elif status is InstantiationStatus.NOT_APPLICABLE:
            b.diag("RI-UNUSED-MODULE-SOURCE", Severity.INFO, cfg.id,
                   f"{path}: unused module source ({d.rule_id}); {n_decl} resource declarations kept, not instantiated",
                   d.inference.supporting)
        if reason is InstantiationReason.ROOT_ROLE_WEAK:
            b.diag("RI-INSTANTIATION-DEFERRED", Severity.INFO, cfg.id,
                   f"{path}: possible dual role (LOW); root instantiation deferred (ROOT_ROLE_WEAK)", d.inference.contrary)
        elif status is InstantiationStatus.DEFERRED:
            b.diag("RI-INSTANTIATION-DEFERRED", Severity.INFO, cfg.id,
                   f"{path}: instantiation deferred ({reason.value if reason else '-'})")
        if d.cyclic and path not in cycles_reported:
            members = _cycle_members(path, structural_calls)
            cycles_reported.update(members)
            b.diag("RI-MODULE-CYCLE", Severity.WARNING, ids.configuration_id(members[0]),
                   "local module cycle: " + " -> ".join((*members, members[0])))

    artifacts = {a.id: a for a in discovery.artifacts()}
    artifacts.update(b.extra_artifacts)
    model = RepositoryModel(
        RepositoryAnchor.from_resolution(discovery.anchor),
        artifacts=tuple(artifacts.values()),
        facts=tuple(b.facts.values()),
        configurations=tuple(configurations),
        module_sources=tuple(sources.values()),
        module_calls=tuple(i.call for infos in calls_by_cfg.values() for i in infos),
        deployment_contexts=tuple(contexts.values()),
        module_instances=tuple(module_instances.values()),
        resource_declarations=tuple(declarations.values()),
        resource_instances=tuple(resource_instances.values()),
        backend_evidence=tuple(backends.values()),
        state_artifacts=tuple(state_artifacts),
        var_files=tuple(var_files),
        evidence=tuple(b.evidence.values()),
        inferences=tuple(d.inference for d in decisions.values()),
        ambiguities=tuple(ambiguities),
        diagnostics=tuple(b.diagnostics.values()),
    )
    return model


def build_repository_model(repo_root: str | Path) -> RepositoryModel:
    """Public reconnaissance entry point: Terraform repository at `repo_root`
    -> RepositoryModel. Read-only, offline, deterministic."""
    return analyze_repository(repo_root)


def _cycle_members(start: str, calls: list[Call]) -> tuple[str, ...]:
    """Members of the cycle through `start`, sorted (deterministic rendering)."""
    edges: dict[str, set[str]] = defaultdict(set)
    for c in calls:
        edges[c.caller].add(c.callee)

    def reach(src: str, rev: bool) -> set[str]:
        seen, todo = set(), [src]
        while todo:
            n = todo.pop()
            nxt = {a for a, bs in edges.items() if n in bs} if rev else edges.get(n, set())
            for m in nxt:
                if m not in seen:
                    seen.add(m)
                    todo.append(m)
        return seen

    members = (reach(start, False) & reach(start, True)) | {start}
    return tuple(sorted(members))


# --------------------------------------------------------------------------- summary


@dataclass(frozen=True)
class ReconSummary:
    """Programmatic summary of a RepositoryModel (counts per deployment
    context, never deduplicated across contexts)."""

    configurations: int
    role_counts: tuple[tuple[str, int], ...]
    confirmed_roots: tuple[str, ...]
    probable_roots: tuple[tuple[str, str], ...]       # (path, confidence)
    module_sources: tuple[str, ...]                   # instantiated via callers
    unused_module_sources: tuple[str, ...]
    dual_roles: tuple[str, ...]
    ambiguous: tuple[tuple[str, str], ...]            # (path, reason)
    unknown: tuple[str, ...]
    local_module_relationships: tuple[tuple[str, str, str], ...]   # (caller, module.<name>, source path)
    external_module_calls: tuple[tuple[str, str], ...]             # (call id, module source id)
    resource_declarations: int
    not_instantiated_declarations: int
    deferred_declarations: int
    deployment_contexts: tuple[str, ...]
    module_instances: int
    desired_instances: int
    template_instances: int
    diagnostics: tuple[tuple[str, int], ...]           # (severity, count)
    diagnostic_codes: tuple[tuple[str, int], ...]

    def render(self) -> str:
        lines = [f"{self.configurations} Terraform configurations: " + ", ".join(f"{r} {n}" for r, n in self.role_counts)]
        lines.append(f"  confirmed roots:  {', '.join(self.confirmed_roots) or '-'}")
        lines.append(f"  probable roots:   {', '.join(f'{p} ({c})' for p, c in self.probable_roots) or '-'}")
        lines.append(f"  dual roles:       {', '.join(self.dual_roles) or '-'}")
        lines.append(f"  module sources:   {', '.join(self.module_sources) or '-'}")
        lines.append(f"  unused modules:   {', '.join(self.unused_module_sources) or '-'}")
        lines.append(f"  ambiguous:        {', '.join(f'{p} ({r})' for p, r in self.ambiguous) or '-'}")
        lines.append(f"  unknown:          {', '.join(self.unknown) or '-'}")
        lines.append(f"  local module relationships: {len(self.local_module_relationships)}")
        lines.extend(f"    {c} --{m}--> {s}" for c, m, s in self.local_module_relationships)
        lines.append(f"  external (unfetched) module calls: {len(self.external_module_calls)}")
        lines.append(f"  resource declarations: {self.resource_declarations} "
                     f"({self.not_instantiated_declarations} not instantiated, {self.deferred_declarations} in deferred configurations)")
        lines.append(f"  deployment contexts: {len(self.deployment_contexts)}; module instances: {self.module_instances}; "
                     f"desired instances: {self.desired_instances} ({self.template_instances} templates, N = unknown)")
        lines.append("  diagnostics: " + (", ".join(f"{s} {n}" for s, n in self.diagnostics) or "none"))
        return "\n".join(lines)


def summarize(model: RepositoryModel) -> ReconSummary:
    R, S = ConfigurationRole, InstantiationStatus
    by_role: dict[ConfigurationRole, list[TerraformConfiguration]] = defaultdict(list)
    for c in model.configurations:
        if c.role is not None:
            by_role[c.role].append(c)

    def status(c: TerraformConfiguration) -> InstantiationStatus | None:
        return c.lifecycle.instantiation.status if c.lifecycle.instantiation else None

    sources = {s.id: s for s in model.module_sources}
    local_rel, external = [], []
    for call in model.module_calls:
        src = sources[call.source]
        if src.kind is ModuleSourceKind.LOCAL:
            local_rel.append((call.caller_path, call.address, src.locator + ("" if src.resolved else " (unresolved)")))
        else:
            external.append((call.id, src.id))
    inventory = model.declaration_inventory()
    deferred = sum(len(e.not_instantiated) for e in inventory.configurations_with_status(S.DEFERRED))
    live = model.desired_instances()
    sev = Counter(d.severity.value for d in model.diagnostics)
    codes = Counter(d.code for d in model.diagnostics)
    return ReconSummary(
        configurations=len(model.configurations),
        role_counts=tuple(model.role_counts().items()),
        confirmed_roots=tuple(c.path for c in by_role[R.CONFIRMED_ROOT]),
        probable_roots=tuple((c.path, c.classification.confidence.value) for c in by_role[R.PROBABLE_ROOT] if c.classification),
        module_sources=tuple(c.path for c in by_role[R.MODULE_SOURCE] if status(c) is not S.NOT_APPLICABLE),
        unused_module_sources=tuple(c.path for c in by_role[R.MODULE_SOURCE] if status(c) is S.NOT_APPLICABLE),
        dual_roles=tuple(c.path for c in by_role[R.DUAL_ROLE]),
        ambiguous=tuple((c.path, c.lifecycle.instantiation.reason.value if c.lifecycle.instantiation and c.lifecycle.instantiation.reason
                         else "-") for c in by_role[R.AMBIGUOUS]),
        unknown=tuple(c.path for c in by_role[R.UNKNOWN]),
        local_module_relationships=tuple(sorted(local_rel)),
        external_module_calls=tuple(sorted(external)),
        resource_declarations=len(model.resource_declarations),
        not_instantiated_declarations=len(inventory.not_instantiated_declarations),
        deferred_declarations=deferred,
        deployment_contexts=tuple(c.id for c in model.deployment_contexts),
        module_instances=len(model.module_instances),
        desired_instances=len(live),
        template_instances=sum(1 for i in live if i.template),
        diagnostics=tuple(sorted(sev.items())),
        diagnostic_codes=tuple(sorted(codes.items())),
    )
