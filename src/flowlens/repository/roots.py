"""Root / module inference: the approved decision table (proposal §19), rules v1.

Pure and deterministic: (per-configuration facts, structural call edges) ->
one :class:`Decision` per configuration. No I/O, no dependence on input order.
Collection code (``recon``, ``hcl``) never imports this module.

Evidence signals (strong -> HIGH, medium -> MEDIUM, weak -> LOW)::

    R-BACKEND  backend/cloud block                           root    strong
    R-STATE    co-located *.tfstate artifact                 root    strong
    R-CI       CI runs terraform here (Phase 3; never emitted) root  strong
    R-TFVARS   terraform.tfvars / *.auto.tfvars present      root    medium
    R-LOCK     .terraform.lock.hcl present                   root    medium
    R-DOTTF    .terraform/ directory present                 root    medium
    R-PROVIDER non-alias provider block with configuration   root    medium if uncalled / weak if called
    R-UNCALLED no instantiated caller                        root    weak (absence)
    R-DEFAULTS every variable has a default                  root    weak
    M-CALLED   called by an instantiated configuration       module  CERTAIN (structural)
    M-REQVAR   required variable not provided by a var file  module  medium
    M-NOPROV   no provider block at all                      module  weak
    M-HINT     path segment `modules`/`module`               module  weak (name hint, never decisive)
    M-DEFERRED-CALLER called only by non-instantiated configs module weak

"Strong root evidence" = R-BACKEND or R-STATE or R-CI, or two or more
*independent* medium root signals (C-corroborate; independence per
:func:`flowlens.repository.evidence.independent`: different claims resting on
disjoint artifacts - one HCL construct is one signal however it is read).

Rules, applied per SCC of the call graph in topological order (callers first):

    ROLE-P1  every file failed to parse                 -> UNKNOWN, DEFERRED(PARSE_FAILED)
    ROLE-X1  in a module cycle with no external
             instantiated caller                        -> AMBIGUOUS, DEFERRED(CYCLE_ONLY)
    no instantiated caller:
    ROLE-U1  strong root                                -> CONFIRMED_ROOT (HIGH)
    ROLE-U2  medium root, module < medium               -> PROBABLE_ROOT (MEDIUM)
    ROLE-U3  root >= medium and module >= medium        -> AMBIGUOUS, DEFERRED(AMBIGUOUS_ROLE)
    ROLE-U4  module >= medium, root only weak           -> MODULE_SOURCE unused (MEDIUM), NOT_APPLICABLE
                                                           (C-partial: AMBIGUOUS if a file failed to parse)
    ROLE-U5  nothing >= medium                          -> PROBABLE_ROOT (LOW), instantiated
    ROLE-X2  U2/U5 outcome, but the configuration is
             called only by non-instantiated configs    -> AMBIGUOUS, DEFERRED(CALLER_DEFERRED)
    at least one instantiated caller:
    ROLE-C1  strong root                                -> DUAL_ROLE (HIGH): root context + instances
    ROLE-C2  exactly one medium root signal             -> MODULE_SOURCE, root_role candidate (LOW),
                                                           root DEFERRED (ROOT_ROLE_WEAK)
    ROLE-C3  otherwise                                  -> MODULE_SOURCE (HIGH if every instantiated
                                                           caller >= MEDIUM, else the minimum)
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from flowlens.repository import ids
from flowlens.repository.callgraph import is_cyclic, strongly_connected_components
from flowlens.repository.enums import (
    AmbiguityKind,
    Confidence,
    ConfigurationRole,
    EvidenceBasis,
    InstantiationReason,
    InstantiationStatus,
    ParseStatus,
    ProvenanceKind,
    RoleStatus,
    min_confidence,
)
from flowlens.repository.evidence import Alternative, Ambiguity, Evidence, Inference, ObservedFact, independent
from flowlens.repository.model import RoleAssessment

RULES_VERSION = 1

STRONG_ROOT = ("R-BACKEND", "R-STATE", "R-CI")
_ROOT_SIGNAL_TEXT = {
    "R-BACKEND": "R-BACKEND (backend or cloud block)",
    "R-STATE": "R-STATE (co-located state artifact)",
    "R-CI": "R-CI (CI step running terraform here; Phase 3)",
    "R-TFVARS": "R-TFVARS (terraform.tfvars / *.auto.tfvars)",
    "R-LOCK": "R-LOCK (.terraform.lock.hcl)",
    "R-DOTTF": "R-DOTTF (.terraform/ directory)",
}
_RESOLUTION_HINTS = (
    "backend or cloud block",
    "co-located state artifact",
    "CI step running terraform in this directory (Phase 3)",
    "autoloaded tfvars / lock file",
)

C = Confidence
RESOLVED = frozenset({InstantiationStatus.RESOLVED_ROOT, InstantiationStatus.RESOLVED_INSTANCES, InstantiationStatus.RESOLVED_BOTH})


# --------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class ConfigInput:
    """Observed facts about one configuration that the rule table reads."""

    path: str
    parse_status: ParseStatus
    directory_fact: ObservedFact
    parse_errors: tuple[ObservedFact, ...] = ()
    backend_facts: tuple[ObservedFact, ...] = ()     # BACKEND_BLOCK / CLOUD_BLOCK
    state_facts: tuple[ObservedFact, ...] = ()
    autoload_var_facts: tuple[ObservedFact, ...] = ()
    lock_facts: tuple[ObservedFact, ...] = ()
    dottf_facts: tuple[ObservedFact, ...] = ()
    provider_facts: tuple[ObservedFact, ...] = ()    # every PROVIDER_CONFIG fact
    variable_facts: tuple[ObservedFact, ...] = ()    # VARIABLE_DECLARED
    #: (presence fact, assigned variable names or None if the file could not be read)
    var_files: tuple[tuple[ObservedFact, tuple[str, ...] | None], ...] = ()
    hint_facts: tuple[ObservedFact, ...] = ()        # PATH_SEGMENT

    @property
    def id(self) -> str:
        return ids.configuration_id(self.path)


@dataclass(frozen=True)
class Call:
    """A resolved local module call: STRUCTURAL edge caller -> callee."""

    caller: str
    callee: str
    name: str
    fact: ObservedFact

    @property
    def label(self) -> str:
        return f"{self.caller} as module.{self.name}"


@dataclass(frozen=True)
class Signal:
    id: str
    side: str            # "root" | "module"
    strength: Confidence
    evidence: Evidence


@dataclass(frozen=True)
class Decision:
    path: str
    rule_id: str
    role: ConfigurationRole
    confidence: Confidence
    root_role: RoleAssessment
    module_role: RoleAssessment
    inference: Inference
    status: InstantiationStatus
    reason: InstantiationReason | None = None
    ambiguity: Ambiguity | None = None
    evidence: tuple[Evidence, ...] = ()
    cyclic: bool = False
    instantiated_callers: tuple[str, ...] = field(default=())

    @property
    def instantiated(self) -> bool:
        return self.status in RESOLVED

    @property
    def has_root_context(self) -> bool:
        return self.status in (InstantiationStatus.RESOLVED_ROOT, InstantiationStatus.RESOLVED_BOTH)


# --------------------------------------------------------------------------- signals


def _ev(kind: ProvenanceKind, claim: str, cfg: ConfigInput, facts, strength: Confidence, detail: str,
        basis: EvidenceBasis = EvidenceBasis.CONTENT) -> Evidence:
    return Evidence(kind, claim, cfg.id, tuple(f.id for f in facts), strength, basis=basis, detail=detail)


def _artifact_names(facts: Sequence[ObservedFact]) -> str:
    return ", ".join(sorted({f.artifact.removeprefix("art:") for f in facts}))


def _signals(cfg: ConfigInput, inst_calls: Sequence[Call], other_calls: Sequence[Call]) -> list[Signal]:
    called = bool(inst_calls)
    out: list[Signal] = []

    def add(sig: str, side: str, strength: Confidence, ev: Evidence) -> None:
        out.append(Signal(sig, side, strength, ev))

    OBS, STR = ProvenanceKind.OBSERVED, ProvenanceKind.STRUCTURAL
    if cfg.backend_facts:
        kinds = sorted({str(dict(f.payload).get("backend_type") or "cloud") for f in cfg.backend_facts})
        add("R-BACKEND", "root", C.HIGH, _ev(OBS, "R-BACKEND", cfg, cfg.backend_facts, C.HIGH,
                                              f"declares backend {', '.join(kinds)} in {_artifact_names(cfg.backend_facts)}"))
    if cfg.state_facts:
        add("R-STATE", "root", C.HIGH, _ev(OBS, "R-STATE", cfg, cfg.state_facts, C.HIGH,
                                            f"co-located state artifact {_artifact_names(cfg.state_facts)} (presence only)"))
    if cfg.autoload_var_facts:
        add("R-TFVARS", "root", C.MEDIUM, _ev(OBS, "R-TFVARS", cfg, cfg.autoload_var_facts, C.MEDIUM,
                                               f"autoloaded variable file {_artifact_names(cfg.autoload_var_facts)}"))
    if cfg.lock_facts:
        add("R-LOCK", "root", C.MEDIUM, _ev(OBS, "R-LOCK", cfg, cfg.lock_facts, C.MEDIUM, "dependency lock file present"))
    if cfg.dottf_facts:
        add("R-DOTTF", "root", C.MEDIUM,
            _ev(OBS, "R-DOTTF", cfg, cfg.dottf_facts, C.MEDIUM, ".terraform/ directory present (init ran here)"))
    configured = [f for f in cfg.provider_facts if dict(f.payload).get("alias") is None and dict(f.payload).get("configured")]
    if configured:
        strength = C.LOW if called else C.MEDIUM
        names = sorted({str(dict(f.payload)["provider"]) for f in configured})
        add("R-PROVIDER", "root", strength, _ev(OBS, "R-PROVIDER", cfg, configured, strength,
                                                 f"configured non-alias provider {', '.join(names)}"
                                                 + (" (weak: the configuration is called as a module)" if called else "")))
    if not called:
        add("R-UNCALLED", "root", C.LOW, _ev(STR, "R-UNCALLED", cfg, [cfg.directory_fact], C.LOW,
                                              "no instantiated configuration calls this directory"))
    variables = [(f, dict(f.payload)) for f in cfg.variable_facts]
    if variables and all(p.get("has_default") for _, p in variables):
        add("R-DEFAULTS", "root", C.LOW, _ev(OBS, "R-DEFAULTS", cfg, [f for f, _ in variables], C.LOW, "every variable has a default"))

    if called:
        add("M-CALLED", "module", C.CERTAIN, _ev(STR, "M-CALLED", cfg, [c.fact for c in inst_calls], C.CERTAIN,
                                                  "called by " + ", ".join(sorted(c.label for c in inst_calls))))
    required = [(f, p) for f, p in variables if not p.get("has_default")]
    names_known = all(names is not None for _, names in cfg.var_files)
    if required and names_known:
        provided = {n for _, names in cfg.var_files for n in names or ()}
        unsatisfied = [(f, p) for f, p in required if p.get("name") not in provided]
        if unsatisfied:
            facts = [f for f, _ in unsatisfied] + [vf for vf, _ in cfg.var_files]
            add("M-REQVAR", "module", C.MEDIUM, _ev(STR, "M-REQVAR", cfg, facts, C.MEDIUM,
                                                     "required variable(s) with no default and no var file in the directory: "
                                                     + ", ".join(sorted(str(p.get("name")) for _, p in unsatisfied))))
    if not cfg.provider_facts:
        add("M-NOPROV", "module", C.LOW, _ev(STR, "M-NOPROV", cfg, [cfg.directory_fact], C.LOW, "no provider block"))
    if cfg.hint_facts:
        segs = sorted({str(dict(f.payload).get("segment")) for f in cfg.hint_facts})
        add("M-HINT", "module", C.LOW, _ev(ProvenanceKind.INFERRED, "M-HINT", cfg, cfg.hint_facts, C.LOW,
                                            f"path segment {', '.join(segs)} (name hint only)", EvidenceBasis.NAME_HINT))
    if not called and other_calls:
        add("M-DEFERRED-CALLER", "module", C.LOW, _ev(STR, "M-DEFERRED-CALLER", cfg, [c.fact for c in other_calls], C.LOW,
                                                       "called only by non-instantiated configurations: "
                                                       + ", ".join(sorted(c.label for c in other_calls))))
    return out


def _independent_count(evidence: Sequence[Evidence], facts_by_id: Mapping[str, ObservedFact]) -> int:
    """Size of a deterministic set of mutually independent items (C-corroborate)."""
    chosen: list[Evidence] = []
    for ev in sorted(evidence, key=lambda e: (e.claim, e.id)):
        if all(independent(ev, c, facts_by_id) for c in chosen):
            chosen.append(ev)
    return len(chosen)


def _level(signals: Sequence[Signal]) -> Confidence:
    return max((s.strength for s in signals), default=C.UNKNOWN, key=lambda c: c.rank)


# --------------------------------------------------------------------------- rules


@dataclass
class _Ctx:
    cfg: ConfigInput
    signals: list[Signal]
    facts_by_id: Mapping[str, ObservedFact]
    partial: bool

    def side(self, side: str) -> list[Signal]:
        return [s for s in self.signals if s.side == side]

    def ev(self, side: str, min_strength: Confidence = C.LOW) -> tuple[str, ...]:
        return tuple(s.evidence.id for s in self.side(side) if s.strength >= min_strength)

    @property
    def root_medium(self) -> list[Evidence]:
        return [s.evidence for s in self.side("root") if s.strength is C.MEDIUM]

    @property
    def independent_medium_root(self) -> int:
        return _independent_count(self.root_medium, self.facts_by_id)

    @property
    def strong_root(self) -> bool:
        return any(s.id in STRONG_ROOT for s in self.side("root")) or self.independent_medium_root >= 2

    @property
    def root_level(self) -> Confidence:
        return C.HIGH if self.strong_root else _level(self.side("root"))

    @property
    def module_level(self) -> Confidence:
        return _level(self.side("module"))

    def missing_root(self) -> tuple[str, ...]:
        present = {s.id for s in self.side("root")}
        return tuple(text for sig, text in _ROOT_SIGNAL_TEXT.items() if sig not in present)

    def negative(self, confidence: Confidence) -> Confidence:
        """C-partial: negative conclusions are capped at LOW when a file failed to parse."""
        return min_confidence(confidence, C.LOW) if self.partial else confidence


def _assessment(ctx: _Ctx, side: str, status: RoleStatus, confidence: Confidence, missing: tuple[str, ...] = ()) -> RoleAssessment:
    other = "module" if side == "root" else "root"
    supporting = ctx.ev(side) if status is not RoleStatus.NO else ()
    contrary = ctx.ev(other, C.MEDIUM) if status is not RoleStatus.NO else ctx.ev(other)
    return RoleAssessment(status, confidence, supporting, contrary, missing)


def _decision(ctx: _Ctx, rule: str, role: ConfigurationRole, confidence: Confidence, root_role: RoleAssessment,
              module_role: RoleAssessment, status: InstantiationStatus, reason: InstantiationReason | None = None, *,
              supporting: tuple[str, ...], contrary: tuple[str, ...] = (), missing: tuple[str, ...] = (),
              alternatives: tuple[Alternative, ...] = (), ambiguity_kind: AmbiguityKind | None = None,
              hints: tuple[str, ...] = (), cyclic: bool = False, callers: tuple[str, ...] = (),
              extra_evidence: tuple[Evidence, ...] = ()) -> Decision:
    subject = ctx.cfg.id
    conclusion = f"role={role.value}"
    if role is ConfigurationRole.MODULE_SOURCE and status is InstantiationStatus.NOT_APPLICABLE:
        conclusion += " (unused)"
    inference = Inference(rule, subject, conclusion, confidence, supporting, tuple(c for c in contrary if c not in supporting),
                          missing, alternatives)
    ambiguity = None
    if ambiguity_kind is not None:
        ambiguity = Ambiguity(ambiguity_kind, subject, alternatives, (*supporting, *contrary), hints)
    evidence = tuple(s.evidence for s in ctx.signals) + extra_evidence
    return Decision(ctx.cfg.path, rule, role, confidence, root_role, module_role, inference, status, reason, ambiguity,
                    evidence, cyclic, callers)


def _decide(ctx: _Ctx, inst_calls: Sequence[Call], other_calls: Sequence[Call], caller_confidences: Sequence[Confidence],
            cycle_only: bool, cyclic: bool) -> Decision:
    R = ConfigurationRole
    S = InstantiationStatus
    Y, N, CAND = RoleStatus.YES, RoleStatus.NO, RoleStatus.CANDIDATE
    cfg = ctx.cfg
    callers = tuple(sorted({c.caller for c in inst_calls}))
    root_ids, module_ids = ctx.ev("root"), ctx.ev("module")
    missing_root = ctx.missing_root()

    # ROLE-P1: nothing parsed. Understanding is impossible; nothing is dropped.
    if cfg.parse_status is ParseStatus.FAILED:
        err = _ev(ProvenanceKind.OBSERVED, "cfg.parse_failed", cfg, cfg.parse_errors, C.CERTAIN,
                  f"every Terraform file failed to parse ({len(cfg.parse_errors)})")
        return _decision(ctx, "ROLE-P1", R.UNKNOWN, C.UNKNOWN, RoleAssessment.unknown(), RoleAssessment.unknown(), S.DEFERRED,
                         InstantiationReason.PARSE_FAILED, supporting=(err.id,), missing=("a parseable Terraform file",),
                         callers=callers, extra_evidence=(err,))

    # ROLE-X1: only reachable through a module cycle.
    if cycle_only:
        root_c = max(ctx.root_level, C.LOW, key=lambda c: c.rank)
        module_c = max(ctx.module_level, C.LOW, key=lambda c: c.rank)
        alts = (Alternative("role=PROBABLE_ROOT", min_confidence(root_c, C.MEDIUM)), Alternative("role=MODULE_SOURCE", module_c))
        conf = max(root_c, module_c, key=lambda c: c.rank)  # the stronger side (§18)
        return _decision(ctx, "ROLE-X1", R.AMBIGUOUS, conf, _assessment(ctx, "root", CAND, root_c),
                         _assessment(ctx, "module", CAND, module_c), S.DEFERRED, InstantiationReason.CYCLE_ONLY,
                         supporting=root_ids, contrary=module_ids, missing=("an instantiated caller outside the module cycle",),
                         alternatives=alts, ambiguity_kind=AmbiguityKind.CYCLE_ONLY,
                         hints=("break the module cycle", "an instantiated caller outside the cycle"), cyclic=cyclic)

    if inst_calls:
        # ---------------- C rules: at least one instantiated caller
        module_conf = C.HIGH if all(c >= C.MEDIUM for c in caller_confidences) else min_confidence(*caller_confidences)
        m_called = _assessment(ctx, "module", Y, C.CERTAIN)
        if ctx.strong_root:
            return _decision(ctx, "ROLE-C1", R.DUAL_ROLE, C.HIGH,
                             _assessment(ctx, "root", Y, C.HIGH, ("R-CI (CI step running terraform here; Phase 3)",)), m_called,
                             S.RESOLVED_BOTH, supporting=(*root_ids, *module_ids), missing=missing_root,
                             cyclic=cyclic, callers=callers)
        if ctx.independent_medium_root == 1:
            return _decision(ctx, "ROLE-C2", R.MODULE_SOURCE, module_conf, _assessment(ctx, "root", CAND, C.LOW, missing_root),
                             m_called, S.RESOLVED_INSTANCES, InstantiationReason.ROOT_ROLE_WEAK,
                             supporting=module_ids, contrary=root_ids, missing=missing_root,
                             alternatives=(Alternative("role=DUAL_ROLE", C.LOW),), cyclic=cyclic, callers=callers)
        provider_weak = any(s.id == "R-PROVIDER" for s in ctx.side("root"))
        if provider_weak:  # possible dual role (§17/§47 weak variant): candidate, root instantiation deferred
            root_role = _assessment(ctx, "root", CAND, C.LOW, missing_root)
            reason: InstantiationReason | None = InstantiationReason.ROOT_ROLE_WEAK
            alts: tuple[Alternative, ...] = (Alternative("role=DUAL_ROLE", C.LOW),)
        else:
            root_role = _assessment(ctx, "root", N, ctx.negative(C.HIGH))
            reason, alts = None, ()
        return _decision(ctx, "ROLE-C3", R.MODULE_SOURCE, module_conf, root_role, m_called, S.RESOLVED_INSTANCES, reason,
                         supporting=module_ids, contrary=root_ids, missing=missing_root if provider_weak else (),
                         alternatives=alts, cyclic=cyclic, callers=callers)

    # ---------------- U rules: no instantiated caller
    root_level, module_level = ctx.root_level, ctx.module_level
    module_cand = (_assessment(ctx, "module", CAND, module_level) if ctx.side("module")
                   else _assessment(ctx, "module", N, ctx.negative(C.HIGH)))
    if ctx.strong_root:
        alts = (Alternative("role=MODULE_SOURCE (unused)", C.LOW),) if module_level >= C.MEDIUM else ()
        return _decision(ctx, "ROLE-U1", R.CONFIRMED_ROOT, C.HIGH, _assessment(ctx, "root", Y, C.HIGH, missing_root), module_cand,
                         S.RESOLVED_ROOT, supporting=root_ids, contrary=module_ids, missing=missing_root, alternatives=alts,
                         cyclic=cyclic)
    if root_level >= C.MEDIUM and module_level >= C.MEDIUM:
        alts = (Alternative("role=PROBABLE_ROOT", C.MEDIUM), Alternative("role=MODULE_SOURCE (unused)", C.MEDIUM))
        return _decision(ctx, "ROLE-U3", R.AMBIGUOUS, C.MEDIUM, _assessment(ctx, "root", CAND, C.MEDIUM, missing_root),
                         _assessment(ctx, "module", CAND, C.MEDIUM), S.DEFERRED, InstantiationReason.AMBIGUOUS_ROLE,
                         supporting=root_ids, contrary=module_ids, missing=missing_root, alternatives=alts,
                         ambiguity_kind=AmbiguityKind.ROLE, hints=_RESOLUTION_HINTS + ("var file providing the required variables",),
                         cyclic=cyclic)
    if module_level >= C.MEDIUM:
        if ctx.partial:  # ROLE-U4 under C-partial: the unparsed file might hold root evidence
            alts = (Alternative("role=MODULE_SOURCE (unused)", C.MEDIUM), Alternative("role=PROBABLE_ROOT", C.LOW))
            return _decision(ctx, "ROLE-U4", R.AMBIGUOUS, C.MEDIUM, _assessment(ctx, "root", CAND, C.LOW, missing_root),
                             _assessment(ctx, "module", CAND, C.MEDIUM), S.DEFERRED, InstantiationReason.AMBIGUOUS_ROLE,
                             supporting=module_ids, contrary=root_ids, missing=(*missing_root, "a complete parse of every file"),
                             alternatives=alts, ambiguity_kind=AmbiguityKind.ROLE,
                             hints=("fix the file that failed to parse", *_RESOLUTION_HINTS), cyclic=cyclic)
        return _decision(ctx, "ROLE-U4", R.MODULE_SOURCE, C.MEDIUM, _assessment(ctx, "root", CAND, C.LOW, missing_root),
                         _assessment(ctx, "module", Y, C.MEDIUM), S.NOT_APPLICABLE, InstantiationReason.UNUSED_MODULE_SOURCE,
                         supporting=module_ids, contrary=root_ids, missing=missing_root,
                         alternatives=(Alternative("role=PROBABLE_ROOT", C.LOW),), cyclic=cyclic)
    if root_level >= C.MEDIUM:
        rule, conf = "ROLE-U2", C.MEDIUM
    else:
        rule, conf = "ROLE-U5", C.LOW
    if other_calls:  # ROLE-X2: its only callers are not instantiated, and its own evidence is not decisive
        alts = (Alternative("role=PROBABLE_ROOT", conf), Alternative("role=MODULE_SOURCE (via non-instantiated callers)", C.LOW))
        return _decision(ctx, "ROLE-X2", R.AMBIGUOUS, conf, _assessment(ctx, "root", CAND, conf, missing_root),
                         _assessment(ctx, "module", CAND, C.LOW), S.DEFERRED, InstantiationReason.CALLER_DEFERRED,
                         supporting=root_ids, contrary=module_ids, missing=(*missing_root, "an instantiated caller"),
                         alternatives=alts, ambiguity_kind=AmbiguityKind.CALLER_DEFERRED,
                         hints=("a caller that is itself instantiated", *_RESOLUTION_HINTS), cyclic=cyclic)
    return _decision(ctx, rule, R.PROBABLE_ROOT, conf, _assessment(ctx, "root", Y, conf, missing_root), module_cand,
                     S.RESOLVED_ROOT, supporting=root_ids, contrary=module_ids, missing=missing_root,
                     alternatives=(Alternative("role=MODULE_SOURCE (unused)", C.LOW),), cyclic=cyclic)


def classify(configs: Mapping[str, ConfigInput], calls: Sequence[Call], facts_by_id: Mapping[str, ObservedFact]) -> dict[str, Decision]:
    """Apply the rule table to every configuration. Returns decisions keyed by path."""
    edges: dict[str, set[str]] = defaultdict(set)
    callers_of: dict[str, list[Call]] = defaultdict(list)
    for c in sorted(calls, key=lambda c: (c.caller, c.name, c.callee)):
        if c.caller in configs and c.callee in configs:
            edges[c.caller].add(c.callee)
            callers_of[c.callee].append(c)
    decisions: dict[str, Decision] = {}
    for comp in strongly_connected_components(configs, edges):
        members = set(comp)
        cyclic = is_cyclic(comp, edges)
        external_inst = [c for m in comp for c in callers_of[m] if c.caller not in members and decisions[c.caller].instantiated]
        for path in comp:
            own = callers_of[path]
            if cyclic and external_inst:
                # the cycle is entered from outside: every member is reached by the instantiation walk
                inst = [c for c in own if c.caller in members or decisions[c.caller].instantiated]
                confidences = [decisions[c.caller].confidence for c in external_inst]
            else:
                inst = [c for c in own if c.caller not in members and decisions[c.caller].instantiated]
                confidences = [decisions[c.caller].confidence for c in inst]
            other = [c for c in own if c not in inst]
            cfg = configs[path]
            ctx = _Ctx(cfg, _signals(cfg, inst, other), facts_by_id, cfg.parse_status is ParseStatus.PARTIAL)
            decisions[path] = _decide(ctx, inst, other, confidences, cycle_only=cyclic and not external_inst, cyclic=cyclic)
    return decisions
