"""Repository Intelligence domain model (ADR 0001, proposal §2).

These are domain objects, **not** graph ``Node``/``Edge``s. The model records
what a repository *configures* - configurations, module sources and calls,
declarations, deployment contexts, and the evidence behind every judgement -
before anything becomes an infrastructure node.

Key separations (each is a distinct type with a distinct id):

- :class:`TerraformConfiguration` - one per **directory**; ``.tf`` files are
  provenance only (:class:`SourceFileRef`) and never identity.
- :class:`ModuleSource` (where module code comes from) vs :class:`ModuleCall`
  (a ``module`` block in a caller) vs :class:`ModuleInstance` (a call realized
  in one deployment context).
- :class:`ResourceDeclaration` (one HCL block) vs
  :class:`DesiredResourceInstance` (one desired thing in one deployment
  context). A block with ``count``/``for_each`` is a *template*: its
  cardinality stays UNKNOWN until evidence resolves it; it is never "1".
- :class:`DeploymentContext` (one independent apply unit) vs
  :class:`TerraformConfiguration`: one configuration is not one environment.

:class:`DesiredResourceInstance` is the boundary type of the Desired
Infrastructure Model (DIM); :meth:`DesiredResourceInstance.derive` is the one
explicit step from RI entities to a DIM entry. Nothing here knows about any
cloud provider or about the storage graph.
"""
from __future__ import annotations

import posixpath
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from functools import cached_property
from typing import Any

from flowlens.repository import ids
from flowlens.repository.enums import (
    ROOT_CAPABLE_ROLES,
    STATUSES_REQUIRING_REASON,
    AnchorKind,
    ArtifactKind,
    BackendKind,
    CardinalityKind,
    Confidence,
    ConfigurationRole,
    DeclarationMode,
    EvidenceBasis,
    InstantiationReason,
    InstantiationStatus,
    LifecycleStage,
    ModuleSourceKind,
    ParseStatus,
    ReadStatus,
    RoleStatus,
    Severity,
    StateFormat,
    VarFileKind,
)
from flowlens.repository.evidence import Ambiguity, Evidence, Inference, ObservedFact
from flowlens.repository.redact import canonical_source_url, redact_text, redact_url, sanitize_backend_attributes

#: Version of the RepositoryModel schema (independent of the node identity scheme; ADR 0007).
CURRENT_REPOSITORY_MODEL_VERSION = 1


def _set(obj: Any, name: str, value: Any) -> None:
    object.__setattr__(obj, name, value)


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _check_role_confidence(role: ConfigurationRole, confidence: Confidence, where: str) -> None:
    """Role/confidence pairs that are contradictions in terms."""
    if role is ConfigurationRole.PROBABLE_ROOT and confidence not in (Confidence.MEDIUM, Confidence.LOW):
        raise ValueError(f"{where}: PROBABLE_ROOT is MEDIUM or LOW by definition, not {confidence.value}")
    if role is ConfigurationRole.CONFIRMED_ROOT and confidence < Confidence.HIGH:
        raise ValueError(f"{where}: CONFIRMED_ROOT requires HIGH or CERTAIN confidence, not {confidence.value}")


# --------------------------------------------------------------------------- anchor & artifacts


@dataclass(frozen=True)
class RepositoryAnchor:
    """What ids are relative to. No absolute path is ever stored."""

    kind: AnchorKind
    scan_root_rel: str = "."

    def __post_init__(self) -> None:
        _set(self, "scan_root_rel", ids.normalize_rel_path(self.scan_root_rel))

    @classmethod
    def from_resolution(cls, resolution: ids.AnchorResolution) -> RepositoryAnchor:
        return cls(resolution.kind, resolution.scan_root_rel)


@dataclass(frozen=True)
class RawArtifact:
    """A file or directory exactly as found. `kind` is syntactic (extension and
    Terraform-defined filename rules); nothing is interpreted here."""

    path: str
    kind: ArtifactKind | None = None
    size: int | None = None
    sha256: str | None = None
    read_status: ReadStatus = ReadStatus.OK
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "path", ids.normalize_rel_path(self.path))
        if self.kind is None:
            _set(self, "kind", ids.artifact_kind_for(self.path))
        _set(self, "id", ids.artifact_id(self.path))


@dataclass(frozen=True)
class SourceFileRef:
    """Provenance only: which artifact contributed to a configuration."""

    artifact: str
    parse_status: ParseStatus = ParseStatus.COMPLETE


@dataclass(frozen=True)
class BlockSummary:
    """Counts per top-level block kind (terraform, provider, resource, ...)."""

    counts: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        _set(self, "counts", tuple(sorted(dict(self.counts).items())))

    @classmethod
    def of(cls, counts: Mapping[str, int]) -> BlockSummary:
        return cls(tuple(counts.items()))

    def get(self, block_kind: str) -> int:
        return dict(self.counts).get(block_kind, 0)


# --------------------------------------------------------------------------- classification & lifecycle


@dataclass(frozen=True)
class RoleAssessment:
    """One role (root or module), assessed independently of the other."""

    status: RoleStatus
    confidence: Confidence
    supporting: tuple[str, ...] = ()
    contrary: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("supporting", "contrary", "missing"):
            _set(self, name, _sorted_unique(getattr(self, name)))

    @classmethod
    def unknown(cls) -> RoleAssessment:
        return cls(RoleStatus.UNKNOWN, Confidence.UNKNOWN)


@dataclass(frozen=True)
class Classification:
    """A configuration's role. `inference` is the explanation (an Inference id)."""

    role: ConfigurationRole
    confidence: Confidence
    root_role: RoleAssessment
    module_role: RoleAssessment
    inference: str

    def __post_init__(self) -> None:
        _check_role_confidence(self.role, self.confidence, "Classification")
        yes = RoleStatus.YES
        if self.role is ConfigurationRole.DUAL_ROLE and not (self.root_role.status is yes and self.module_role.status is yes):
            raise ValueError("DUAL_ROLE requires root_role=yes AND module_role=yes")
        if self.role is ConfigurationRole.CONFIRMED_ROOT and self.root_role.status is not yes:
            raise ValueError("CONFIRMED_ROOT requires root_role=yes")
        if self.role is ConfigurationRole.PROBABLE_ROOT and self.root_role.status not in (yes, RoleStatus.CANDIDATE):
            raise ValueError("PROBABLE_ROOT requires root_role=yes or candidate")
        if self.role is ConfigurationRole.MODULE_SOURCE and self.module_role.status is not yes:
            raise ValueError("MODULE_SOURCE requires module_role=yes")


@dataclass(frozen=True)
class InstantiationRecord:
    """Outcome of the instantiation decision. Understanding (classification)
    and instantiation are separate: only this decision may be DEFERRED, and
    then it always carries a reason and the inference behind it."""

    status: InstantiationStatus
    reason: InstantiationReason | None = None
    inference: str | None = None
    contexts: tuple[str, ...] = ()    # as root
    instances: tuple[str, ...] = ()   # as module source

    def __post_init__(self) -> None:
        _set(self, "contexts", _sorted_unique(self.contexts))
        _set(self, "instances", _sorted_unique(self.instances))
        if self.status in STATUSES_REQUIRING_REASON and (self.reason is None or self.inference is None):
            raise ValueError(f"instantiation {self.status.value} requires a reason code and an inference id")
        if self.status in (InstantiationStatus.RESOLVED_ROOT, InstantiationStatus.RESOLVED_BOTH) and not self.contexts:
            raise ValueError(f"{self.status.value} requires at least one deployment context")
        if self.status in (InstantiationStatus.RESOLVED_INSTANCES, InstantiationStatus.RESOLVED_BOTH) and not self.instances:
            raise ValueError(f"{self.status.value} requires at least one module instance")
        if self.status in (InstantiationStatus.DEFERRED, InstantiationStatus.NOT_APPLICABLE) and (self.contexts or self.instances):
            raise ValueError(f"{self.status.value} cannot carry contexts or instances")


@dataclass(frozen=True)
class ConfigurationLifecycle:
    """DISCOVERED -> CLASSIFIED -> INSTANTIATED -> CORRELATED. A configuration
    may stop at any stage; discovery never implies instantiation."""

    stage: LifecycleStage = LifecycleStage.DISCOVERED
    instantiation: InstantiationRecord | None = None

    def __post_init__(self) -> None:
        reached = self.stage.rank >= LifecycleStage.INSTANTIATED.rank
        if reached != (self.instantiation is not None):
            raise ValueError("an instantiation record exists exactly when the INSTANTIATED stage was reached")


@dataclass(frozen=True)
class TerraformConfiguration:
    """One Terraform configuration = one directory. Identity is the
    anchor-relative directory path; file names never contribute to it."""

    path: str
    files: tuple[SourceFileRef, ...] = ()
    parse_status: ParseStatus = ParseStatus.COMPLETE
    block_summary: BlockSummary = BlockSummary()
    lifecycle: ConfigurationLifecycle = ConfigurationLifecycle()
    classification: Classification | None = None
    outside_scan_root: bool = False
    id: str = field(init=False)
    outside_anchor: bool = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "path", ids.normalize_rel_path(self.path))
        _set(self, "files", tuple(sorted(set(self.files), key=lambda f: f.artifact)))
        classified = self.lifecycle.stage.rank >= LifecycleStage.CLASSIFIED.rank
        if classified != (self.classification is not None):
            raise ValueError(f"{self.path}: a classification exists exactly when the CLASSIFIED stage was reached")
        _set(self, "id", ids.configuration_id(self.path))
        _set(self, "outside_anchor", ids.is_outside(self.path))

    @property
    def role(self) -> ConfigurationRole | None:
        return self.classification.role if self.classification else None


# --------------------------------------------------------------------------- modules


@dataclass(frozen=True)
class ModuleSource:
    """Where module code comes from. Independent of how many times, and by
    whom, it is called. `locator` is the anchor-relative directory for local
    sources, the registry address, or the URL (credentials never in the id)."""

    kind: ModuleSourceKind
    locator: str
    raw_source: str = ""
    version_constraint: str | None = None
    ref: str | None = None
    id: str = field(init=False)
    configuration: str | None = field(init=False)

    def __post_init__(self) -> None:
        if self.kind is ModuleSourceKind.LOCAL:
            _set(self, "locator", ids.normalize_rel_path(self.locator))
        elif self.kind is not ModuleSourceKind.REGISTRY:
            _set(self, "locator", canonical_source_url(self.locator))  # never keep credentials
        _set(self, "raw_source", redact_url(self.raw_source))
        _set(self, "id", ids.module_source_id(self.kind, self.locator))
        _set(self, "configuration", ids.configuration_id(self.locator) if self.kind is ModuleSourceKind.LOCAL else None)


@dataclass(frozen=True)
class MetaArguments:
    """Meta-argument *presence* on a block. Expressions are kept as written
    (redacted) and never evaluated."""

    count: str | None = None
    for_each: str | None = None
    dynamic_blocks: tuple[str, ...] = ()
    depends_on: bool = False
    lifecycle: bool = False
    provider: str | None = None

    def __post_init__(self) -> None:
        _set(self, "count", redact_text(self.count) if self.count is not None else None)
        _set(self, "for_each", redact_text(self.for_each) if self.for_each is not None else None)
        _set(self, "dynamic_blocks", _sorted_unique(self.dynamic_blocks))

    @property
    def expands(self) -> bool:
        """count/for_each make the block a template. ``dynamic`` blocks shape
        attributes only and never change resource cardinality."""
        return self.count is not None or self.for_each is not None

    @property
    def expansion_expression(self) -> str | None:
        if self.count is not None:
            return f"count = {self.count}"
        if self.for_each is not None:
            return f"for_each = {self.for_each}"
        return None


@dataclass(frozen=True)
class Cardinality:
    """How many real instances one declaration/call yields.

    Invariant: cardinality is never invented. UNKNOWN stays UNKNOWN - it has no
    count, combines to UNKNOWN, and is reported as "unknown", never as 1.
    """

    kind: CardinalityKind
    count: int | None = None
    keys: tuple[str, ...] | None = None
    expression: str | None = None

    def __post_init__(self) -> None:
        if self.expression is not None:
            _set(self, "expression", redact_text(self.expression))
        if self.kind is CardinalityKind.STATICALLY_RESOLVABLE:
            if self.count is None and self.keys is None:
                raise ValueError("STATICALLY_RESOLVABLE cardinality needs a count or keys")
            if self.keys is not None:
                _set(self, "keys", tuple(self.keys))
                if self.count is None:
                    _set(self, "count", len(self.keys))
                elif self.count != len(self.keys):
                    raise ValueError("count and keys disagree")
        elif self.count is not None or self.keys is not None:
            raise ValueError(f"{self.kind.value} cardinality cannot carry a count or keys")

    @classmethod
    def single(cls) -> Cardinality:
        """No count/for_each: Terraform defines exactly one instance."""
        return cls(CardinalityKind.STATICALLY_RESOLVABLE, count=1)

    @classmethod
    def unknown(cls, expression: str | None = None) -> Cardinality:
        return cls(CardinalityKind.UNKNOWN, expression=expression)

    @property
    def instance_count(self) -> int | None:
        """The number of instances, or None when not statically known."""
        return self.count if self.kind is CardinalityKind.STATICALLY_RESOLVABLE else None

    @property
    def is_single(self) -> bool:
        return self.instance_count == 1 and self.expression is None

    def render(self) -> str:
        return f"N = {self.count}" if self.instance_count is not None else f"N = {self.kind.value.lower()}"

    @staticmethod
    def combine(*parts: Cardinality) -> Cardinality:
        """Cardinality of a nested path (module instance x declaration).
        UNKNOWN dominates, then RUNTIME_DEPENDENT, then PARTIALLY_RESOLVABLE;
        only an all-static path has a count (the product)."""
        exprs = tuple(p.expression for p in parts if p.expression)
        expr = " x ".join(exprs) or None
        for kind in (CardinalityKind.UNKNOWN, CardinalityKind.RUNTIME_DEPENDENT, CardinalityKind.PARTIALLY_RESOLVABLE):
            if any(p.kind is kind for p in parts):
                return Cardinality(kind, expression=expr)
        total = 1
        for p in parts:
            total *= p.count or 0
        return Cardinality(CardinalityKind.STATICALLY_RESOLVABLE, count=total, expression=expr)


@dataclass(frozen=True)
class ModuleCall:
    """A ``module "name" {}`` block in a caller configuration: a STRUCTURAL
    relationship caller -> source, and itself a declaration."""

    caller_path: str
    name: str
    source: str               # ModuleSource id
    meta: MetaArguments = MetaArguments()
    evidence: str | None = None
    id: str = field(init=False)
    caller: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "caller_path", ids.normalize_rel_path(self.caller_path))
        _set(self, "id", ids.module_call_id(self.caller_path, self.name))
        _set(self, "caller", ids.configuration_id(self.caller_path))

    @property
    def address(self) -> str:
        return f"module.{self.name}"


# --------------------------------------------------------------------------- deployment contexts & instances


@dataclass(frozen=True)
class DeploymentContext:
    """One independent apply unit: a root configuration in its root role.

    Separate from :class:`TerraformConfiguration` and from "environment": one
    configuration may be applied in several contexts (var files, workspaces);
    those are recorded as *candidates* and never multiply instances until
    execution evidence exists. `role`/`confidence` are inherited from the
    root's classification and are never promoted downstream.
    """

    root_path: str
    role: ConfigurationRole
    confidence: Confidence
    workspace: str | None = None
    var_files: tuple[str, ...] = ()   # VarFileArtifact ids (candidates only, not applied)
    backend: str | None = None        # BackendEvidence id
    state: tuple[str, ...] = ()       # StateArtifact ids
    id: str = field(init=False)
    root: str = field(init=False)

    def __post_init__(self) -> None:
        if self.role not in ROOT_CAPABLE_ROLES:
            raise ValueError(f"a deployment context needs a root-capable role, not {self.role.value}")
        _check_role_confidence(self.role, self.confidence, "DeploymentContext")
        _set(self, "root_path", ids.normalize_rel_path(self.root_path))
        _set(self, "var_files", _sorted_unique(self.var_files))
        _set(self, "state", _sorted_unique(self.state))
        _set(self, "id", ids.context_id(self.root_path))
        _set(self, "root", ids.configuration_id(self.root_path))

    @property
    def basis(self) -> str:
        return "dual_role_root" if self.role is ConfigurationRole.DUAL_ROLE else "root_role"


@dataclass(frozen=True)
class ModuleInstance:
    """A module call realized in one deployment context (`<ctx>::<module path>`).
    Distinct from :class:`ModuleSource`: one source called by N calls in M
    contexts yields N x M instances."""

    context: str
    module_path: str
    call: str                              # ModuleCall id
    source: str                            # ModuleSource id
    source_configuration: str | None = None  # None for non-local (unfetched) sources
    expanded_by: tuple[str, ...] = ()      # module-path prefixes carrying count/for_each
    cardinality: Cardinality | None = None
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "expanded_by", tuple(self.expanded_by))
        if self.cardinality is None:
            _set(self, "cardinality", Cardinality.unknown() if self.expanded_by else Cardinality.single())
        elif not self.expanded_by and not self.cardinality.is_single:
            raise ValueError("a module instance with no count/for_each on its path is exactly one instance")
        _set(self, "id", ids.module_instance_id(self.context, self.module_path))

    @property
    def template(self) -> bool:
        return bool(self.expanded_by)


@dataclass(frozen=True)
class ResourceDeclaration:
    """Source-level: one ``resource``/``data`` block in one configuration.
    `provider_type` is the raw Terraform type (never normalized here)."""

    configuration_path: str
    mode: DeclarationMode
    provider_type: str
    name: str
    meta: MetaArguments = MetaArguments()
    evidence: str | None = None
    id: str = field(init=False)
    configuration: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "configuration_path", ids.normalize_rel_path(self.configuration_path))
        _set(self, "id", ids.declaration_id(self.configuration_path, self.mode, self.provider_type, self.name))
        _set(self, "configuration", ids.configuration_id(self.configuration_path))

    @property
    def address(self) -> str:
        """Terraform-native, module-relative address."""
        local = f"{self.provider_type}.{self.name}"
        return f"data.{local}" if self.mode is DeclarationMode.DATA else local

    @property
    def cardinality(self) -> Cardinality:
        """No count/for_each -> exactly one. Otherwise UNKNOWN: expressions are
        never evaluated in the repository model."""
        return Cardinality.unknown(self.meta.expansion_expression) if self.meta.expands else Cardinality.single()


@dataclass(frozen=True)
class DesiredResourceInstance:
    """DIM boundary type: declaration x module-instance path x deployment context.

    `id` is ``tf:<root cfg>::<address>``. `context_role` and `confidence` are
    inherited from the context (weakest link) and are **never promoted**: an
    instance derived from a PROBABLE_ROOT stays PROBABLE_ROOT at <= MEDIUM.
    A template stays a template with its cardinality as known (UNKNOWN stays
    UNKNOWN); it is never counted as one resource.
    """

    context: str
    declaration: str
    address: str
    context_role: ConfigurationRole
    confidence: Confidence
    cardinality: Cardinality
    template: bool
    id: str = field(init=False)

    def __post_init__(self) -> None:
        if self.context_role not in ROOT_CAPABLE_ROLES:
            raise ValueError(f"desired instances only exist in root contexts, not {self.context_role.value}")
        if self.context_role is ConfigurationRole.PROBABLE_ROOT and self.confidence > Confidence.MEDIUM:
            raise ValueError("an instance of a PROBABLE_ROOT context cannot be more confident than MEDIUM")
        if not self.template and not self.cardinality.is_single:
            raise ValueError("a non-template desired instance is exactly one instance")
        _set(self, "id", ids.desired_instance_id(self.context, self.address))

    @classmethod
    def derive(
        cls,
        context: DeploymentContext,
        declaration: ResourceDeclaration,
        module_instance: ModuleInstance | None = None,
        *,
        path_confidence: Confidence | None = None,
    ) -> DesiredResourceInstance:
        """The explicit RI -> DIM step. Confidence follows C-min: it can only
        stay equal to the context's or go down (`path_confidence`)."""
        if module_instance is not None and module_instance.context != context.id:
            raise ValueError(f"module instance {module_instance.id} is not in context {context.id}")
        parts = [module_instance.cardinality] if module_instance is not None else []
        parts.append(declaration.cardinality)
        address = f"{module_instance.module_path}.{declaration.address}" if module_instance is not None else declaration.address
        confidence = context.confidence if path_confidence is None else min(context.confidence, path_confidence)
        return cls(
            context=context.id,
            declaration=declaration.id,
            address=address,
            context_role=context.role,
            confidence=confidence,
            cardinality=Cardinality.combine(*parts),
            template=declaration.meta.expands or bool(module_instance and module_instance.template),
        )


# --------------------------------------------------------------------------- backend / state / var files (geometry only)


@dataclass(frozen=True)
class BackendEvidence:
    """A ``backend``/``cloud`` block: presence, type and attribute *names*.
    Values are kept only for allowlisted identity-level keys; others are
    ``<redacted>``. Remote state is never fetched."""

    configuration_path: str
    kind: BackendKind
    backend_type: str | None = None
    attributes: Any = ()   # Mapping at construction -> sanitized ((name, value), ...)
    partial_config: bool = False
    evidence: str | None = None
    id: str = field(init=False)
    configuration: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "configuration_path", ids.normalize_rel_path(self.configuration_path))
        attrs = self.attributes if isinstance(self.attributes, Mapping) else dict(self.attributes)
        _set(self, "attributes", sanitize_backend_attributes(attrs))
        _set(self, "id", ids.backend_evidence_id(self.configuration_path, self.kind))
        _set(self, "configuration", ids.configuration_id(self.configuration_path))

    @property
    def keys_present(self) -> tuple[str, ...]:
        return tuple(k for k, _ in self.attributes)


@dataclass(frozen=True)
class StateArtifact:
    """A state/plan file found in the repository. Identity and presence only;
    content is not parsed in Phase 1. Binding to a context requires an Inference."""

    path: str
    format: StateFormat = StateFormat.UNKNOWN
    bound_context: str | None = None
    binding: str | None = None   # Inference id explaining the binding
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "path", ids.normalize_rel_path(self.path))
        if (self.bound_context is None) != (self.binding is None):
            raise ValueError("a state binding needs both a context and the inference that justifies it")
        _set(self, "id", ids.state_artifact_id(self.path))


@dataclass(frozen=True)
class VarFileArtifact:
    """A tfvars file. Kind and auto-loading follow Terraform's own filename
    rules. Values are never read into the model; its existence does not mean it
    was applied."""

    path: str
    id: str = field(init=False)
    kind: VarFileKind = field(init=False)
    autoloaded: bool = field(init=False)
    configuration: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "path", ids.normalize_rel_path(self.path))
        name = posixpath.basename(self.path)
        if name.endswith(".json"):
            kind = VarFileKind.TFVARS_JSON
        elif name == "terraform.tfvars":
            kind = VarFileKind.TERRAFORM_TFVARS
        elif name.endswith(".auto.tfvars"):
            kind = VarFileKind.AUTO_TFVARS
        elif name.endswith(".tfvars"):
            kind = VarFileKind.NAMED_TFVARS
        else:
            raise ValueError(f"not a Terraform variable file: {self.path!r}")
        _set(self, "kind", kind)
        autoloaded = name in ("terraform.tfvars", "terraform.tfvars.json") or name.endswith((".auto.tfvars", ".auto.tfvars.json"))
        _set(self, "autoloaded", autoloaded)
        _set(self, "id", ids.var_file_id(self.path))
        _set(self, "configuration", ids.configuration_id(posixpath.dirname(self.path) or "."))


@dataclass(frozen=True)
class Diagnostic:
    code: str                 # e.g. "RI-PARSE-FAILED", "RI-OVERRIDE-FILE-UNMERGED"
    severity: Severity
    subject: str
    message: str
    evidence: tuple[str, ...] = ()
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "message", redact_text(self.message))
        _set(self, "evidence", _sorted_unique(self.evidence))
        _set(self, "id", ids.diagnostic_id(self.code, self.subject, self.message))


# --------------------------------------------------------------------------- serialization


def to_jsonable(value: Any) -> Any:
    """Plain JSON-compatible structure: dataclass -> dict, Enum -> value,
    tuple -> list. Used for deterministic export; secrets were already redacted
    at construction."""
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple | list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------- inventory


@dataclass(frozen=True)
class InventoryEntry:
    configuration: str
    path: str
    role: ConfigurationRole | None
    confidence: Confidence | None
    stage: LifecycleStage
    status: InstantiationStatus | None
    reason: InstantiationReason | None
    declarations: tuple[str, ...]
    not_instantiated: tuple[str, ...]
    types_not_instantiated: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class DeclarationInventory:
    """The full declaration inventory, including configurations whose
    instantiation was deferred or is not applicable (invariant A1/A2)."""

    entries: tuple[InventoryEntry, ...]

    @property
    def total_declarations(self) -> int:
        return sum(len(e.declarations) for e in self.entries)

    @property
    def not_instantiated_declarations(self) -> tuple[str, ...]:
        return tuple(d for e in self.entries for d in e.not_instantiated)

    def configurations_with_status(self, status: InstantiationStatus | None) -> tuple[InventoryEntry, ...]:
        return tuple(e for e in self.entries if e.status is status)

    def summary(self) -> tuple[str, ...]:
        """Human summary lines, e.g. ``2 configurations deferred (AMBIGUOUS_ROLE)
        - 4 resource declarations not instantiated: a (3 aws_lambda_function), ...``"""
        labels = {
            InstantiationStatus.DEFERRED: "deferred",
            InstantiationStatus.NOT_APPLICABLE: "not applicable",
            None: "not yet instantiated",
        }
        groups: dict[tuple[str, str], list[InventoryEntry]] = defaultdict(list)
        for status, label in labels.items():
            for e in self.configurations_with_status(status):
                why = e.reason.value if e.reason else f"stage {e.stage.value}"
                groups[(label, why)].append(e)
        lines = []
        for (label, why), entries in groups.items():
            n_decl = sum(len(e.not_instantiated) for e in entries)
            listing = ", ".join(
                f"{e.path} ({', '.join(f'{n} {t}' for t, n in e.types_not_instantiated) or '0 declarations'})" for e in entries
            )
            noun = "configuration" if len(entries) == 1 else "configurations"
            decl_noun = "declaration" if n_decl == 1 else "declarations"
            lines.append(
                f"{len(entries)} {noun} {label} ({why}) — {n_decl} resource {decl_noun} not instantiated: {listing}"
            )
        return tuple(lines)


# --------------------------------------------------------------------------- the model


_COLLECTIONS = (
    "artifacts",
    "facts",
    "configurations",
    "module_sources",
    "module_calls",
    "deployment_contexts",
    "module_instances",
    "resource_declarations",
    "resource_instances",
    "backend_evidence",
    "state_artifacts",
    "var_files",
    "evidence",
    "inferences",
    "ambiguities",
    "diagnostics",
)


@dataclass(frozen=True)
class RepositoryModel:
    """Everything Repository Intelligence knows about one repository.

    Construction is order-independent: every collection is sorted by id and
    duplicate ids are rejected, so the same repository always yields the same
    model and byte-identical :meth:`to_json`.
    """

    anchor: RepositoryAnchor
    artifacts: tuple[RawArtifact, ...] = ()
    facts: tuple[ObservedFact, ...] = ()
    configurations: tuple[TerraformConfiguration, ...] = ()
    module_sources: tuple[ModuleSource, ...] = ()
    module_calls: tuple[ModuleCall, ...] = ()
    deployment_contexts: tuple[DeploymentContext, ...] = ()
    module_instances: tuple[ModuleInstance, ...] = ()
    resource_declarations: tuple[ResourceDeclaration, ...] = ()
    resource_instances: tuple[DesiredResourceInstance, ...] = ()
    backend_evidence: tuple[BackendEvidence, ...] = ()
    state_artifacts: tuple[StateArtifact, ...] = ()
    var_files: tuple[VarFileArtifact, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    inferences: tuple[Inference, ...] = ()
    ambiguities: tuple[Ambiguity, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    schema_version: int = CURRENT_REPOSITORY_MODEL_VERSION

    def __post_init__(self) -> None:
        seen: dict[str, str] = {}
        for name in _COLLECTIONS:
            items = tuple(sorted(getattr(self, name), key=lambda x: x.id))
            for item in items:
                if item.id in seen:
                    raise ValueError(f"duplicate id {item.id!r} (in {seen[item.id]} and {name})")
                seen[item.id] = name
            _set(self, name, items)

    # ---- lookup

    @cached_property
    def _index(self) -> dict[str, Any]:
        return {item.id: item for name in _COLLECTIONS for item in getattr(self, name)}

    def get(self, entity_id: str) -> Any | None:
        return self._index.get(entity_id)

    def _all(self) -> Iterator[Any]:
        for name in _COLLECTIONS:
            yield from getattr(self, name)

    def inferences_about(self, subject: str) -> tuple[Inference, ...]:
        return tuple(i for i in self.inferences if i.subject == subject)

    def role_counts(self) -> dict[str, int]:
        """A3 conservation: every configuration is counted exactly once
        (UNCLASSIFIED for those that stopped at DISCOVERED)."""
        counts = Counter(c.role.value if c.role else "UNCLASSIFIED" for c in self.configurations)
        return dict(sorted(counts.items()))

    # ---- DIM boundary

    def desired_instances(self) -> tuple[DesiredResourceInstance, ...]:
        """The DIM projection input: desired instances of *instantiated*
        contexts only. Deferred/not-applicable configurations contribute none,
        but stay fully represented in the model (see declaration_inventory)."""
        live = {ctx for c in self.configurations if c.lifecycle.instantiation for ctx in c.lifecycle.instantiation.contexts}
        return tuple(i for i in self.resource_instances if i.context in live)

    def declaration_inventory(self) -> DeclarationInventory:
        instantiated = {i.declaration for i in self.resource_instances}
        by_cfg: dict[str, list[ResourceDeclaration]] = defaultdict(list)
        for d in self.resource_declarations:
            by_cfg[d.configuration].append(d)
        entries = []
        for c in self.configurations:
            decls = by_cfg.get(c.id, [])
            missing = [d for d in decls if d.id not in instantiated]
            record = c.lifecycle.instantiation
            entries.append(
                InventoryEntry(
                    configuration=c.id,
                    path=c.path,
                    role=c.role,
                    confidence=c.classification.confidence if c.classification else None,
                    stage=c.lifecycle.stage,
                    status=record.status if record else None,
                    reason=record.reason if record else None,
                    declarations=tuple(d.id for d in decls),
                    not_instantiated=tuple(d.id for d in missing),
                    types_not_instantiated=tuple(sorted(Counter(d.provider_type for d in missing).items())),
                )
            )
        return DeclarationInventory(tuple(entries))

    # ---- serialization

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)

    def to_json(self) -> str:
        return ids.canonical_json(self.to_dict())

    # ---- invariants

    def validate(self) -> tuple[str, ...]:
        """Referential integrity plus the model invariants. Returns violations
        (empty when valid); never mutates or drops anything."""
        v: list[str] = []
        idx = self._index

        def ref(owner: str, target: str | None, kinds: tuple[type, ...]) -> None:
            if target is not None and not isinstance(idx.get(target), kinds):
                v.append(f"{owner}: dangling reference {target!r}")

        for f in self.facts:
            ref(f.id, f.artifact, (RawArtifact,))
        for e in self.evidence:
            for fid in e.facts:
                ref(e.id, fid, (ObservedFact,))
        for inf in self.inferences:
            for eid in (*inf.supporting, *inf.contrary):
                ref(inf.id, eid, (Evidence,))
            v.extend(self._name_hint_violations(inf))
        for a in self.ambiguities:
            for eid in a.reasons:
                ref(a.id, eid, (Evidence,))
        for d in self.diagnostics:
            for eid in d.evidence:
                ref(d.id, eid, (Evidence,))

        ambiguous_subjects = {a.subject for a in self.ambiguities}
        for c in self.configurations:
            for f in c.files:
                ref(c.id, f.artifact, (RawArtifact,))
            cl = c.classification
            if cl is not None:
                ref(c.id, cl.inference, (Inference,))
                for ra in (cl.root_role, cl.module_role):
                    for eid in (*ra.supporting, *ra.contrary):
                        ref(c.id, eid, (Evidence,))
                if cl.role is ConfigurationRole.AMBIGUOUS and c.id not in ambiguous_subjects:
                    v.append(f"{c.id}: AMBIGUOUS configuration has no Ambiguity record (alternatives/reasons)")
            rec = c.lifecycle.instantiation
            if rec is not None:
                ref(c.id, rec.inference, (Inference,))
                for ctx in rec.contexts:
                    ref(c.id, ctx, (DeploymentContext,))
                    ctx_obj = idx.get(ctx)
                    if isinstance(ctx_obj, DeploymentContext) and ctx_obj.root != c.id:
                        v.append(f"{c.id}: lists context {ctx} rooted at {ctx_obj.root}")
                for mi in rec.instances:
                    ref(c.id, mi, (ModuleInstance,))

        for ms in self.module_sources:
            ref(ms.id, ms.configuration, (TerraformConfiguration,))
        for call in self.module_calls:
            ref(call.id, call.caller, (TerraformConfiguration,))
            ref(call.id, call.source, (ModuleSource,))
            ref(call.id, call.evidence, (Evidence,))
        for d in self.resource_declarations:
            ref(d.id, d.configuration, (TerraformConfiguration,))
            ref(d.id, d.evidence, (Evidence,))
        for b in self.backend_evidence:
            ref(b.id, b.configuration, (TerraformConfiguration,))
            ref(b.id, b.evidence, (Evidence,))
        for s in self.state_artifacts:
            ref(s.id, s.bound_context, (DeploymentContext,))
            ref(s.id, s.binding, (Inference,))

        for ctx in self.deployment_contexts:
            ref(ctx.id, ctx.root, (TerraformConfiguration,))
            ref(ctx.id, ctx.backend, (BackendEvidence,))
            for vf in ctx.var_files:
                ref(ctx.id, vf, (VarFileArtifact,))
            for st in ctx.state:
                ref(ctx.id, st, (StateArtifact,))
            root = idx.get(ctx.root)
            if isinstance(root, TerraformConfiguration):
                if root.role is not ctx.role:
                    v.append(f"{ctx.id}: context role {ctx.role.value} != root classification {root.role.value if root.role else None}")
                elif root.classification and ctx.confidence > root.classification.confidence:
                    v.append(f"{ctx.id}: context confidence promoted above its root classification")

        for mi in self.module_instances:
            ref(mi.id, mi.context, (DeploymentContext,))
            ref(mi.id, mi.call, (ModuleCall,))
            ref(mi.id, mi.source, (ModuleSource,))
            ref(mi.id, mi.source_configuration, (TerraformConfiguration,))

        live_contexts = {i.context for i in self.desired_instances()}
        for inst in self.resource_instances:
            ref(inst.id, inst.declaration, (ResourceDeclaration,))
            ctx = idx.get(inst.context)
            if not isinstance(ctx, DeploymentContext):
                v.append(f"{inst.id}: dangling reference {inst.context!r}")
                continue
            if inst.context_role is not ctx.role:
                v.append(f"{inst.id}: context_role {inst.context_role.value} != context role {ctx.role.value} (no promotion)")
            if inst.confidence > ctx.confidence:
                v.append(f"{inst.id}: confidence {inst.confidence.value} promoted above context {ctx.confidence.value}")
            if inst.context not in live_contexts:
                v.append(f"{inst.id}: desired instance of a context that was not instantiated")

        for s in self._strings(self.to_dict()):
            if ids.is_absolute_path(s):
                v.append(f"absolute path in model: {s!r}")
        return tuple(v)

    def assert_valid(self) -> None:
        violations = self.validate()
        if violations:
            raise ValueError("invalid RepositoryModel:\n  " + "\n  ".join(violations))

    def _name_hint_violations(self, inf: Inference) -> list[str]:
        """Names are weak hints: a conclusion resting only on NAME_HINT evidence
        may be at most LOW, and cannot stand against content evidence >= MEDIUM."""
        support = [self._index.get(e) for e in inf.supporting]
        support = [e for e in support if isinstance(e, Evidence)]
        if not support or any(e.basis is EvidenceBasis.CONTENT for e in support):
            return []
        out = []
        if inf.confidence > Confidence.LOW:
            out.append(f"{inf.id}: conclusion supported only by name hints cannot exceed LOW")
        contrary = [self._index.get(e) for e in inf.contrary]
        if any(isinstance(e, Evidence) and e.basis is EvidenceBasis.CONTENT and e.strength >= Confidence.MEDIUM for e in contrary):
            out.append(f"{inf.id}: name hints cannot override contrary content evidence")
        return out

    @classmethod
    def _strings(cls, value: Any) -> Iterator[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for v in value.values():
                yield from cls._strings(v)
        elif isinstance(value, list):
            for v in value:
                yield from cls._strings(v)
