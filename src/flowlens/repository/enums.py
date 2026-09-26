"""Closed vocabularies of the Repository Intelligence (RI) domain model.

Everything here is Terraform-native and provider-neutral. Values are plain
strings (``(str, Enum)``) so they serialize to stable, human-readable JSON.

Confidence is *ordinal only* (see ADR 0004): CERTAIN > HIGH > MEDIUM > LOW >
UNKNOWN. There are no floating-point scores anywhere in the model.
"""
from __future__ import annotations

from enum import Enum


class Confidence(str, Enum):
    """Ordinal confidence. Compare with ``<``/``>=`` or :func:`min_confidence`.

    CERTAIN  an observed or structural fact, or an ASSERTED claim.
    HIGH     strong direct evidence, no medium-or-stronger contrary evidence.
    MEDIUM   consistent evidence, but key corroboration is missing.
    LOW      weak or indirect evidence only; plausible, not actionable.
    UNKNOWN  insufficient evidence. A legitimate result, never coerced.
    """

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CERTAIN = "CERTAIN"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank >= other.rank


_CONFIDENCE_RANK = {c: i for i, c in enumerate(Confidence)}


def min_confidence(*values: Confidence) -> Confidence:
    """C-min: a derived conclusion is no stronger than its weakest premise."""
    if not values:
        raise ValueError("min_confidence() needs at least one value")
    return min(values, key=lambda c: c.rank)


class ProvenanceKind(str, Enum):
    """How a piece of evidence came to be (ADR 0006)."""

    OBSERVED = "OBSERVED"        # read directly from an artifact
    STRUCTURAL = "STRUCTURAL"    # computed from observed facts with Terraform's own rules
    INFERRED = "INFERRED"        # heuristic judgement; at most HIGH, backed by an Inference
    ASSERTED = "ASSERTED"        # user-provided; labelled as such


class Polarity(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"


class EvidenceBasis(str, Enum):
    """What the evidence is *about*.

    CONTENT    Terraform content or Terraform-defined filename semantics
               (backend block, ``terraform.tfvars``, lock file, a call edge, ...).
    NAME_HINT  a directory/file *name* chosen by a human (``modules/``, ``prod/``).
               Names are weak hints only and can never be decisive (ADR 0006).
    """

    CONTENT = "CONTENT"
    NAME_HINT = "NAME_HINT"


class ConfigurationRole(str, Enum):
    CONFIRMED_ROOT = "CONFIRMED_ROOT"
    PROBABLE_ROOT = "PROBABLE_ROOT"
    MODULE_SOURCE = "MODULE_SOURCE"
    DUAL_ROLE = "DUAL_ROLE"
    AMBIGUOUS = "AMBIGUOUS"
    UNKNOWN = "UNKNOWN"


#: Roles that own a root DeploymentContext (and therefore may yield DIM instances).
ROOT_CAPABLE_ROLES = frozenset({ConfigurationRole.CONFIRMED_ROOT, ConfigurationRole.PROBABLE_ROOT, ConfigurationRole.DUAL_ROLE})


class RoleStatus(str, Enum):
    """Outcome of assessing one role (root or module) independently."""

    YES = "yes"
    NO = "no"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"


class LifecycleStage(str, Enum):
    """Furthest pipeline stage a configuration reached. Stages never regress
    within a scan, and discovery never implies instantiation."""

    DISCOVERED = "DISCOVERED"
    CLASSIFIED = "CLASSIFIED"
    INSTANTIATED = "INSTANTIATED"
    CORRELATED = "CORRELATED"

    @property
    def rank(self) -> int:
        return list(LifecycleStage).index(self)


class InstantiationStatus(str, Enum):
    RESOLVED_ROOT = "RESOLVED_ROOT"
    RESOLVED_INSTANCES = "RESOLVED_INSTANCES"
    RESOLVED_BOTH = "RESOLVED_BOTH"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DEFERRED = "DEFERRED"
    PARTIAL = "PARTIAL"


#: Statuses that must carry a reason code and an inference id.
STATUSES_REQUIRING_REASON = frozenset({InstantiationStatus.NOT_APPLICABLE, InstantiationStatus.DEFERRED, InstantiationStatus.PARTIAL})


class InstantiationReason(str, Enum):
    AMBIGUOUS_ROLE = "AMBIGUOUS_ROLE"
    CYCLE_ONLY = "CYCLE_ONLY"
    CALLER_DEFERRED = "CALLER_DEFERRED"
    PARSE_FAILED = "PARSE_FAILED"
    ROOT_ROLE_WEAK = "ROOT_ROLE_WEAK"
    SOURCE_UNREADABLE = "SOURCE_UNREADABLE"
    UNUSED_MODULE_SOURCE = "UNUSED_MODULE_SOURCE"


class AmbiguityKind(str, Enum):
    ROLE = "ROLE"                          # comparable evidence for mutually exclusive roles (ROLE-U3)
    CYCLE_ONLY = "CYCLE_ONLY"              # reachable only through a module cycle (ROLE-X1)
    CALLER_DEFERRED = "CALLER_DEFERRED"    # only callers are themselves deferred (ROLE-X2)
    STATE_BINDING = "STATE_BINDING"        # a state artifact matches zero or several contexts


class CardinalityKind(str, Enum):
    STATICALLY_RESOLVABLE = "STATICALLY_RESOLVABLE"
    PARTIALLY_RESOLVABLE = "PARTIALLY_RESOLVABLE"
    RUNTIME_DEPENDENT = "RUNTIME_DEPENDENT"
    UNKNOWN = "UNKNOWN"


class AnchorKind(str, Enum):
    GIT_TOPLEVEL = "git_toplevel"
    SCAN_ROOT = "scan_root"


class ArtifactKind(str, Enum):
    """Syntactic artifact kind, assigned by extension and Terraform-defined
    filename rules only (see :func:`flowlens.repository.ids.artifact_kind_for`)."""

    TF_HCL = "tf_hcl"
    TF_JSON = "tf_json"
    TF_OVERRIDE = "tf_override"
    TFVARS = "tfvars"
    AUTO_TFVARS = "auto_tfvars"
    TFVARS_JSON = "tfvars_json"
    LOCKFILE = "lockfile"
    TFSTATE = "tfstate"
    TERRAGRUNT_HCL = "terragrunt_hcl"
    CI_CONFIG = "ci_config"
    DOT_TERRAFORM_DIR = "dot_terraform_dir"
    DIRECTORY = "directory"
    OTHER = "other"


class ReadStatus(str, Enum):
    OK = "ok"
    UNREADABLE = "unreadable"
    TOO_LARGE = "too_large"
    SKIPPED_BY_POLICY = "skipped_by_policy"


class ParseStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class FactKind(str, Enum):
    """Parser-level statements. None of these is a judgement."""

    BLOCK_PRESENT = "BLOCK_PRESENT"
    META_ARG_PRESENT = "META_ARG_PRESENT"
    MODULE_SOURCE_LITERAL = "MODULE_SOURCE_LITERAL"
    BACKEND_BLOCK = "BACKEND_BLOCK"
    CLOUD_BLOCK = "CLOUD_BLOCK"
    PROVIDER_CONFIG = "PROVIDER_CONFIG"
    VARIABLE_DECLARED = "VARIABLE_DECLARED"
    OUTPUT_DECLARED = "OUTPUT_DECLARED"
    LOCALS_DECLARED = "LOCALS_DECLARED"
    MOVED_BLOCK = "MOVED_BLOCK"
    IMPORT_BLOCK = "IMPORT_BLOCK"
    CHECK_BLOCK = "CHECK_BLOCK"
    REMOVED_BLOCK = "REMOVED_BLOCK"
    REFERENCE = "REFERENCE"
    LITERAL_ATTRIBUTE = "LITERAL_ATTRIBUTE"
    ARTIFACT_PRESENT = "ARTIFACT_PRESENT"    # e.g. a lock file or .terraform/ exists
    PATH_SEGMENT = "PATH_SEGMENT"            # a path contains a segment; input for NAME_HINT evidence only
    PARSE_ERROR = "PARSE_ERROR"


class ModuleSourceKind(str, Enum):
    LOCAL = "local"
    REGISTRY = "registry"
    GIT = "git"
    HTTP = "http"
    OTHER = "other"


class DeclarationMode(str, Enum):
    MANAGED = "managed"
    DATA = "data"


class BackendKind(str, Enum):
    BACKEND = "backend"
    CLOUD = "cloud"


class StateFormat(str, Enum):
    RAW_TFSTATE_V4 = "raw_tfstate_v4"
    SHOW_JSON = "show_json"
    PLAN_JSON = "plan_json"
    UNKNOWN = "unknown"


class VarFileKind(str, Enum):
    TERRAFORM_TFVARS = "terraform.tfvars"
    AUTO_TFVARS = "auto.tfvars"
    NAMED_TFVARS = "named_tfvars"
    TFVARS_JSON = "tfvars_json"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
