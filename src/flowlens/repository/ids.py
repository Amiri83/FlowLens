"""Deterministic, repository-relative identity for Repository Intelligence (ADR 0003).

Every id is built from an *anchor-relative POSIX path* plus Terraform-native
names. Nothing machine-dependent may enter an id: no absolute paths, hostnames,
usernames, timestamps, UUIDs, random values, dict/set iteration order, or cloud
account ids. The same repository checked out at ``/home/alice/project``,
``/tmp/project`` or ``/build/project`` therefore produces identical ids.

Id forms (proposal §35)::

    art:<path>                          raw artifact
    cfg:<path>                          Terraform configuration (one per directory)
    modsrc:<kind>:<locator>             module source (where module code comes from)
    call:<cfg>::module.<name>           module call (a `module` block in a configuration)
    ctx:root:<cfg>                      deployment context (one independent apply unit)
    <ctx>::<module path>                module instance (a call, in a context)
    decl:<cfg>::<mode>.<type>.<name>    resource declaration (one block)
    tf:<cfg>::<address>                 desired resource instance (future DIM node id)
    fact:/ev:<digest>, inf:<rule>:<subject>, amb:<kind>:<subject>

``<cfg>``/``<path>`` inside ids have ``%`` and ``:`` percent-encoded, so the
first ``::`` in an id is always the qualifier separator; Terraform keys such as
``["a::b"]`` can only occur after it.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from flowlens.repository.enums import AnchorKind, ArtifactKind, DeclarationMode, ModuleSourceKind
from flowlens.repository.redact import canonical_source_url

DIGEST_LENGTH = 16
DEFAULT_REGISTRY_HOST = "registry.terraform.io"

_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


# --------------------------------------------------------------------------- canonical form


def canonical_json(value: Any) -> str:
    """Canonical serialization for anything hashed into an id: sorted keys,
    fixed separators, no whitespace, UTF-8 preserved."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default)


def _json_default(value: Any) -> Any:
    if isinstance(value, tuple | frozenset | set):
        items = list(value)
        return sorted(items, key=canonical_json) if isinstance(value, frozenset | set) else items
    if hasattr(value, "value"):  # Enum
        return value.value
    raise TypeError(f"not canonically serializable: {type(value).__name__}")


def digest(value: Any, length: int = DIGEST_LENGTH) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:length]


# --------------------------------------------------------------------------- paths


def is_absolute_path(path: str) -> bool:
    return path.startswith(("/", "\\\\")) or bool(_WINDOWS_ABS_RE.match(path))


def normalize_rel_path(path: str) -> str:
    """Normalize an anchor-relative POSIX path: ``posixpath.normpath``, no
    trailing slash, ``"."`` for the anchor itself, case preserved. Absolute
    paths are rejected: they must never enter the model."""
    if is_absolute_path(path):
        raise ValueError(f"absolute path is not allowed in the repository model: {path!r}")
    norm = posixpath.normpath(path) if path else "."
    return norm.rstrip("/") or "."


def is_outside(rel_path: str) -> bool:
    """True when an anchor-relative path escapes the anchor (``../x``)."""
    return rel_path == ".." or rel_path.startswith("../")


def encode_path(rel_path: str) -> str:
    """Encode a normalized relative path for use inside an id."""
    return normalize_rel_path(rel_path).replace("%", "%25").replace(":", "%3A")


@dataclass(frozen=True)
class AnchorResolution:
    """The anchor of one scan. Transient: holds the absolute anchor directory
    only so paths can be made relative. It is never stored in the model; the
    model stores :class:`~flowlens.repository.model.RepositoryAnchor` instead."""

    kind: AnchorKind
    scan_root_rel: str
    directory: Path = field(repr=False, compare=False)

    def relative(self, path: str | os.PathLike[str]) -> str:
        """Lexical anchor-relative POSIX path (``..`` segments if outside)."""
        rel = os.path.relpath(os.path.abspath(path), self.directory)
        return normalize_rel_path(PurePosixPath(Path(rel)).as_posix())


def resolve_anchor(scan_path: str | os.PathLike[str]) -> AnchorResolution:
    """Nearest ancestor of `scan_path` containing ``.git`` (a directory, or a
    file for worktrees/submodules), by filesystem lookup only - no git binary.
    Falls back to the scan root itself (``kind=scan_root``)."""
    start = Path(os.path.abspath(scan_path))
    scan_dir = start if start.is_dir() or not start.exists() else start.parent
    for candidate in (scan_dir, *scan_dir.parents):
        if (candidate / ".git").exists():
            anchor = AnchorResolution(AnchorKind.GIT_TOPLEVEL, ".", candidate)
            return AnchorResolution(AnchorKind.GIT_TOPLEVEL, anchor.relative(scan_dir), candidate)
    return AnchorResolution(AnchorKind.SCAN_ROOT, ".", scan_dir)


def artifact_kind_for(rel_path: str, *, is_dir: bool = False) -> ArtifactKind:
    """Syntactic artifact kind from extension and Terraform-defined filename
    rules only. Any other filename carries no meaning."""
    p = normalize_rel_path(rel_path)
    name = posixpath.basename(p)
    parts = p.split("/")
    if is_dir:
        return ArtifactKind.DOT_TERRAFORM_DIR if name == ".terraform" else ArtifactKind.DIRECTORY
    if name == ".terraform.lock.hcl":
        return ArtifactKind.LOCKFILE
    if name in ("override.tf", "override.tf.json") or name.endswith(("_override.tf", "_override.tf.json")):
        return ArtifactKind.TF_OVERRIDE
    if name.endswith(".tf.json"):
        return ArtifactKind.TF_JSON
    if name.endswith(".tf"):
        return ArtifactKind.TF_HCL
    if name.endswith(".tfvars.json"):
        return ArtifactKind.TFVARS_JSON
    if name.endswith(".auto.tfvars"):
        return ArtifactKind.AUTO_TFVARS
    if name.endswith(".tfvars"):
        return ArtifactKind.TFVARS
    if name.endswith((".tfstate", ".tfstate.backup")):
        return ArtifactKind.TFSTATE
    if name == "terragrunt.hcl":
        return ArtifactKind.TERRAGRUNT_HCL
    if name in (".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", "atlantis.yaml") or (
        len(parts) >= 3 and parts[-3:-1] == [".github", "workflows"] and name.endswith((".yml", ".yaml"))
    ):
        return ArtifactKind.CI_CONFIG
    return ArtifactKind.OTHER


# --------------------------------------------------------------------------- id builders


def artifact_id(rel_path: str) -> str:
    return f"art:{encode_path(rel_path)}"


def configuration_id(rel_dir: str) -> str:
    return f"cfg:{encode_path(rel_dir)}"


def module_source_id(kind: ModuleSourceKind, locator: str) -> str:
    """Identity of *where module code comes from*, independent of how many
    times or by whom it is called. Credentials never enter the id."""
    if kind is ModuleSourceKind.LOCAL:
        return f"modsrc:local:{encode_path(locator)}"
    if kind is ModuleSourceKind.REGISTRY:
        addr, _, subdir = locator.partition("//")
        parts = addr.split("/")
        if len(parts) == 3:
            parts.insert(0, DEFAULT_REGISTRY_HOST)
        if len(parts) != 4 or not all(parts):
            raise ValueError(f"registry module source must be [host/]namespace/name/provider: {locator!r}")
        return f"modsrc:registry:{'/'.join(parts)}" + (f"//{subdir}" if subdir else "")
    return f"modsrc:{kind.value}:{canonical_source_url(locator)}"


def _check_module_path(module_path: str) -> str:
    if not module_path.startswith("module."):
        raise ValueError(f"module path must start with 'module.': {module_path!r}")
    return module_path


def module_call_id(caller_rel_dir: str, name: str) -> str:
    return f"call:{encode_path(caller_rel_dir)}::module.{name}"


def context_id(root_rel_dir: str) -> str:
    """Default (unqualified) deployment context of a root configuration.
    Future qualified contexts (workspace / var-file) append ``@...`` and leave
    this id valid (ADR 0011)."""
    return f"ctx:root:{encode_path(root_rel_dir)}"


def module_instance_id(ctx_id: str, module_path: str) -> str:
    if not ctx_id.startswith("ctx:root:"):
        raise ValueError(f"not a deployment context id: {ctx_id!r}")
    return f"{ctx_id}::{_check_module_path(module_path)}"


def declaration_id(cfg_rel_dir: str, mode: DeclarationMode, provider_type: str, name: str) -> str:
    return f"decl:{encode_path(cfg_rel_dir)}::{mode.value}.{provider_type}.{name}"


def desired_instance_id(ctx_id: str, address: str) -> str:
    """``tf:<root cfg>::<address>``: keeps the legacy ``tf:`` prefix (consumers
    test ``startswith("tf:")``) and qualifies the context-relative Terraform
    address with the root configuration of its deployment context."""
    if not ctx_id.startswith("ctx:root:") or "::" in ctx_id:
        raise ValueError(f"not a deployment context id: {ctx_id!r}")
    if not address:
        raise ValueError("empty Terraform address")
    return f"tf:{ctx_id.removeprefix('ctx:root:')}::{address}"


def split_desired_instance_id(node_id: str) -> tuple[str, str]:
    """``tf:<cfg>::<address>`` -> (encoded cfg, address); splits on the FIRST ``::``."""
    if not node_id.startswith("tf:") or "::" not in node_id:
        raise ValueError(f"not a configuration-qualified desired instance id: {node_id!r}")
    cfg, address = node_id.removeprefix("tf:").split("::", 1)
    return cfg, address


def fact_id(artifact: str, locator: Any, kind: Any, payload: Any) -> str:
    return "fact:" + digest({"artifact": artifact, "locator": locator, "kind": kind, "payload": payload})


def evidence_id(kind: Any, claim: str, subject: str, facts: Iterable[str], polarity: Any, basis: Any) -> str:
    return "ev:" + digest({"kind": kind, "claim": claim, "subject": subject, "facts": sorted(facts), "polarity": polarity, "basis": basis})


def inference_id(rule_id: str | None, subject: str) -> str:
    return f"inf:{rule_id or 'ASSERTED'}:{subject}"


def ambiguity_id(kind: Any, subject: str) -> str:
    return f"amb:{getattr(kind, 'value', kind)}:{subject}"


def diagnostic_id(code: str, subject: str, message: str) -> str:
    return "diag:" + digest({"code": code, "subject": subject, "message": message})


def backend_evidence_id(cfg_rel_dir: str, kind: Any) -> str:
    return f"backend:{encode_path(cfg_rel_dir)}::{getattr(kind, 'value', kind)}"


def state_artifact_id(rel_path: str) -> str:
    return f"state:{encode_path(rel_path)}"


def var_file_id(rel_path: str) -> str:
    return f"varfile:{encode_path(rel_path)}"
