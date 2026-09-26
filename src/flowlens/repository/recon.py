"""Stage 1 of reconnaissance: boundary discovery and raw artifacts (proposal §6).

Walks the scan root deterministically (sorted, repository-relative) and
records every Terraform-relevant file as a :class:`RawArtifact` with a
*syntactic* kind (extension and Terraform-defined filename rules only). Nothing
is interpreted here: no file content is judged, no directory is called a root
or a module.

Rules:

- :data:`SKIP_DIRS` are never descended into. ``.terraform/`` is the one skip
  directory whose *presence* is recorded (it means ``terraform init`` ran
  there); its contents (downloaded modules/providers) are never scanned.
- Symlinks are followed only when their target stays inside the anchor, and
  never into a directory already on the current walk path (loops). Anything
  else yields a diagnostic and is not followed.
- Paths are anchor-relative POSIX strings. The absolute anchor directory is
  used only to open files and never leaves this module.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from flowlens.repository import ids
from flowlens.repository.enums import ArtifactKind, ReadStatus, Severity
from flowlens.repository.model import Diagnostic, RawArtifact

#: Directories never descended into: Terraform/Terragrunt caches (downloaded
#: copies, not the user's configuration) and VCS/tooling directories.
SKIP_DIRS = frozenset({".terraform", ".terragrunt-cache", ".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__"})

#: Terraform configuration files: together they form one configuration per directory.
CONFIG_KINDS = frozenset({ArtifactKind.TF_HCL, ArtifactKind.TF_JSON, ArtifactKind.TF_OVERRIDE})

#: Kinds recorded as artifacts. CI files and everything else are out of scope
#: for structural reconnaissance and are not recorded.
_RECORDED_KINDS = CONFIG_KINDS | {
    ArtifactKind.TFVARS,
    ArtifactKind.AUTO_TFVARS,
    ArtifactKind.TFVARS_JSON,
    ArtifactKind.LOCKFILE,
    ArtifactKind.TFSTATE,
    ArtifactKind.TERRAGRUNT_HCL,
}

#: Kinds whose text is needed downstream (configuration files; var files for
#: their variable *names* only). State files are hashed, never parsed.
_TEXT_KINDS = CONFIG_KINDS | {ArtifactKind.TFVARS, ArtifactKind.AUTO_TFVARS, ArtifactKind.TFVARS_JSON}

MAX_FILE_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class DiscoveredFile:
    artifact: RawArtifact
    text: str | None = field(default=None, repr=False)  # transient; never stored in the model

    @property
    def path(self) -> str:
        return self.artifact.path

    @property
    def kind(self) -> ArtifactKind:
        assert self.artifact.kind is not None
        return self.artifact.kind


@dataclass
class DirectoryListing:
    """Terraform material found directly inside one directory."""

    path: str
    files: list[DiscoveredFile] = field(default_factory=list)
    dot_terraform: RawArtifact | None = None
    outside_scan_root: bool = False

    @property
    def config_files(self) -> list[DiscoveredFile]:
        return [f for f in self.files if f.kind in CONFIG_KINDS]

    def of_kind(self, *kinds: ArtifactKind) -> list[DiscoveredFile]:
        return [f for f in self.files if f.kind in kinds]


@dataclass
class Discovery:
    """Everything stage 1 found. `directories` maps an anchor-relative dir to
    its listing; iteration helpers are sorted."""

    anchor: ids.AnchorResolution
    directories: dict[str, DirectoryListing] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def listing(self, rel_dir: str) -> DirectoryListing:
        return self.directories.setdefault(rel_dir, DirectoryListing(rel_dir))

    def sorted_directories(self) -> list[DirectoryListing]:
        return [self.directories[k] for k in sorted(self.directories)]

    def configuration_dirs(self) -> list[str]:
        return sorted(d for d, lst in self.directories.items() if lst.config_files)

    def artifacts(self) -> list[RawArtifact]:
        out = []
        for lst in self.sorted_directories():
            out.extend(f.artifact for f in lst.files)
            if lst.dot_terraform is not None:
                out.append(lst.dot_terraform)
        return out

    def diag(self, code: str, severity: Severity, subject: str, message: str) -> None:
        self.diagnostics.append(Diagnostic(code, severity, subject, message))


def _within(real: str, base_real: str) -> bool:
    return real == base_real or real.startswith(base_real.rstrip(os.sep) + os.sep)


def _read(discovery: Discovery, abs_path: str, rel_path: str, kind: ArtifactKind) -> DiscoveredFile:
    try:
        size = os.path.getsize(abs_path)
        if size > MAX_FILE_BYTES:
            discovery.diag("RI-ARTIFACT-TOO-LARGE", Severity.WARNING, ids.artifact_id(rel_path),
                           f"{rel_path}: {size} bytes exceeds the {MAX_FILE_BYTES}-byte limit; not read")
            return DiscoveredFile(RawArtifact(rel_path, kind, size=size, read_status=ReadStatus.TOO_LARGE))
        with open(abs_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        discovery.diag("RI-ARTIFACT-UNREADABLE", Severity.WARNING, ids.artifact_id(rel_path),
                       f"{rel_path}: unreadable ({type(exc).__name__})")
        return DiscoveredFile(RawArtifact(rel_path, kind, read_status=ReadStatus.UNREADABLE))
    artifact = RawArtifact(rel_path, kind, size=len(data), sha256=hashlib.sha256(data).hexdigest())
    text = None
    if kind in _TEXT_KINDS:
        text = data.decode("utf-8", errors="replace")
    return DiscoveredFile(artifact, text)


def _scan_directory(discovery: Discovery, abs_dir: str, rel_dir: str, anchor_real: str, active: frozenset[str],
                    recursive: bool, outside_scan_root: bool = False) -> None:
    """Record the Terraform material of one directory; descend if `recursive`."""
    listing = discovery.listing(rel_dir)
    listing.outside_scan_root = listing.outside_scan_root or outside_scan_root
    try:
        entries = sorted(os.scandir(abs_dir), key=lambda e: e.name)
    except OSError as exc:
        discovery.diag("RI-ARTIFACT-UNREADABLE", Severity.WARNING, ids.artifact_id(rel_dir),
                       f"{rel_dir}: directory unreadable ({type(exc).__name__})")
        return
    for entry in entries:
        rel = ids.normalize_rel_path(posixpath.join(rel_dir, entry.name))
        is_link = entry.is_symlink()
        if is_link:
            real = os.path.realpath(entry.path)
            if not _within(real, anchor_real):
                discovery.diag("RI-SYMLINK-OUTSIDE-ANCHOR", Severity.WARNING, ids.artifact_id(rel),
                               f"{rel}: symlink target is outside the repository anchor; not followed")
                continue
            if not os.path.exists(real):
                discovery.diag("RI-SYMLINK-BROKEN", Severity.WARNING, ids.artifact_id(rel), f"{rel}: broken symlink; not followed")
                continue
        if entry.is_dir():  # follows in-anchor symlinks
            if entry.name == ".terraform":
                listing.dot_terraform = RawArtifact(rel, ArtifactKind.DOT_TERRAFORM_DIR, read_status=ReadStatus.SKIPPED_BY_POLICY)
                continue
            if entry.name in SKIP_DIRS or not recursive:
                continue
            real_dir = os.path.realpath(entry.path)
            if real_dir in active:
                discovery.diag("RI-SYMLINK-LOOP", Severity.WARNING, ids.artifact_id(rel),
                               f"{rel}: symlink points back into its own walk path; not followed")
                continue
            _scan_directory(discovery, entry.path, rel, anchor_real, active | {real_dir}, recursive)
            continue
        if not entry.is_file():
            continue
        kind = ids.artifact_kind_for(rel)
        if kind not in _RECORDED_KINDS:
            continue
        listing.files.append(_read(discovery, entry.path, rel, kind))
        if kind is ArtifactKind.TERRAGRUNT_HCL:
            discovery.diag("RI-UNSUPPORTED-CONSTRUCT", Severity.INFO, ids.artifact_id(rel),
                           f"{rel}: Terragrunt configuration recorded; Terragrunt semantics are not interpreted")


def discover(scan_path: str | os.PathLike[str]) -> Discovery:
    """Recursively discover Terraform material under `scan_path`."""
    anchor = ids.resolve_anchor(scan_path)
    discovery = Discovery(anchor)
    anchor_real = os.path.realpath(anchor.directory)
    scan_abs = os.path.join(anchor.directory, anchor.scan_root_rel)
    if anchor.kind.value == "scan_root":
        discovery.diag("RI-ANCHOR-SCAN-ROOT", Severity.WARNING, "anchor",
                       "no .git found above the scan path: identities are relative to the scan root, "
                       "so scanning a parent directory later changes them")
    if not os.path.isdir(scan_abs):
        discovery.diag("RI-SCAN-ROOT-MISSING", Severity.ERROR, "anchor", "scan path is not a directory")
        return discovery
    _scan_directory(discovery, scan_abs, anchor.scan_root_rel, anchor_real, frozenset({os.path.realpath(scan_abs)}), recursive=True)
    return discovery


def in_scan_root(discovery: Discovery, rel_dir: str) -> bool:
    root = discovery.anchor.scan_root_rel
    return root == "." or rel_dir == root or rel_dir.startswith(root + "/")


def load_directory(discovery: Discovery, rel_dir: str) -> DirectoryListing | None:
    """Read a directory outside the scan root but inside the anchor (a local
    module source such as ``../modules/x``), non-recursively. Returns None if
    it cannot be read; never leaves the anchor."""
    if ids.is_outside(rel_dir):
        return None
    if rel_dir in discovery.directories:
        return discovery.directories[rel_dir]
    abs_dir = os.path.join(discovery.anchor.directory, rel_dir)
    anchor_real = os.path.realpath(discovery.anchor.directory)
    if not os.path.isdir(abs_dir) or not _within(os.path.realpath(abs_dir), anchor_real):
        return None
    _scan_directory(discovery, abs_dir, rel_dir, anchor_real, frozenset({os.path.realpath(abs_dir)}), recursive=False,
                    outside_scan_root=True)
    return discovery.directories.get(rel_dir)


def directory_exists(discovery: Discovery, rel_dir: str) -> bool:
    if ids.is_outside(rel_dir):
        return False
    return Path(discovery.anchor.directory, rel_dir).is_dir()
