"""Module source classification and local resolution (proposal §15, §20).

Terraform's own rules decide what a ``source`` string is:

- ``./x`` / ``../x`` - a LOCAL path, resolved lexically relative to the
  *calling* configuration's directory and normalized to anchor-relative.
- ``[host/]namespace/name/provider[//subdir]`` - a REGISTRY address.
- ``git::...``, ``git@host:...``, ``github.com/...``, ``bitbucket.org/...`` - GIT.
- ``http(s)://...`` - HTTP.
- anything else (``s3::``, ``gcs::``, ``hg::``, absolute paths, ...) - OTHER.

Remote sources are recorded, never fetched: their contents stay UNKNOWN.
Credentials are stripped from every stored form (see ``redact.py``).
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from flowlens.repository import ids
from flowlens.repository.enums import ModuleSourceKind
from flowlens.repository.redact import redact_url

_REGISTRY_SEGMENT = r"[0-9A-Za-z](?:[0-9A-Za-z_.\-]*[0-9A-Za-z])?"
_REGISTRY_RE = re.compile(
    rf"^(?:(?P<host>[0-9A-Za-z.\-]+\.[A-Za-z]{{2,}}(?::\d+)?)/)?(?P<ns>{_REGISTRY_SEGMENT})/(?P<name>{_REGISTRY_SEGMENT})"
    rf"/(?P<provider>[0-9a-z]+)(?://(?P<subdir>.+))?$"
)
_GIT_HOSTS = ("github.com/", "bitbucket.org/")
_SCP_GIT_RE = re.compile(r"^[A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+:")


@dataclass(frozen=True)
class SourceSpec:
    """A classified module source. For LOCAL, `locator` is the resolved
    anchor-relative directory; otherwise it is the canonical remote locator."""

    kind: ModuleSourceKind
    locator: str
    raw: str          # redacted, as written
    ref: str | None = None


def is_local(source: str) -> bool:
    """Terraform treats only ``./`` and ``../`` prefixes as local paths."""
    return source.startswith(("./", "../")) or source in (".", "..")


def resolve_local(caller_dir: str, source: str) -> str:
    """Lexical resolution relative to the calling configuration directory.
    The result is anchor-relative; it may start with ``..`` (outside the
    anchor), which callers must treat as unreadable."""
    return ids.normalize_rel_path(posixpath.normpath(posixpath.join(caller_dir, source)))


def _ref(url: str) -> str | None:
    rest = url.split("::", 1)[1] if re.match(r"^[a-z0-9]+::", url) else url
    query = urlsplit(rest).query if "://" in rest else rest.partition("?")[2]
    for k, v in parse_qsl(query, keep_blank_values=True):
        if k == "ref":
            return v
    return None


def classify_source(caller_dir: str, source: str) -> SourceSpec:
    raw = redact_url(source)
    if is_local(source):
        return SourceSpec(ModuleSourceKind.LOCAL, resolve_local(caller_dir, source), raw)
    if source.startswith("git::") or _SCP_GIT_RE.match(source) or source.startswith(_GIT_HOSTS):
        return SourceSpec(ModuleSourceKind.GIT, source, raw, _ref(source))
    if source.startswith(("http://", "https://")):
        return SourceSpec(ModuleSourceKind.HTTP, source, raw, _ref(source))
    if "://" not in source and "::" not in source and _REGISTRY_RE.match(source):
        return SourceSpec(ModuleSourceKind.REGISTRY, source, raw)
    return SourceSpec(ModuleSourceKind.OTHER, source, raw, _ref(source))
