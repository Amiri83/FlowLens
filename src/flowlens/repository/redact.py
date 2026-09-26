"""Minimal redaction utilities for the Repository Intelligence model (ADR 0009).

The RepositoryModel stores *structure, not secrets*: names and keys are kept,
values that may be secret are replaced by :data:`REDACTED`. This is a guard
rail on everything the model persists or prints, not a secret scanner.

- :func:`redact_url`             mask URL userinfo and secret query parameters (display form).
- :func:`canonical_source_url`   drop userinfo and the whole query (identity form, for ids).
- :func:`redact_attribute`       value of an attribute whose *name* looks sensitive -> redacted.
- :func:`guard_value`            obvious secret *shapes* (token prefixes, PEM, JWT,
                                 long high-entropy strings) -> redacted, with a reason.
- :func:`redact_text`            free text (evidence details, diagnostics).
- :func:`sanitize_backend_attributes`  allowlist for backend/cloud block attributes.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "<redacted>"
_USERINFO_MASK = "***"

#: Attribute/parameter names whose values are never kept.
SENSITIVE_NAME_RE = re.compile(r"(?i)(password|passwd|secret|token|key|credential|private|cert|auth|signature|sig$|session)")

#: Query parameters that carry credentials in module-source / download URLs.
_SECRET_QUERY_RE = re.compile(r"(?i)^(access_token|token|sig|signature|password|secret|x-amz-.*|x-goog-.*|sp|se|sv|sr|skoid|sktid)$")

#: Backend/cloud attributes whose values are identity-level and safe to keep.
#: Everything else is recorded by name with a redacted value.
BACKEND_ATTRIBUTE_ALLOWLIST = frozenset(
    {
        "bucket",
        "key",
        "region",
        "encrypt",
        "dynamodb_table",
        "use_lockfile",
        "workspace_key_prefix",
        "organization",
        "container_name",
        "prefix",
    }
)

_TOKEN_PREFIXES: tuple[tuple[str, str], ...] = (
    ("ghp_", "GitHub token prefix"),
    ("gho_", "GitHub token prefix"),
    ("ghs_", "GitHub token prefix"),
    ("ghu_", "GitHub token prefix"),
    ("ghr_", "GitHub token prefix"),
    ("github_pat_", "GitHub token prefix"),
    ("glpat-", "GitLab token prefix"),
    ("xoxb-", "Slack token prefix"),
    ("xoxp-", "Slack token prefix"),
    ("xoxa-", "Slack token prefix"),
    ("xoxs-", "Slack token prefix"),
    ("sk_live_", "Stripe key prefix"),
    ("sk-", "API secret key prefix"),
    ("AIza", "Google API key prefix"),
)
_AWS_ACCESS_KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_HIGH_ENTROPY_CHARSET_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")
_PEM_BLOCK_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|\Z)", re.DOTALL)
_URL_IN_TEXT_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")
_MIN_ENTROPY_LENGTH = 32
_MIN_ENTROPY_BITS = 4.0


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_secret(value: str) -> str | None:
    """Return a reason if `value` has an obvious secret shape, else None.

    Deliberately conservative: Terraform references (``var.x``,
    ``aws_lambda_function.this.arn``), ARNs and paths contain ``.``/``:``/``/``
    patterns that keep them out of the high-entropy rule.
    """
    v = value.strip()
    if not v:
        return None
    if "-----BEGIN " in v:
        return "PEM block"
    if _AWS_ACCESS_KEY_RE.match(v):
        return "AWS access key id shape"
    for prefix, reason in _TOKEN_PREFIXES:
        if v.startswith(prefix) and len(v) >= len(prefix) + 16:
            return reason
    if _JWT_RE.match(v):
        return "JWT shape"
    if (
        len(v) >= _MIN_ENTROPY_LENGTH
        and _HIGH_ENTROPY_CHARSET_RE.match(v)
        and any(c.isdigit() for c in v)
        and any(c.isupper() for c in v)
        and any(c.islower() for c in v)
        and _shannon_entropy(v) >= _MIN_ENTROPY_BITS
    ):
        return "long high-entropy string"
    return None


def guard_value(value: Any) -> tuple[Any, str | None]:
    """Replace a scalar that looks like a secret. Returns (safe_value, reason)."""
    if isinstance(value, str):
        reason = looks_secret(value)
        if reason:
            return REDACTED, reason
    return value, None


def redact_attribute(name: str, value: Any) -> tuple[Any, str | None]:
    """Keep the attribute *name*; drop the value if the name or value looks sensitive."""
    if SENSITIVE_NAME_RE.search(name):
        return REDACTED, "sensitive attribute name"
    return guard_value(value)


def _split_forced_getter(source: str) -> tuple[str, str]:
    # Terraform module sources may force a getter: "git::https://...", "s3::https://...".
    m = re.match(r"^([a-z0-9]+)::(.*)$", source)
    return (m.group(1) + "::", m.group(2)) if m else ("", source)


def _has_scheme(url: str) -> bool:
    return "://" in url


def redact_url(url: str) -> str:
    """Display form: ``https://user:tok@host/x?access_token=t&ref=v1`` ->
    ``https://***@host/x?access_token=***&ref=v1``. Non-URLs pass through."""
    prefix, rest = _split_forced_getter(url)
    if not _has_scheme(rest):
        return url
    parts = urlsplit(rest)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"{_USERINFO_MASK}@{netloc.rsplit('@', 1)[1]}"
    query = parts.query
    if query:
        pairs = [
            (k, _USERINFO_MASK if _SECRET_QUERY_RE.match(k) or SENSITIVE_NAME_RE.search(k) else v)
            for k, v in parse_qsl(query, keep_blank_values=True)
        ]
        query = urlencode(pairs, safe="*/:")
    return prefix + urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def canonical_source_url(url: str) -> str:
    """Identity form used inside ids: userinfo and the entire query string are
    removed (``?ref=`` is recorded as an attribute, not as identity)."""
    prefix, rest = _split_forced_getter(url)
    if not _has_scheme(rest):
        return url.split("?", 1)[0]
    parts = urlsplit(rest)
    host = parts.netloc.rsplit("@", 1)[-1]
    return prefix + urlunsplit((parts.scheme, host, parts.path, "", ""))


def redact_text(text: str) -> str:
    """Redact free text: PEM blocks, URL credentials, and secret-shaped tokens."""
    if not text:
        return text
    out = _PEM_BLOCK_RE.sub(REDACTED, text)
    out = _URL_IN_TEXT_RE.sub(lambda m: redact_url(m.group(0)), out)
    words = re.split(r"(\s+)", out)
    for i, word in enumerate(words):
        core = word.strip("\"'`,;()[]{}")
        # key=value / key: value shapes: judge the value part, and the key name.
        for sep in ("=", ":"):
            if sep in core and "://" not in core:
                k, v = core.split(sep, 1)
                if v and (SENSITIVE_NAME_RE.search(k) or looks_secret(v)):
                    words[i] = word.replace(v, REDACTED)
                    break
        else:
            if core and looks_secret(core):
                words[i] = word.replace(core, REDACTED)
    return "".join(words)


def sanitize_backend_attributes(attributes: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Backend/cloud attribute names are always kept; values are kept only for
    allowlisted, scalar, non-secret-looking attributes. Sorted by name."""
    out: list[tuple[str, str]] = []
    for name in sorted(attributes):
        value = attributes[name]
        if name in BACKEND_ATTRIBUTE_ALLOWLIST and isinstance(value, str | bool | int):
            text = str(value).lower() if isinstance(value, bool) else str(value)
            out.append((name, guard_value(text)[0]))
        else:
            out.append((name, REDACTED))
    return tuple(out)
