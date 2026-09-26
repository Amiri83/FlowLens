"""Stage 2 of reconnaissance: structural HCL parsing into observed facts (proposal §7).

Parses ``.tf`` (python-hcl2) and ``.tf.json`` just far enough to see the
*structure* of a file: which top-level blocks exist, their labels and line
ranges, and which meta-arguments are present. Expressions are never
evaluated; they are kept as written (redacted) or reduced to "literal or not".

Parsers emit :class:`ObservedFact` records only. Nothing here decides that a
directory is a root, a module, an environment or an application.
"""
from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import hcl2
from hcl2.rules.base import BlockRule

from flowlens.repository.enums import FactKind
from flowlens.repository.evidence import Locator, ObservedFact
from flowlens.repository.redact import redact_text, redact_url

#: Top-level block kinds modeled (provider-neutral), with their label count.
BLOCK_LABELS: Mapping[str, int] = {
    "terraform": 0,
    "provider": 1,
    "variable": 1,
    "locals": 0,
    "module": 1,
    "resource": 2,
    "data": 2,
    "output": 1,
    "moved": 0,
    "import": 0,
    "check": 1,
    "removed": 0,
}

#: Provider-block attributes that do not constitute provider *configuration*.
_PROVIDER_NON_CONFIG = frozenset({"alias", "version"})

#: Module-block arguments that are Terraform meta-arguments, not module inputs.
MODULE_META_ARGS = frozenset({"source", "version", "count", "for_each", "depends_on", "providers", "lifecycle"})

_MAX_EXPR = 200


def _unquote(s: str) -> str:
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _clean(value: Any) -> Any:
    """Drop python-hcl2's ``__is_block__`` sentinels (quotes are kept so that
    literals stay distinguishable from expressions)."""
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if k != "__is_block__"}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def is_literal(value: Any) -> bool:
    """True for a value that needs no evaluation: numbers, booleans, null,
    quoted strings without interpolation, and collections of those."""
    if value is None or isinstance(value, bool | int | float):
        return True
    if isinstance(value, str):
        return value.startswith('"') and value.endswith('"') and "${" not in value and "%{" not in value
    if isinstance(value, list):
        return all(is_literal(v) for v in value)
    if isinstance(value, dict):
        return all(is_literal(v) for v in value.values())
    return False


def expression_text(value: Any) -> str:
    """The expression as written (never evaluated), redacted and bounded."""
    if isinstance(value, str):
        text = value[2:-1] if value.startswith("${") and value.endswith("}") and value.count("${") == 1 else value
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif value is None:
        text = "null"
    else:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    text = redact_text(" ".join(text.split()))
    return text if len(text) <= _MAX_EXPR else text[: _MAX_EXPR - 3] + "..."


def literal_string(value: Any) -> str | None:
    """The string value if `value` is a quoted literal string, else None."""
    if isinstance(value, str) and is_literal(value):
        return _unquote(value)
    return None


# --------------------------------------------------------------------------- parsed structure


@dataclass(frozen=True)
class HclBlock:
    """One top-level block as written. `body` is transient (never stored in
    the model); only facts derived from it are."""

    kind: str
    labels: tuple[str, ...]
    body: Mapping[str, Any] = field(repr=False)
    line_start: int | None = None
    line_end: int | None = None

    def locator(self) -> Locator:
        return Locator(self.kind, self.labels, self.line_start, self.line_end)

    def nested(self, name: str) -> list[Any]:
        """Nested blocks named `name` (python-hcl2 keeps them as a list)."""
        value = self.body.get(name)
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        if isinstance(value, dict):
            return [value]
        return []


@dataclass(frozen=True)
class ParsedFile:
    blocks: tuple[HclBlock, ...] = ()
    error: str | None = None
    error_line: int | None = None
    unsupported: tuple[str, ...] = ()   # top-level constructs that are not modeled blocks

    @property
    def ok(self) -> bool:
        return self.error is None


def _error(exc: Exception) -> ParsedFile:
    message = redact_text(" ".join(str(exc).split())[:300]) or type(exc).__name__
    return ParsedFile(error=f"{type(exc).__name__}: {message}", error_line=getattr(exc, "line", None))


def _parse_hcl(text: str) -> ParsedFile:
    try:
        start = hcl2.parses(text, discard_comments=True)
        body = start.children[0]
        blocks: list[HclBlock] = []
        unsupported: list[str] = []
        for child in body.children:
            if not isinstance(child, BlockRule):
                name = type(child).__name__
                if name not in ("NewLineOrCommentRule",):
                    unsupported.append(f"top-level {name.removesuffix('Rule').lower()}")
                continue
            names = [_unquote(str(label.serialize())) for label in child.labels]
            meta = getattr(child, "_meta", None)
            line_start = getattr(meta, "line", None)
            line_end = getattr(meta, "end_line", None)
            blocks.append(HclBlock(names[0], tuple(names[1:]), _clean(child.body.serialize()), line_start, line_end))
    except Exception as exc:  # any parser failure must only skip this file
        return _error(exc)
    return ParsedFile(tuple(blocks), unsupported=tuple(unsupported))


def _json_blocks(kind: str, value: Any, n_labels: int, labels: tuple[str, ...] = ()) -> Iterator[HclBlock]:
    """Terraform JSON syntax: labels are nested object keys; any level may be
    an array of objects."""
    if isinstance(value, list):
        for item in value:
            yield from _json_blocks(kind, item, n_labels, labels)
        return
    if not isinstance(value, dict):
        return
    if n_labels == 0:
        yield HclBlock(kind, labels, _json_body(value))
        return
    for key in value:
        yield from _json_blocks(kind, value[key], n_labels - 1, (*labels, key))


def _json_body(value: Any) -> Any:
    """Map JSON values into the python-hcl2 shape used downstream: strings are
    quoted literals unless they interpolate."""
    if isinstance(value, str):
        return value if "${" in value else f'"{value}"'
    if isinstance(value, dict):
        return {k: _json_body(v) for k, v in value.items() if not k.startswith("//")}
    if isinstance(value, list):
        return [_json_body(v) for v in value]
    return value


def _parse_json(text: str) -> ParsedFile:
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("top level of a .tf.json file must be an object")
        blocks: list[HclBlock] = []
        unsupported: list[str] = []
        for kind in data:
            if kind.startswith("//"):
                continue
            if kind not in BLOCK_LABELS:
                unsupported.append(f"block {kind}")
                continue
            blocks.extend(_json_blocks(kind, data[kind], BLOCK_LABELS[kind]))
    except Exception as exc:
        return _error(exc)
    return ParsedFile(tuple(blocks), unsupported=tuple(unsupported))


def parse_terraform(text: str, *, json_syntax: bool) -> ParsedFile:
    """Parse one configuration file. Never raises: failures come back as
    ``ParsedFile(error=...)`` so the caller skips only this file."""
    return _parse_json(text) if json_syntax else _parse_hcl(text)


def var_file_names(text: str, *, json_syntax: bool) -> tuple[str, ...]:
    """Variable NAMES assigned by a tfvars file. Values are parsed by the
    library but discarded immediately; they never reach the model. Raises on
    a parse failure."""
    data = json.loads(text) if json_syntax else hcl2.loads(text)
    if not isinstance(data, dict):
        raise ValueError("variable file is not an object")
    return tuple(sorted(k for k in data if not k.startswith("//")))


# --------------------------------------------------------------------------- facts


def _meta_facts(artifact: str, block: HclBlock, loc: Locator) -> list[ObservedFact]:
    out = []
    for arg in ("count", "for_each"):
        if arg in block.body:
            value = block.body[arg]
            out.append(ObservedFact(artifact, loc, FactKind.META_ARG_PRESENT,
                                    {"arg": arg, "expr": expression_text(value), "literal": is_literal(value)}))
    if "depends_on" in block.body:
        out.append(ObservedFact(artifact, loc, FactKind.META_ARG_PRESENT, {"arg": "depends_on"}))
    if "lifecycle" in block.body:
        out.append(ObservedFact(artifact, loc, FactKind.META_ARG_PRESENT, {"arg": "lifecycle"}))
    if "provider" in block.body and block.kind in ("resource", "data"):
        # a provider *pin* (`provider = aws.us`), not a provider configuration
        out.append(ObservedFact(artifact, loc, FactKind.META_ARG_PRESENT,
                                {"arg": "provider", "expr": expression_text(block.body["provider"])}))
    if "providers" in block.body and block.kind == "module":
        out.append(ObservedFact(artifact, loc, FactKind.META_ARG_PRESENT, {"arg": "providers"}))
    for dyn in dynamic_blocks(block):
        name, body = dyn
        payload: dict[str, Any] = {"arg": "dynamic", "block": name}
        if "for_each" in body:
            payload["expr"] = expression_text(body["for_each"])
        out.append(ObservedFact(artifact, loc, FactKind.META_ARG_PRESENT, payload))
    return out


def dynamic_blocks(block: HclBlock) -> list[tuple[str, Mapping[str, Any]]]:
    """(name, body) of ``dynamic "name" {}`` sub-blocks, at any depth."""
    found: list[tuple[str, Mapping[str, Any]]] = []

    def walk(body: Any) -> None:
        if isinstance(body, list):
            for item in body:
                walk(item)
        elif isinstance(body, dict):
            for key, value in body.items():
                if key == "dynamic":
                    for dyn in value if isinstance(value, list) else [value]:
                        if isinstance(dyn, dict):
                            for name, inner in dyn.items():
                                found.append((_unquote(name), inner if isinstance(inner, dict) else {}))
                                walk(inner)
                elif isinstance(value, dict | list):
                    walk(value)

    walk(dict(block.body))
    return sorted(found, key=lambda x: x[0])


def provider_is_configured(block: HclBlock) -> bool:
    return any(k not in _PROVIDER_NON_CONFIG for k in block.body)


def block_facts(artifact: str, block: HclBlock) -> list[ObservedFact]:
    """All observed facts for one top-level block. Pure: same block, same facts."""
    loc = block.locator()
    b = block.body
    facts = [ObservedFact(artifact, loc, FactKind.BLOCK_PRESENT)]
    kind = block.kind
    if kind == "terraform":
        for backend in block.nested("backend"):
            for btype, bbody in backend.items():
                attrs = sorted(bbody) if isinstance(bbody, dict) else []
                facts.append(ObservedFact(artifact, Locator("terraform", ("backend", _unquote(btype)), loc.line_start, loc.line_end),
                                          FactKind.BACKEND_BLOCK,
                                          {"backend_type": _unquote(btype), "attribute_names": ",".join(attrs)}))
        for cloud in block.nested("cloud"):
            facts.append(ObservedFact(artifact, Locator("terraform", ("cloud",), loc.line_start, loc.line_end), FactKind.CLOUD_BLOCK,
                                      {"attribute_names": ",".join(sorted(k for k in cloud))}))
        for req in block.nested("required_providers"):
            facts.append(ObservedFact(artifact, Locator("terraform", ("required_providers",), loc.line_start, loc.line_end),
                                      FactKind.BLOCK_PRESENT, {"providers": ",".join(sorted(req))}))
    elif kind == "provider":
        alias = (literal_string(b["alias"]) or expression_text(b["alias"])) if "alias" in b else None
        facts.append(ObservedFact(artifact, loc, FactKind.PROVIDER_CONFIG, {
            "provider": block.labels[0] if block.labels else "",
            "alias": alias,
            "configured": provider_is_configured(block),
            "attribute_names": ",".join(sorted(k for k in b if k not in _PROVIDER_NON_CONFIG)),
        }))
    elif kind == "variable":
        facts.append(ObservedFact(artifact, loc, FactKind.VARIABLE_DECLARED, {
            "name": block.labels[0] if block.labels else "",
            "has_default": "default" in b,
            "type": expression_text(b["type"]) if "type" in b else None,
            "sensitive": b.get("sensitive") is True,
        }))
    elif kind == "output":
        facts.append(ObservedFact(artifact, loc, FactKind.OUTPUT_DECLARED,
                                  {"name": block.labels[0] if block.labels else "", "sensitive": b.get("sensitive") is True}))
    elif kind == "locals":
        facts.append(ObservedFact(artifact, loc, FactKind.LOCALS_DECLARED, {"names": ",".join(sorted(b))}))
    elif kind == "module":
        source = b.get("source")
        literal = literal_string(source)
        payload: dict[str, Any] = {
            "source": redact_url(literal) if literal is not None else expression_text(source) if source is not None else None,
            "literal": literal is not None,
        }
        if "version" in b:
            payload["version"] = literal_string(b["version"]) or expression_text(b["version"])
        facts.append(ObservedFact(artifact, loc, FactKind.MODULE_SOURCE_LITERAL, payload))
        facts.extend(_meta_facts(artifact, block, loc))
    elif kind in ("resource", "data"):
        facts.extend(_meta_facts(artifact, block, loc))
    elif kind == "moved":
        facts.append(ObservedFact(artifact, loc, FactKind.MOVED_BLOCK,
                                  {"from": expression_text(b.get("from")), "to": expression_text(b.get("to"))}))
    elif kind == "import":
        id_value = b.get("id")
        facts.append(ObservedFact(artifact, loc, FactKind.IMPORT_BLOCK, {
            "to": expression_text(b.get("to")),
            "id_literal": literal_string(id_value),
        }))
    elif kind == "check":
        facts.append(ObservedFact(artifact, loc, FactKind.CHECK_BLOCK, {"name": block.labels[0] if block.labels else ""}))
    elif kind == "removed":
        facts.append(ObservedFact(artifact, loc, FactKind.REMOVED_BLOCK, {"from": expression_text(b.get("from"))}))
    return facts


def parse_error_fact(artifact: str, parsed: ParsedFile) -> ObservedFact:
    return ObservedFact(artifact, Locator(line_start=parsed.error_line), FactKind.PARSE_ERROR, {"error": parsed.error})
