"""Deterministic Terraform ingestion: HCL2 config directories, and the JSON
produced by `terraform show -json` for both state and plan output.

No network access, no `terraform` binary invocation happens here — callers
are expected to have already run `terraform show -json > out.json` (or point
us at a `.tf` config directory / `terraform.tfstate` file) themselves.
"""
from __future__ import annotations

import json
import logging
import os
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2

from flowlens.ids import make_node_id, make_tf_only_node_id, normalize_terraform_type
from flowlens.models.graph import Edge, Graph, Node, RelationshipType, Source

logger = logging.getLogger(__name__)

#: A Terraform reference: `data.<type>.<name>`, `module.<name>` or
#: `<type>.<name>`. The special prefixes are tried first so e.g.
#: "data.aws_ami.ubuntu.id" yields "data.aws_ami.ubuntu" rather than
#: "data.aws_ami". The lookbehind stops matches mid-way through an attribute
#: chain (e.g. the "network.vpc_id" in "module.network.vpc_id").
_REF_PATTERN = re.compile(
    r"(?<![\w.])(data\.[a-zA-Z_][a-zA-Z0-9_-]*\.[a-zA-Z_][a-zA-Z0-9_-]*"
    r"|module\.[a-zA-Z_][a-zA-Z0-9_-]*"
    r"|[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_-]*)"
)

#: Directories never scanned for .tf files: Terraform/Terragrunt caches
#: (downloaded module/provider copies, not the user's config) and VCS/tooling
#: dirs.
_SKIP_DIRS = frozenset({".terraform", ".terragrunt-cache", ".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__"})


def _unquote(s: str) -> str:
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _normalize(value: Any) -> Any:
    """python-hcl2 (>=8) preserves literal quoting around plain string
    values (e.g. '"10.0.0.0/16"') and marks nested blocks with a
    `__is_block__` sentinel key. Strip both so desired_state holds plain
    Python values comparable to AWS actual_state and terraform show -json.
    """
    if isinstance(value, str):
        return _unquote(value)
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items() if k != "__is_block__"}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def ingest_path(path: str | Path) -> Graph:
    """Ingest a Terraform config directory, a single .tf file, a
    terraform.tfstate file, or `terraform show -json` output (state or plan).
    """
    p = Path(path)
    if p.is_dir():
        return parse_config_dir(p)
    if p.suffix == ".tf":
        return parse_config_dir(p.parent, files=[p])
    if p.suffix in (".json", ".tfstate"):
        data = json.loads(p.read_text())
        if "resource_changes" in data:
            return parse_plan_json(data)
        if _is_raw_tfstate(data):
            return parse_state_json(raw_tfstate_to_show_json(data))
        if "values" in data or "resources" in data or "root_module" in data:
            return parse_state_json(data)
        raise ValueError(f"Unrecognized terraform JSON structure in {path}")
    raise ValueError(f"Unsupported terraform input: {path}")


def _resource_name(body: dict[str, Any], fallback: str) -> str:
    tags = body.get("tags")
    if isinstance(tags, dict) and tags.get("Name"):
        return str(tags["Name"])
    return fallback


def _find_references(value: Any, address_set: set[str], exclude: str, scope: str = "") -> set[str]:
    """Scan a (possibly nested) HCL value for `<type>.<name>` tokens that
    match another known resource address, i.e. a Terraform interpolation
    reference such as "${aws_vpc.main.id}" or "aws_subnet.a.id" in a list.

    `scope` is the module path the value was written in ("" for the root,
    else e.g. "module.api."): Terraform references are relative to their
    own module, so "aws_vpc.main" inside module.api means
    "module.api.aws_vpc.main" and never a same-named resource elsewhere.
    """
    found: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, str):
            for match in _REF_PATTERN.finditer(v):
                candidate = scope + match.group(1)
                if candidate in address_set and candidate != exclude:
                    found.add(candidate)
        elif isinstance(v, dict):
            for vv in v.values():
                walk(vv)
        elif isinstance(v, list):
            for vv in v:
                walk(vv)

    walk(value)
    return found


def _add_depends_on_edges(graph: Graph, src_id: str, refs: Iterable[str], id_by_address: dict[str, str]) -> None:
    for ref_address in refs:
        dst_id = id_by_address.get(ref_address)
        if dst_id is None or dst_id == src_id:
            continue
        edge_id = f"{src_id}->{dst_id}:depends_on"
        graph.add_edge(
            Edge(
                id=edge_id,
                source_node=src_id,
                target_node=dst_id,
                relationship_type=RelationshipType.DEPENDS_ON,
                source=Source.TERRAFORM,
            )
        )


def discover_tf_files(dir_path: Path) -> list[Path]:
    """Recursively find `.tf` files under `dir_path`, in a deterministic
    (sorted) order, skipping Terraform/Terragrunt caches and VCS dirs.
    """
    found: list[Path] = []
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        found.extend(Path(root) / f for f in files if f.endswith(".tf"))
    return sorted(found)


#: (mode, terraform type or None for modules, name, normalized body, source file)
_Block = tuple[str, str | None, str, dict[str, Any], str]


def _blocks_in(parsed: dict[str, Any], rel_file: str) -> Iterable[tuple[str, _Block]]:
    """Yield (address, block) for every resource, data and module block."""
    for mode, prefix in (("managed", ""), ("data", "data.")):
        for block in parsed.get("resource" if mode == "managed" else "data", []):
            for raw_type, named in block.items():
                tf_type = _unquote(raw_type)
                for raw_name, body in named.items():
                    name = _unquote(raw_name)
                    yield f"{prefix}{tf_type}.{name}", (mode, tf_type, name, _normalize(body), rel_file)
    for block in parsed.get("module", []):
        for raw_name, body in block.items():
            name = _unquote(raw_name)
            yield f"module.{name}", ("module", None, name, _normalize(body), rel_file)


#: Backstop nesting limit for local module calls. Genuine cycles are cut as
#: soon as a directory repeats on the current call path; this only bounds
#: pathological (acyclic but absurdly deep) trees.
_MAX_MODULE_DEPTH = 32

#: Meta-arguments that make Terraform expand one block into many instances.
_EXPANSION_ARGS = ("count", "for_each")


@dataclass(frozen=True)
class _ConfigBlock:
    mode: str
    tf_type: str | None  # None for module calls
    name: str
    body: dict[str, Any]
    file: str
    #: Module-instance path the block lives in: "" for a root module, else
    #: e.g. "module.app.module.worker." (always ends with ".").
    scope: str
    #: (address, "count" | "for_each") for the block itself and every
    #: enclosing module call that is expanded at apply time.
    expanded_by: tuple[tuple[str, str], ...]


def _local_module_dir(caller_dir: str, source: Any) -> str | None:
    """Scan-relative directory of a local module source ("./x", "../x"),
    or None for sources we cannot read (registry, git, http, ...).
    """
    if not isinstance(source, str) or not source.startswith(("./", "../")):
        return None
    return posixpath.normpath(posixpath.join(caller_dir, source))


def parse_config_dir(dir_path: Path, files: list[Path] | None = None) -> Graph:
    """Parse a directory tree of .tf files into a Graph of desired-state nodes.

    `.tf` files are discovered recursively (see discover_tf_files) and
    grouped by directory, a directory being a Terraform module. Directories
    no local `module` block points at are root modules; their `resource`,
    `data` and `module` blocks are addressed as in Terraform (`aws_vpc.main`,
    `data.aws_ami.x`, `module.network`).

    Local module calls (`source = "./..."` / `"../..."`) are followed, and
    the called directory's blocks are addressed per module *instance*, as
    Terraform does: `module "a"` and `module "b"` with the same source yield
    `module.a.aws_lambda_function.this` and `module.b.aws_lambda_function.this`.
    Nesting is kept (`module.app.module.worker.<type>.<name>`); a module
    cycle is cut with a warning. Identity never depends on where the source
    directory lives. Registry/git sources are not fetched: the module call
    stays a node of its own.

    `count` / `for_each` are not evaluated: a counted resource or a resource
    inside a counted module yields one template node (metadata
    `terraform_template`, `terraform_expansion`); concrete instance keys only
    come from state/plan.

    Resource attribute values become `desired_state`. Generic `depends_on`
    edges are derived from interpolation references (and explicit
    `depends_on` lists) between blocks of the same module instance;
    semantic edges (contains, forwards_to, ...) are added later by
    flowlens.linking.linker.

    A file that fails to parse is skipped and reported in
    `graph.metadata["terraform_scan"]["warnings"]` rather than aborting, as
    is a genuinely duplicated address (the first definition is kept).
    """
    graph = Graph()
    warnings: list[str] = []
    files_scanned = 0

    def rel(path: Path) -> str:
        return Path(os.path.relpath(path, dir_path)).as_posix()

    def parse(tf_file: Path, rel_file: str) -> dict[str, Any] | None:
        nonlocal files_scanned
        files_scanned += 1
        try:
            with open(tf_file) as f:
                return hcl2.load(f)
        except Exception as exc:  # any parser failure must only skip this file
            message = " ".join(str(exc).split()) or type(exc).__name__
            warnings.append(f"{rel_file}: failed to parse, skipped ({type(exc).__name__}: {message})")
            logger.info("Skipping unparseable Terraform file %s: %s", tf_file, message)
            return None

    #: scan-relative module directory -> [(scan-relative file, parsed HCL)]
    modules: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for tf_file in files if files is not None else discover_tf_files(dir_path):
        rel_file = rel(tf_file)
        entries = modules.setdefault(posixpath.dirname(rel_file) or ".", [])
        parsed = parse(tf_file, rel_file)
        if parsed is not None:
            entries.append((rel_file, parsed))

    def load(module_dir: str) -> list[tuple[str, dict[str, Any]]]:
        """Parsed files of a module directory, reading it on first use when
        discovery did not cover it (e.g. `../modules/x` outside the scan).
        """
        if module_dir not in modules:
            entries = modules[module_dir] = []
            directory = dir_path / module_dir
            for tf_file in sorted(directory.glob("*.tf")) if directory.is_dir() else []:
                rel_file = posixpath.normpath(posixpath.join(module_dir, tf_file.name))
                parsed = parse(tf_file, rel_file)
                if parsed is not None:
                    entries.append((rel_file, parsed))
        return modules[module_dir]

    blocks: dict[str, _ConfigBlock] = {}
    instantiated: set[str] = set()

    def instantiate(module_dir: str, scope: str, call_path: tuple[str, ...], expanded_by: tuple[tuple[str, str], ...]) -> None:
        instantiated.add(module_dir)
        calls: list[_ConfigBlock] = []
        for rel_file, parsed in load(module_dir):
            for local_address, (mode, tf_type, name, body, _file) in _blocks_in(parsed, rel_file):
                address = scope + local_address
                if address in blocks:
                    warnings.append(f"{rel_file}: duplicate address {address} (already defined in {blocks[address].file}); kept the first")
                    continue
                own = tuple((address, arg) for arg in _EXPANSION_ARGS if arg in body)
                block = _ConfigBlock(mode, tf_type, name, body, rel_file, scope, expanded_by + own)
                blocks[address] = block
                if mode == "module":
                    calls.append(block)
        for call in calls:
            address = call.scope + f"module.{call.name}"
            source = call.body.get("source")
            child_dir = _local_module_dir(module_dir, source)
            if child_dir is None:
                continue
            if child_dir in call_path:
                warnings.append(f"{call.file}: {address} source {source!r} forms a module cycle; not followed")
            elif len(call_path) > _MAX_MODULE_DEPTH:
                warnings.append(f"{call.file}: {address} exceeds module nesting depth {_MAX_MODULE_DEPTH}; not followed")
            elif not load(child_dir):
                warnings.append(f"{call.file}: {address} source {source!r} has no readable .tf files; its resources were not scanned")
            else:
                instantiate(child_dir, address + ".", call_path + (child_dir,), call.expanded_by)

    discovered = sorted(modules)
    called = {
        child_dir
        for module_dir in discovered
        for rel_file, parsed in modules[module_dir]
        for _address, (mode, _t, _n, body, _f) in _blocks_in(parsed, rel_file)
        if mode == "module" and (child_dir := _local_module_dir(module_dir, body.get("source"))) is not None
    }
    for module_dir in discovered:
        if module_dir not in called:
            instantiate(module_dir, "", (module_dir,), ())
    # Directories only reachable through a module cycle (or from nowhere
    # but themselves) still get scanned, as roots.
    for module_dir in discovered:
        if module_dir not in instantiated:
            instantiate(module_dir, "", (module_dir,), ())

    id_by_address: dict[str, str] = {}
    for address, block in blocks.items():
        node_id = make_tf_only_node_id(address)
        id_by_address[address] = node_id
        metadata: dict[str, Any] = {"terraform_mode": block.mode, "terraform_file": block.file}
        if block.tf_type is not None:
            metadata["terraform_type"] = block.tf_type
        elif isinstance(block.body.get("source"), str):
            metadata["module_source"] = block.body["source"]
        if block.scope:
            metadata["terraform_module"] = block.scope[:-1]
        if block.expanded_by:
            # A template for instances whose keys only state/plan know.
            metadata["terraform_template"] = True
            metadata["terraform_expansion"] = [{"address": a, "meta_argument": arg} for a, arg in block.expanded_by]
        graph.add_node(
            Node(
                id=node_id,
                name=_resource_name(block.body, block.name),
                resource_type=normalize_terraform_type(block.tf_type, block.body) if block.tf_type is not None else "module",
                source=Source.TERRAFORM,
                terraform_address=address,
                metadata=metadata,
                desired_state=block.body,
            )
        )

    address_set = set(blocks)
    for address, block in blocks.items():
        refs = _find_references(block.body, address_set, exclude=address, scope=block.scope)
        _add_depends_on_edges(graph, id_by_address[address], refs, id_by_address)

    graph.metadata["terraform_scan"] = {"files_scanned": files_scanned, "warnings": warnings}
    return graph


def _walk_state_module(module: dict[str, Any], out: list[dict[str, Any]]) -> None:
    out.extend(module.get("resources", []))
    for child in module.get("child_modules", []):
        _walk_state_module(child, out)


def parse_state_json(data: dict[str, Any]) -> Graph:
    """Parse `terraform show -json` state output (or a raw terraform.tfstate
    with a `values.root_module` shape) into a Graph of desired-state nodes.

    When a resource's applied attributes include a real cloud id (`values.id`),
    the node id is built from it so this graph can merge with AWS-discovered
    nodes for the same resource.
    """
    graph = Graph()
    root = data.get("values", {}).get("root_module") if "values" in data else data.get("root_module", {})
    root = root or {}

    resources: list[dict[str, Any]] = []
    _walk_state_module(root, resources)

    id_by_address: dict[str, str] = {}
    for r in resources:
        if r.get("mode") != "managed":
            continue
        tf_type, name, address = r["type"], r["name"], r["address"]
        values = r.get("values") or {}
        normalized = normalize_terraform_type(tf_type, values)
        cloud_id = values.get("id")
        node_id = make_node_id(normalized, cloud_id) if cloud_id else make_tf_only_node_id(address)
        id_by_address[address] = node_id
        graph.add_node(
            Node(
                id=node_id,
                name=_resource_name(values, name),
                resource_type=normalized,
                source=Source.TERRAFORM,
                terraform_address=address,
                aws_arn=values.get("arn"),
                metadata={"terraform_type": tf_type},
                desired_state=values,
            )
        )

    address_set = set(id_by_address.keys())
    for r in resources:
        if r.get("mode") != "managed":
            continue
        address = r["address"]
        values = r.get("values") or {}
        refs = _find_references(values, address_set, exclude=address)
        for dep in r.get("depends_on", []) or []:
            if dep in address_set:
                refs.add(dep)
        _add_depends_on_edges(graph, id_by_address[address], refs, id_by_address)

    return graph


def parse_plan_json(data: dict[str, Any]) -> Graph:
    """Parse `terraform show -json` plan output into a Graph of desired-state
    nodes, using each resource change's `after` values (the planned state).
    """
    graph = Graph()
    changes = data.get("resource_changes", [])

    id_by_address: dict[str, str] = {}
    for c in changes:
        if c.get("mode") != "managed":
            continue
        tf_type, name, address = c["type"], c["name"], c["address"]
        after = (c.get("change") or {}).get("after") or {}
        normalized = normalize_terraform_type(tf_type, after)
        cloud_id = after.get("id")
        node_id = make_node_id(normalized, cloud_id) if cloud_id else make_tf_only_node_id(address)
        id_by_address[address] = node_id
        graph.add_node(
            Node(
                id=node_id,
                name=_resource_name(after, name),
                resource_type=normalized,
                source=Source.TERRAFORM,
                terraform_address=address,
                aws_arn=after.get("arn"),
                metadata={"terraform_type": tf_type, "change_actions": c.get("change", {}).get("actions", [])},
                desired_state=after,
            )
        )

    address_set = set(id_by_address.keys())
    for c in changes:
        if c.get("mode") != "managed":
            continue
        address = c["address"]
        after = (c.get("change") or {}).get("after") or {}
        refs = _find_references(after, address_set, exclude=address)
        _add_depends_on_edges(graph, id_by_address[address], refs, id_by_address)

    return graph


def _is_raw_tfstate(data: dict[str, Any]) -> bool:
    """A raw terraform.tfstate (format v4) has top-level `resources` whose
    entries carry `instances`, unlike `terraform show -json` output.
    """
    resources = data.get("resources")
    return isinstance(resources, list) and any(isinstance(r, dict) and "instances" in r for r in resources)


def raw_tfstate_to_show_json(data: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw terraform.tfstate into the `terraform show -json` shape
    parse_state_json understands (flattened into the root module; module
    paths are kept in each resource address).
    """
    resources = []
    for r in data.get("resources", []):
        prefix = f"{r['module']}." if r.get("module") else ""
        base = f"{prefix}{'data.' if r.get('mode') == 'data' else ''}{r['type']}.{r['name']}"
        for inst in r.get("instances", []):
            key = inst.get("index_key")
            suffix = "" if key is None else (f"[{key}]" if isinstance(key, int) else f'["{key}"]')
            resources.append(
                {
                    "address": base + suffix,
                    "mode": r.get("mode", "managed"),
                    "type": r["type"],
                    "name": r["name"],
                    "values": inst.get("attributes") or {},
                    "depends_on": inst.get("dependencies", []),
                }
            )
    return {"values": {"root_module": {"resources": resources}}}


def combine_config_and_state(config: Graph, state: Graph) -> Graph:
    """Merge a config-only graph with a state graph of the same stack.

    A config node (id "tf:<address>") whose address also appears in state is
    replaced by the state node (which carries the real cloud id and so can
    merge with AWS-discovered nodes); edges are re-pointed accordingly.
    Config-only resources (not applied yet) are kept as-is.
    """
    state_id_by_address = {n.terraform_address: n.id for n in state.nodes.values() if n.terraform_address}
    remap: dict[str, str] = {}
    result = Graph(metadata={**config.metadata, **state.metadata})
    for node in state.nodes.values():
        result.add_node(node)
    for node in config.nodes.values():
        state_id = state_id_by_address.get(node.terraform_address or "")
        if state_id is not None:
            remap[node.id] = state_id
        else:
            result.add_node(node)
    for edge in list(state.edges.values()) + list(config.edges.values()):
        src = remap.get(edge.source_node, edge.source_node)
        dst = remap.get(edge.target_node, edge.target_node)
        if src == dst:
            continue
        rel = edge.relationship_type.value
        result.add_edge(edge.model_copy(update={"id": f"{src}->{dst}:{rel}", "source_node": src, "target_node": dst}))
    return result
