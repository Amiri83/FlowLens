"""Deterministic Terraform ingestion: HCL2 config directories, and the JSON
produced by `terraform show -json` for both state and plan output.

No network access, no `terraform` binary invocation happens here — callers
are expected to have already run `terraform show -json > out.json` (or point
us at a `.tf` config directory / `terraform.tfstate` file) themselves.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import hcl2

from flowlens.ids import make_node_id, make_tf_only_node_id, normalize_terraform_type
from flowlens.models.graph import Edge, Graph, Node, RelationshipType, Source

_REF_PATTERN = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_-]*)")


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


def _find_references(value: Any, address_set: set[str], exclude: str) -> set[str]:
    """Scan a (possibly nested) HCL value for `<type>.<name>` tokens that
    match another known resource address, i.e. a Terraform interpolation
    reference such as "${aws_vpc.main.id}" or "aws_subnet.a.id" in a list.
    """
    found: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, str):
            for match in _REF_PATTERN.finditer(v):
                candidate = f"{match.group(1)}.{match.group(2)}"
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


def parse_config_dir(dir_path: Path, files: list[Path] | None = None) -> Graph:
    """Parse a directory of .tf files into a Graph of desired-state nodes.

    Resource attribute values become `desired_state`. Generic `depends_on`
    edges are derived from interpolation references between resources;
    semantic edges (contains, forwards_to, ...) are added later by
    flowlens.linking.linker.
    """
    graph = Graph()
    tf_files = files if files is not None else sorted(dir_path.glob("*.tf"))

    resources: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for tf_file in tf_files:
        with open(tf_file) as f:
            parsed = hcl2.load(f)
        for resource_block in parsed.get("resource", []):
            for raw_type, named in resource_block.items():
                tf_type = _unquote(raw_type)
                for raw_name, body in named.items():
                    name = _unquote(raw_name)
                    address = f"{tf_type}.{name}"
                    resources[address] = (tf_type, name, _normalize(body))

    id_by_address: dict[str, str] = {}
    for address, (tf_type, name, body) in resources.items():
        node_id = make_tf_only_node_id(address)
        id_by_address[address] = node_id
        graph.add_node(
            Node(
                id=node_id,
                name=_resource_name(body, name),
                resource_type=normalize_terraform_type(tf_type),
                source=Source.TERRAFORM,
                terraform_address=address,
                metadata={"terraform_type": tf_type},
                desired_state=body,
            )
        )

    address_set = set(resources.keys())
    for address, (_tf_type, _name, body) in resources.items():
        refs = _find_references(body, address_set, exclude=address)
        _add_depends_on_edges(graph, id_by_address[address], refs, id_by_address)

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
        normalized = normalize_terraform_type(tf_type)
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
        normalized = normalize_terraform_type(tf_type)
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
