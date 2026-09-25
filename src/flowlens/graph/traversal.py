"""Deterministic path finding over the FlowLens graph.

BFS shortest path (fewest hops) that honors edge direction by default. Ties
are broken deterministically: outgoing edges are always explored in sorted
(neighbor id, semantic-before-depends_on, edge id) order, so the same graph yields the same path on
every run regardless of insertion order.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from flowlens.models.graph import Edge, Graph, RelationshipType


@dataclass(frozen=True)
class PathStep:
    """One hop of a path: traverse `edge` from `from_node` to `to_node`.
    `reversed` is True when an undirected search walked the edge against its
    stored direction.
    """

    from_node: str
    to_node: str
    edge: Edge
    reversed: bool = False


@dataclass
class PathResult:
    nodes: list[str] = field(default_factory=list)
    steps: list[PathStep] = field(default_factory=list)

    @property
    def edge_ids(self) -> list[str]:
        return [s.edge.id for s in self.steps]

    def to_dict(self) -> dict:
        return {
            "found": True,
            "nodes": self.nodes,
            "edges": self.edge_ids,
            "hops": [
                {
                    "from": s.from_node,
                    "to": s.to_node,
                    "edge": s.edge.id,
                    "relationship_type": s.edge.relationship_type.value,
                    "reversed": s.reversed,
                }
                for s in self.steps
            ],
        }


def _adjacency(
    graph: Graph, directed: bool, relationship_types: set[RelationshipType] | None
) -> dict[str, list[tuple[str, str, Edge, bool]]]:
    """node id -> [(neighbor_id, edge_id, edge, reversed)] in deterministic order."""
    adj: dict[str, list[tuple[str, str, Edge, bool]]] = {}
    for edge in graph.edges.values():
        if relationship_types is not None and edge.relationship_type not in relationship_types:
            continue
        if edge.source_node not in graph.nodes or edge.target_node not in graph.nodes:
            continue
        adj.setdefault(edge.source_node, []).append((edge.target_node, edge.id, edge, False))
        if not directed:
            adj.setdefault(edge.target_node, []).append((edge.source_node, edge.id, edge, True))
    for neighbors in adj.values():
        # When several edges join the same pair, prefer a semantic one
        # (forwards_to, integrates_with, ...) over generic depends_on.
        neighbors.sort(key=lambda t: (t[0], t[2].relationship_type == RelationshipType.DEPENDS_ON, t[1]))
    return adj


def shortest_path(
    graph: Graph,
    source: str,
    target: str,
    *,
    directed: bool = True,
    relationship_types: Iterable[RelationshipType | str] | None = None,
    max_depth: int | None = None,
) -> PathResult | None:
    """Return the fewest-hop path from `source` to `target`, or None.

    directed=True follows edges only from source_node to target_node.
    relationship_types restricts which edge types may be traversed.
    max_depth caps the number of hops explored.
    """
    if source not in graph.nodes or target not in graph.nodes:
        return None
    if source == target:
        return PathResult(nodes=[source])

    rel_filter = {RelationshipType(r) for r in relationship_types} if relationship_types is not None else None
    adj = _adjacency(graph, directed, rel_filter)

    # parent[node] = (previous node, step taken to reach node)
    parent: dict[str, tuple[str, PathStep]] = {}
    visited = {source}
    queue: deque[tuple[str, int]] = deque([(source, 0)])
    while queue:
        current, depth = queue.popleft()
        if max_depth is not None and depth >= max_depth:
            continue
        for neighbor, _edge_id, edge, rev in adj.get(current, []):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            parent[neighbor] = (current, PathStep(current, neighbor, edge, rev))
            if neighbor == target:
                return _rebuild(parent, source, target)
            queue.append((neighbor, depth + 1))
    return None


def _rebuild(parent: dict[str, tuple[str, PathStep]], source: str, target: str) -> PathResult:
    steps: list[PathStep] = []
    node = target
    while node != source:
        prev, step = parent[node]
        steps.append(step)
        node = prev
    steps.reverse()
    return PathResult(nodes=[source] + [s.to_node for s in steps], steps=steps)


def resolve_node_ref(graph: Graph, ref: str) -> str | None:
    """Resolve a user-supplied reference to a node id. Accepts, in order:
    an exact node id, a Terraform address, an ARN, a raw cloud id (the part
    after "<type>:"), a node name, or a `name`/`function_name` attribute. Returns None when nothing matches or
    the reference is ambiguous.
    """
    if ref in graph.nodes:
        return ref
    for attr in ("terraform_address", "aws_arn"):
        hits = sorted(n.id for n in graph.nodes.values() if getattr(n, attr) == ref)
        if len(hits) == 1:
            return hits[0]
    by_cloud_id = sorted(n.id for n in graph.nodes.values() if n.id.split(":", 1)[-1] == ref)
    if len(by_cloud_id) == 1:
        return by_cloud_id[0]
    by_name = sorted(n.id for n in graph.nodes.values() if n.name == ref)
    if len(by_name) == 1:
        return by_name[0]
    by_attr = sorted(
        n.id
        for n in graph.nodes.values()
        if any(ref in (s.get("name"), s.get("function_name")) for s in (n.desired_state or {}, n.actual_state or {}))
    )
    if len(by_attr) == 1:
        return by_attr[0]
    return None
