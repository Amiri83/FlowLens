"""Correlate Terraform (desired) nodes with AWS (actual) nodes.

Matching is deterministic and uses reliable identifiers only, strongest
first, within the same resource_type:

1. node id            (e.g. both sides are "vpc:vpc-0abc")
2. ARN
3. cloud resource id  (Terraform state `id` vs the id AWS reports)
4. terraform_address  (when both sides carry one)
5. name               (only if unique on *both* sides; otherwise ambiguous)

A name that matches several candidates is never guessed: those nodes are
reported as ambiguous so the diff layer can mark them UNKNOWN.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from flowlens.models.graph import Graph, Node, Source


@dataclass
class MatchResult:
    pairs: list[tuple[Node, Node, str]] = field(default_factory=list)  # (desired, actual, matched_by)
    terraform_only: list[Node] = field(default_factory=list)
    aws_only: list[Node] = field(default_factory=list)
    ambiguous: list[tuple[Node, list[Node]]] = field(default_factory=list)  # desired node, candidates


def _cloud_id_from_node_id(node: Node) -> str | None:
    if node.id.startswith("tf:") or ":" not in node.id:
        return None
    return node.id.split(":", 1)[1]


def desired_cloud_id(node: Node) -> str | None:
    state = node.desired_state or {}
    value = state.get("id")
    if isinstance(value, str) and value and "${" not in value:
        return value
    return _cloud_id_from_node_id(node)


def actual_cloud_id(node: Node) -> str | None:
    return _cloud_id_from_node_id(node)


def _names(node: Node, state: dict[str, Any] | None) -> set[str]:
    state = state or {}
    names = set()
    # A Terraform node without a Name tag is named after its resource label
    # ("main", "app"); that label says nothing about the real resource name.
    label = node.terraform_address.rsplit(".", 1)[-1] if node.terraform_address else None
    if node.name != label:
        names.add(node.name)
    for key in ("name", "function_name", "family"):
        value = state.get(key)
        if isinstance(value, str):
            names.add(value)
    tags = state.get("tags")
    if isinstance(tags, dict) and isinstance(tags.get("Name"), str):
        names.add(tags["Name"])
    return {n for n in names if n and "${" not in n}


def split_graph(graph: Graph) -> tuple[list[Node], list[Node]]:
    """Split a stored (possibly merged) graph into desired and actual views.

    A MERGED node that carries both desired_state and actual_state appears on
    both sides (it will then match itself by node id).
    """
    desired, actual = [], []
    for node in sorted(graph.nodes.values(), key=lambda n: n.id):
        if node.desired_state is not None or node.source == Source.TERRAFORM:
            desired.append(node.model_copy(update={"source": Source.TERRAFORM, "actual_state": None}))
        if node.actual_state is not None or node.source == Source.AWS:
            actual.append(node.model_copy(update={"source": Source.AWS, "desired_state": None}))
    return desired, actual


_KeyFn = Callable[[Node, bool], Iterable[str | None]]

#: (label, key function). The bool argument is True for the desired side.
_STRATEGIES: list[tuple[str, _KeyFn]] = [
    ("id", lambda n, _d: [n.id]),
    ("arn", lambda n, d: [n.aws_arn or ((n.desired_state or {}).get("arn") if d else None)]),
    ("resource_id", lambda n, d: [desired_cloud_id(n) if d else actual_cloud_id(n)]),
    ("terraform_address", lambda n, _d: [n.terraform_address]),
    ("name", lambda n, d: sorted(_names(n, n.desired_state if d else n.actual_state))),
]


def match_nodes(desired: Iterable[Node], actual: Iterable[Node]) -> MatchResult:
    remaining_desired = sorted(desired, key=lambda n: n.id)
    remaining_actual = sorted(actual, key=lambda n: n.id)
    result = MatchResult()
    ambiguous_ids: set[str] = set()

    for label, key_fn in _STRATEGIES:
        index: dict[tuple[str, str], list[Node]] = {}
        for a in remaining_actual:
            for key in key_fn(a, False):
                if key:
                    index.setdefault((a.resource_type, key), []).append(a)
        used_actual: set[str] = set()
        still_desired = []
        for d in remaining_desired:
            candidates: dict[str, Node] = {}
            for key in key_fn(d, True):
                if key:
                    for a in index.get((d.resource_type, key), []):
                        if a.id not in used_actual:
                            candidates[a.id] = a
            if len(candidates) == 1:
                a = next(iter(candidates.values()))
                result.pairs.append((d, a, label))
                used_actual.add(a.id)
            elif len(candidates) > 1 and label == "name":
                result.ambiguous.append((d, sorted(candidates.values(), key=lambda n: n.id)))
                ambiguous_ids.update(candidates)
            else:
                still_desired.append(d)
        remaining_desired = still_desired
        remaining_actual = [a for a in remaining_actual if a.id not in used_actual]

    result.terraform_only = remaining_desired
    result.aws_only = [a for a in remaining_actual if a.id not in ambiguous_ids]
    return result
