"""Desired-vs-actual comparison: assign a CompareStatus to every resource.

Statuses:
  MATCHED         in Terraform and AWS, compared attributes agree
  DIFFERENT       in Terraform and AWS, at least one compared attribute differs
  TERRAFORM_ONLY  declared in Terraform, not found in AWS
  AWS_ONLY        found in AWS, not declared in Terraform
  UNKNOWN         cannot be decided: ambiguous match, or the AWS scan could not
                  read that resource type (e.g. AccessDenied)

Only attributes present with a concrete value on *both* sides are compared;
unresolved Terraform interpolations ("${aws_vpc.main.id}") and nested
blocks are skipped, so config-only Terraform never produces false drift.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from flowlens.compare.matcher import match_nodes, split_graph
from flowlens.models.graph import Graph, Node


class CompareStatus(str, Enum):
    MATCHED = "MATCHED"
    TERRAFORM_ONLY = "TERRAFORM_ONLY"
    AWS_ONLY = "AWS_ONLY"
    DIFFERENT = "DIFFERENT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AttributeDiff:
    key: str
    desired: Any
    actual: Any


@dataclass
class ComparisonResult:
    status: CompareStatus
    resource_type: str
    desired_id: str | None = None
    actual_id: str | None = None
    name: str | None = None
    matched_by: str | None = None
    differences: list[AttributeDiff] = field(default_factory=list)
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "resource_type": self.resource_type,
            "desired_id": self.desired_id,
            "actual_id": self.actual_id,
            "name": self.name,
            "matched_by": self.matched_by,
            "differences": [{"key": d.key, "desired": d.desired, "actual": d.actual} for d in self.differences],
            "reason": self.reason,
        }


_MISSING = object()


def _comparable(value: Any) -> Any:
    """Normalize a value for comparison, or return _MISSING if it should be
    skipped (None, empty, interpolation, nested structure).
    """
    if value is None:
        return _MISSING
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _MISSING if not value or "${" in value else value
    if isinstance(value, list):
        if not value or not all(isinstance(v, (str, int, float)) and not isinstance(v, bool) for v in value):
            return _MISSING
        items = [str(v) for v in value]
        return _MISSING if any("${" in v for v in items) else tuple(sorted(items))
    return _MISSING


def diff_attributes(desired: dict[str, Any] | None, actual: dict[str, Any] | None) -> list[AttributeDiff]:
    desired, actual = desired or {}, actual or {}
    diffs = []
    for key in sorted(set(desired) & set(actual)):
        if key in ("id", "arn", "tags"):
            continue
        d, a = _comparable(desired[key]), _comparable(actual[key])
        if d is _MISSING or a is _MISSING:
            continue
        if d != a:
            diffs.append(AttributeDiff(key, desired[key], actual[key]))
    return diffs


def compare_nodes(
    desired: Iterable[Node],
    actual: Iterable[Node],
    unresolved_resource_types: Iterable[str] = (),
) -> list[ComparisonResult]:
    unresolved = set(unresolved_resource_types)
    match = match_nodes(desired, actual)
    results: list[ComparisonResult] = []

    for d, a, matched_by in match.pairs:
        diffs = diff_attributes(d.desired_state, a.actual_state)
        results.append(
            ComparisonResult(
                status=CompareStatus.DIFFERENT if diffs else CompareStatus.MATCHED,
                resource_type=d.resource_type,
                desired_id=d.id,
                actual_id=a.id,
                name=d.name,
                matched_by=matched_by,
                differences=diffs,
            )
        )
    for d, candidates in match.ambiguous:
        results.append(
            ComparisonResult(
                status=CompareStatus.UNKNOWN,
                resource_type=d.resource_type,
                desired_id=d.id,
                name=d.name,
                reason="ambiguous name match: " + ", ".join(c.id for c in candidates),
            )
        )
    for d in match.terraform_only:
        if d.resource_type in unresolved:
            results.append(
                ComparisonResult(
                    status=CompareStatus.UNKNOWN,
                    resource_type=d.resource_type,
                    desired_id=d.id,
                    name=d.name,
                    reason=f"AWS scan could not read resource type '{d.resource_type}' (permissions/errors)",
                )
            )
        else:
            results.append(
                ComparisonResult(CompareStatus.TERRAFORM_ONLY, d.resource_type, desired_id=d.id, name=d.name)
            )
    for a in match.aws_only:
        results.append(ComparisonResult(CompareStatus.AWS_ONLY, a.resource_type, actual_id=a.id, name=a.name))

    results.sort(key=lambda r: (r.resource_type, r.desired_id or "", r.actual_id or ""))
    return results


def compare_graph(graph: Graph) -> list[ComparisonResult]:
    """Compare a stored graph that contains both Terraform and AWS nodes.
    Resource types the last AWS scan could not read become UNKNOWN rather
    than TERRAFORM_ONLY.
    """
    desired, actual = split_graph(graph)
    unresolved = (graph.metadata.get("aws_scan") or {}).get("unresolved_resource_types", [])
    return compare_nodes(desired, actual, unresolved)


def summarize(results: Iterable[ComparisonResult]) -> dict[str, int]:
    counts = {s.value: 0 for s in CompareStatus}
    for r in results:
        counts[r.status.value] += 1
    return counts
