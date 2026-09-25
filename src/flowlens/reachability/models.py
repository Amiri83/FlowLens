"""Result model of a reachability analysis.

Four-state status everywhere: ALLOWED, BLOCKED, UNKNOWN, NOT_APPLICABLE.
UNKNOWN means FlowLens does not have enough information to prove either
allow or block — it is never a guess in either direction.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from flowlens.reachability.netutil import PortRange, fmt_traffic


class CheckStatus(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"

    @property
    def label(self) -> str:
        """Plain-text tag for terminal output (no color needed)."""
        return {"ALLOWED": "[PASS]", "BLOCKED": "[FAIL]", "UNKNOWN": "[ ?? ]", "NOT_APPLICABLE": "[ -- ]"}[self.value]


def combine(statuses) -> CheckStatus:
    """Conjunction of required checks: any BLOCKED -> BLOCKED, else any
    UNKNOWN -> UNKNOWN, else ALLOWED. NOT_APPLICABLE checks are ignored;
    if nothing was actually proven, the result is UNKNOWN (never ALLOWED).
    """
    seen = {s for s in statuses if s != CheckStatus.NOT_APPLICABLE}
    if not seen:
        return CheckStatus.UNKNOWN
    if CheckStatus.BLOCKED in seen:
        return CheckStatus.BLOCKED
    if CheckStatus.UNKNOWN in seen:
        return CheckStatus.UNKNOWN
    return CheckStatus.ALLOWED


@dataclass
class TrafficContext:
    """Traffic as seen at one hop. The port is allowed to change along the
    path (ALB :443 -> target group :8080 -> ECS :8080): `current_port` is the
    port on this hop, `original_port` the one the client asked for.
    """

    protocol: str
    source: str
    destination: str
    current_port: PortRange | None
    original_port: PortRange | None
    source_cidrs: list[str] | None = None  # None = unknown
    destination_cidrs: list[str] | None = None
    source_sgs: list[str] = field(default_factory=list)
    destination_sgs: list[str] = field(default_factory=list)

    def at_port(self, port: PortRange | None) -> TrafficContext:
        return replace(self, current_port=port)

    @property
    def traffic(self) -> str:
        return fmt_traffic(self.protocol, self.current_port)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "source": self.source,
            "destination": self.destination,
            "current_port": str(self.current_port) if self.current_port else None,
            "original_port": str(self.original_port) if self.original_port else None,
            "source_cidrs": self.source_cidrs,
            "destination_cidrs": self.destination_cidrs,
            "source_sgs": self.source_sgs,
            "destination_sgs": self.destination_sgs,
        }


@dataclass
class ReachabilityCheck:
    check_type: str  # e.g. "security_group_ingress", "route", "nacl_egress_return"
    status: CheckStatus
    source: str
    destination: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    suggestion: str | None = None
    hop_index: int | None = None
    #: Graph node ids this check is about (for UI highlighting).
    resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type,
            "status": self.status.value,
            "source": self.source,
            "destination": self.destination,
            "reason": self.reason,
            "evidence": self.evidence,
            "suggestion": self.suggestion,
            "hop_index": self.hop_index,
            "resources": self.resources,
        }


@dataclass
class ReachabilityHop:
    """One hop on the evaluated path: `from` -> `to` carrying `protocol/port`.
    kind="network" is a packet hop (SG/NACL/route checks apply);
    kind="forward" is a load balancer handing traffic to a target group,
    where the port may change.
    """

    index: int
    kind: str
    from_label: str
    to_label: str
    protocol: str
    port_in: PortRange | None
    port_out: PortRange | None
    description: str
    from_node: str | None = None
    to_node: str | None = None
    nodes: list[str] = field(default_factory=list)
    status: CheckStatus = CheckStatus.UNKNOWN
    context: TrafficContext | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "kind": self.kind,
            "from": self.from_label,
            "to": self.to_label,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "protocol": self.protocol,
            "port_in": str(self.port_in) if self.port_in else None,
            "port_out": str(self.port_out) if self.port_out else None,
            "traffic": fmt_traffic(self.protocol, self.port_out),
            "description": self.description,
            "nodes": self.nodes,
            "status": self.status.value,
            "context": self.context.to_dict() if self.context else None,
        }


@dataclass
class CandidatePath:
    """One evaluated topology candidate (a possible way traffic could flow)."""

    label: str
    hops: list[ReachabilityHop]
    checks: list[ReachabilityCheck]
    status: CheckStatus = CheckStatus.UNKNOWN

    @property
    def first_blocking(self) -> ReachabilityCheck | None:
        return next((c for c in self.checks if c.status == CheckStatus.BLOCKED), None)

    @property
    def first_unknown(self) -> ReachabilityCheck | None:
        return next((c for c in self.checks if c.status == CheckStatus.UNKNOWN), None)

    def summary(self) -> dict[str, Any]:
        decisive = self.first_blocking or self.first_unknown
        return {
            "label": self.label,
            "status": self.status.value,
            "reason": decisive.reason if decisive else None,
        }


@dataclass
class ReachabilityResult:
    source: str
    destination: str
    protocol: str
    port: PortRange | None
    overall_status: CheckStatus
    path: list[ReachabilityHop] = field(default_factory=list)
    checks: list[ReachabilityCheck] = field(default_factory=list)
    blocked_at: str | None = None
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    source_node: str | None = None
    destination_node: str | None = None
    path_label: str = ""
    candidates: list[dict[str, Any]] = field(default_factory=list)
    subnets: list[dict[str, Any]] = field(default_factory=list)
    #: Graph (topology) connectivity, reported for contrast only — it is
    #: never used as evidence of reachability.
    topology_connected: bool | None = None
    limits: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "source_node": self.source_node,
            "destination_node": self.destination_node,
            "protocol": self.protocol,
            "port": str(self.port) if self.port else None,
            "traffic": fmt_traffic(self.protocol, self.port),
            "overall_status": self.overall_status.value,
            "path_label": self.path_label,
            "path": [h.to_dict() for h in self.path],
            "checks": [c.to_dict() for c in self.checks],
            "blocked_at": self.blocked_at,
            "reason": self.reason,
            "evidence": self.evidence,
            "uncertainties": self.uncertainties,
            "suggestions": self.suggestions,
            "candidates": self.candidates,
            "subnets": self.subnets,
            "topology_connected": self.topology_connected,
            "limits": self.limits,
        }
