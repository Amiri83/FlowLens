"""Deterministic network reachability & troubleshooting engine.

Separate from topology traversal (flowlens.graph.traversal): a path in the
graph shows that resources are *connected*; this package decides whether
traffic can actually *flow* on a given protocol/port, and where and why it
is blocked when it cannot.
"""
from flowlens.reachability.engine import EndpointError, ReachabilityEngine, analyze
from flowlens.reachability.models import (
    CheckStatus,
    ReachabilityCheck,
    ReachabilityHop,
    ReachabilityResult,
    TrafficContext,
)

__all__ = [
    "CheckStatus",
    "EndpointError",
    "ReachabilityCheck",
    "ReachabilityEngine",
    "ReachabilityHop",
    "ReachabilityResult",
    "TrafficContext",
    "analyze",
]
