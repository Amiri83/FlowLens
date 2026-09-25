"""Stateless network ACL evaluation.

NACLs are evaluated at the subnet boundary, in ascending rule-number order;
the first rule that matches a packet decides, and the implicit final `*`
rule denies. Because they are stateless, the reply direction must be
allowed explicitly: for a connection to port P the reply leaves the server
from P towards the client's ephemeral port (1024-65535 covers AWS-managed
clients and every common OS).

Supported: rule ordering, allow/deny, ingress/egress, protocol (incl. -1),
IPv4/IPv6 CIDR, port ranges, ICMP type. A rule whose CIDR only partially
overlaps the peer's range makes the ports it would decide UNKNOWN rather
than guessing which addresses are in play.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from flowlens.reachability.facts import Nacl, NaclRule
from flowlens.reachability.models import CheckStatus
from flowlens.reachability.netutil import (
    ALL_PORTS,
    Interval,
    IPNetwork,
    cidr_relation,
    fmt_intervals,
    intersect,
    merge,
    subtract,
)


@dataclass
class NaclVerdict:
    status: CheckStatus
    allowed: list[Interval] = field(default_factory=list)
    denied: list[Interval] = field(default_factory=list)
    uncertain: list[Interval] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    detail: str = ""


def _rule_interval(rule: NaclRule, protocol: str) -> list[Interval] | None:
    if rule.protocol == "all":
        return [ALL_PORTS]
    if rule.protocol in ("icmp", "icmpv6"):
        return [ALL_PORTS] if rule.icmp_type in (None, -1) else [(rule.icmp_type, rule.icmp_type)]
    return [rule.ports] if rule.ports is not None else None


def evaluate(
    nacl: Nacl,
    direction: str,
    protocol: str,
    required: list[Interval] | None,
    peer: IPNetwork | None,
    *,
    partial_is_unknown: bool = False,
) -> NaclVerdict:
    """Evaluate one direction of one NACL for traffic to/from `peer`.

    required: ports (or ICMP types) the packets use; None = unknown port
    (then only an all-ports decision is conclusive).
    partial_is_unknown: for reply traffic to an unknown ephemeral port, a
    NACL that allows only part of the range is UNKNOWN (depends on the
    client OS), not BLOCKED.
    """
    port_unknown = required is None
    wanted = [ALL_PORTS] if port_unknown else merge(required)
    remaining = list(wanted)
    allowed: list[Interval] = []
    denied: list[Interval] = []
    ambiguous: list[tuple[list[Interval], str]] = []
    evidence: list[str] = []
    partial_protocol_deny = False
    rules = sorted(getattr(nacl, direction), key=lambda r: (r.rule_no is None, r.rule_no or 0))
    for rule in rules:
        if not remaining:
            break
        if rule.unresolved:
            ambiguous.append((list(remaining), "unresolved"))
            evidence.append(f"{nacl.label} {direction} {rule.describe()} has unresolved values [{rule.origin}]")
            continue
        if rule.protocol != "all" and rule.protocol != protocol:
            if protocol == "all" and rule.action == "deny":
                partial_protocol_deny = True
                evidence.append(f"{nacl.label} {direction} {rule.describe()} denies part of all-traffic [{rule.origin}]")
            continue
        span = _rule_interval(rule, protocol)
        hit = intersect(remaining, span) if span is not None else list(remaining)
        if not hit:
            continue
        relation = "covers" if peer is None and rule.cidr.prefixlen == 0 else (
            "overlaps" if peer is None else cidr_relation(rule.cidr, peer)
        )
        if relation == "disjoint":
            continue
        if relation == "overlaps":
            ambiguous.append((hit, rule.action))
            evidence.append(f"{nacl.label} {direction} {rule.describe()} matches only part of {peer or 'the peer'} [{rule.origin}]")
            continue
        (allowed if rule.action == "allow" else denied).extend(hit)
        evidence.append(f"{nacl.label} {direction} {rule.describe()} -> {rule.action.upper()} ports {fmt_intervals(hit)} [{rule.origin}]")
        remaining = subtract(remaining, hit)
    if remaining:
        denied.extend(remaining)
        evidence.append(f"{nacl.label} {direction} rule * DENY (implicit) for {fmt_intervals(remaining)}")
    allowed, denied = merge(allowed), merge(denied)
    uncertain: list[Interval] = []
    for span, action in ambiguous:
        if action == "unresolved":
            uncertain.extend(span)
        elif action == "allow":
            uncertain.extend(intersect(span, denied))
        else:
            uncertain.extend(intersect(span, allowed))
    uncertain = merge(uncertain)
    certain_denied = subtract(denied, uncertain)

    if partial_protocol_deny and not certain_denied:
        return NaclVerdict(CheckStatus.BLOCKED, allowed, denied, uncertain, evidence, "a protocol-specific DENY precedes the allow")
    if not denied and not uncertain:
        return NaclVerdict(CheckStatus.ALLOWED, allowed, denied, uncertain, evidence, f"allowed ports {fmt_intervals(allowed)}")
    if port_unknown:
        if not allowed and not uncertain:
            return NaclVerdict(CheckStatus.BLOCKED, allowed, denied, uncertain, evidence, "every port is denied")
        return NaclVerdict(CheckStatus.UNKNOWN, allowed, denied, uncertain, evidence, "port unknown and only some ports are allowed")
    if certain_denied:
        if partial_is_unknown and allowed:
            return NaclVerdict(
                CheckStatus.UNKNOWN,
                allowed,
                denied,
                uncertain,
                evidence,
                f"only ports {fmt_intervals(allowed)} of {fmt_intervals(wanted)} allowed; depends on the client's ephemeral port range",
            )
        return NaclVerdict(CheckStatus.BLOCKED, allowed, denied, uncertain, evidence, f"denied ports {fmt_intervals(certain_denied)}")
    detail = f"ports {fmt_intervals(uncertain)} depend on the exact address"
    return NaclVerdict(CheckStatus.UNKNOWN, allowed, denied, uncertain, evidence, detail)
