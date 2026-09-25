"""Stateful security group evaluation.

Security groups are allow-lists attached to an ENI; traffic is permitted
when *any* attached group has a matching rule. They are stateful: once a
connection is allowed in the initiating direction, reply packets are
allowed automatically, so return traffic is never evaluated against the
opposite-direction rules here.

A rule matches a peer when protocol and port match and either one of its
security group references is attached to the peer, or one of its CIDRs
fully contains the peer's address range. Partial CIDR overlap, prefix
lists and unresolved values make a rule a "maybe" -> UNKNOWN, never a
guessed ALLOW or BLOCK.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from flowlens.reachability.facts import NetworkFacts, SGRule
from flowlens.reachability.models import CheckStatus
from flowlens.reachability.netutil import (
    ALL_PORTS,
    ICMP_ECHO_REQUEST,
    Interval,
    IPNetwork,
    PortRange,
    cidr_relation,
    fmt_intervals,
    fmt_traffic,
    has_ports,
    merge,
    subtract,
)


@dataclass
class Peer:
    """The other side of a connection, as seen by the SG being evaluated."""

    label: str
    cidrs: list[IPNetwork] | None  # None = address unknown
    sgs: list[str] = field(default_factory=list)
    sgs_unknown: bool = False
    name: str = ""


@dataclass
class Verdict:
    status: CheckStatus
    reason: str
    evidence: list[str] = field(default_factory=list)
    suggestion: str | None = None
    notes: list[str] = field(default_factory=list)


def request_intervals(protocol: str, port: PortRange | None) -> list[Interval] | None:
    """Port (or ICMP type) intervals a request needs; None when unknown."""
    if protocol == "all":
        return [ALL_PORTS]
    if protocol in ("icmp", "icmpv6"):
        t = port.lo if port is not None else ICMP_ECHO_REQUEST
        return [(t, t)]
    if not has_ports(protocol):
        return [ALL_PORTS]
    return [port.interval] if port is not None else None


def _protocol_match(rule: SGRule, protocol: str) -> str:
    """"yes", "no" or "maybe"."""
    if rule.protocol is None:
        return "maybe"
    if rule.protocol == "all":
        return "yes"
    if protocol == "all":
        return "no"  # a single-protocol rule never allows *all* traffic
    return "yes" if rule.protocol == protocol else "no"


def _peer_match(rule: SGRule, owner: str, peer: Peer, facet: IPNetwork | None, why: list[str]) -> str:
    """"yes" (rule definitely covers this peer facet), "maybe", or "no".
    Reasons for a "maybe" are appended to `why`.
    """
    if any(ref in peer.sgs for ref in rule.sg_refs) or (rule.self_ref and owner in peer.sgs):
        return "yes"
    result = "no"
    if (rule.sg_refs or rule.self_ref) and peer.sgs_unknown:
        result = "maybe"
        why.append(f"security groups of {peer.name or peer.label} are unknown, so SG-referencing rules cannot be matched")
    for cidr in rule.cidrs:
        if facet is None:
            if cidr.prefixlen == 0:
                return "yes"
            result = "maybe"
            why.append(f"address of {peer.name or peer.label} is unknown; rule CIDR {cidr} may or may not cover it")
            continue
        relation = cidr_relation(cidr, facet)
        if relation == "covers":
            return "yes"
        if relation == "overlaps":
            result = "maybe"
            why.append(f"rule CIDR {cidr} covers only part of {facet}")
    if rule.prefix_lists:
        result = "maybe"
        why.append(f"prefix lists are not expanded ({', '.join(rule.prefix_lists)})")
    if rule.unresolved:
        result = "maybe"
        why.append(f"unresolved rule values: {', '.join(rule.unresolved)}")
    return result


def evaluate(
    facts: NetworkFacts,
    *,
    owner_label: str,
    sg_keys: list[str],
    sg_unresolved: list[str],
    direction: str,
    protocol: str,
    port: PortRange | None,
    peer: Peer,
) -> Verdict:
    """Evaluate one direction (ingress on the receiver, or egress on the
    sender) of the security groups attached to one endpoint.
    """
    traffic = fmt_traffic(protocol, port)
    word = "from" if direction == "ingress" else "to"
    if not sg_keys:
        detail = "; ".join(sg_unresolved) or "no security groups recorded"
        return Verdict(
            CheckStatus.UNKNOWN,
            f"security groups of {owner_label} are unknown ({detail})",
            [f"{owner_label}: security groups unresolved: {detail}"],
            f"Scan AWS (flowlens aws scan) or provide Terraform state so {owner_label}'s security groups are known.",
        )

    required = request_intervals(protocol, port)
    facets: list[IPNetwork | None] = list(peer.cidrs) if peer.cidrs else [None]
    incomplete_notes: list[str] = []
    rules: list[tuple[str, SGRule]] = []
    for key in sg_keys:
        sg = facts.security_groups.get(key)
        if sg is None:
            incomplete_notes.append(f"{facts.label(key)}: security group rules not in the scanned data")
            continue
        if not sg.complete:
            incomplete_notes.extend(sg.notes or [f"{sg.label}: rules incomplete"])
        rules.extend((key, r) for r in getattr(sg, direction))
    if sg_unresolved:
        incomplete_notes.append(f"{owner_label}: additional security groups unresolved: {', '.join(sg_unresolved)}")
    if facts.orphan_sg_rules:
        incomplete_notes.extend(facts.orphan_sg_rules)

    matched: list[str] = []
    why: list[str] = []
    facet_status: list[tuple[IPNetwork | None, CheckStatus, list[Interval]]] = []
    for facet in facets:
        covered: list[Interval] = []
        maybe: list[Interval] = []
        for owner, rule in rules:
            pm = _protocol_match(rule, protocol)
            if pm == "no":
                continue
            if pm == "maybe":
                why.append(f"unresolved protocol in {rule.origin}")
            peer_m = _peer_match(rule, owner, peer, facet, why)
            if peer_m == "no":
                continue
            interval = rule.ports
            definite = pm == "yes" and peer_m == "yes" and interval is not None
            span = [interval] if interval is not None else [ALL_PORTS]
            if definite:
                covered.extend(span)
                text = f"{facts.label(owner)} {rule.describe(facts.labels)} [{rule.origin}]"
                if text not in matched and (required is None or subtract(required, span) != required):
                    matched.append(text)
            else:
                maybe.extend(span)
        covered, maybe = merge(covered), merge(maybe)
        if required is None:  # port unknown: only an all-ports rule proves ALLOWED
            if not subtract([ALL_PORTS], covered):
                status = CheckStatus.ALLOWED
            elif covered or maybe:
                status = CheckStatus.UNKNOWN
            else:
                status = CheckStatus.BLOCKED
            facet_status.append((facet, status, covered))
            continue
        missing = subtract(required, covered)
        if not missing:
            status = CheckStatus.ALLOWED
        elif subtract(missing, maybe):
            status = CheckStatus.BLOCKED
        else:
            status = CheckStatus.UNKNOWN
        if status == CheckStatus.BLOCKED and incomplete_notes:
            status = CheckStatus.UNKNOWN
        facet_status.append((facet, status, covered))

    sg_names = ", ".join(facts.label(k) for k in sg_keys)
    statuses = {s for _f, s, _c in facet_status}
    existing = [f"{facts.label(o)} {r.describe(facts.labels)} [{r.origin}]" for o, r in rules] or [
        f"{sg_names}: no {direction} rules at all"
    ]
    if statuses == {CheckStatus.ALLOWED}:
        return Verdict(CheckStatus.ALLOWED, f"{sg_names} {direction} permits {traffic} {word} {peer.label}", matched)
    if CheckStatus.BLOCKED in statuses:
        blocked = [f for f, s, _c in facet_status if s == CheckStatus.BLOCKED]
        partial = len(blocked) < len(facet_status)
        scope = f" (for {', '.join(str(f) for f in blocked)})" if partial else ""
        covered_ports = merge([iv for _f, _s, c in facet_status for iv in c])
        port_note = f"; ports allowed for this peer: {fmt_intervals(covered_ports)}" if covered_ports and has_ports(protocol) else ""
        reason = f"{sg_names} does not permit {traffic} {word} {peer.label}{scope}{port_note}"
        if partial:
            reason = "partially blocked: " + reason
        return Verdict(
            CheckStatus.BLOCKED,
            reason,
            ["existing " + direction + " rules: " + e for e in existing] + incomplete_notes,
            f"Check whether {sg_names} should allow {direction} {traffic} {word} {peer.label}.",
        )
    detail = "; ".join(dict.fromkeys(why + incomplete_notes)) or "a rule may match only part of the peer's addresses"
    if required is None:
        detail = f"port is unknown and not every port is allowed ({detail})"
    return Verdict(
        CheckStatus.UNKNOWN,
        f"cannot prove {sg_names} {direction} permits {traffic} {word} {peer.label}: {detail}",
        matched + ["relevant " + direction + " rules: " + e for e in existing],
        f"Resolve the missing values (e.g. scan AWS or provide Terraform state) for {sg_names}.",
        incomplete_notes,
    )
