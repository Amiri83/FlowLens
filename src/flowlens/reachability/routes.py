"""Route table evaluation: effective table per subnet, longest-prefix match,
and PUBLIC/PRIVATE subnet classification from routing evidence.

The effective table is the subnet's explicit association, falling back to
the VPC main route table. Every table implicitly contains the VPC local
route. A subnet is PUBLIC only when its effective table has an active
route to an internet gateway — names and tags are never consulted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from flowlens.reachability.facts import NetworkFacts, Route, RouteTable
from flowlens.reachability.netutil import IPNetwork


@dataclass
class RouteLookup:
    subnet: str
    destination: IPNetwork | None
    table: RouteTable | None
    how: str
    route: Route | None = None
    #: Routes whose destination cannot be compared (prefix lists, unresolved).
    opaque: list[Route] = field(default_factory=list)

    def evidence(self, facts: NetworkFacts) -> str:
        sn = facts.label(self.subnet)
        if self.table is None:
            return f"{sn}: route table unknown ({self.how})"
        if self.route is None:
            return f"{sn} -> {self.table.label} ({self.how}): no route matches {self.destination}"
        return f"{sn} -> {self.table.label} ({self.how}): {self.route.describe()} matches {self.destination} [{self.route.origin}]"


def lookup(facts: NetworkFacts, subnet_key: str, destination: IPNetwork | None) -> RouteLookup:
    rt_key, how = facts.effective_route_table(subnet_key)
    table = facts.route_tables.get(rt_key or "")
    result = RouteLookup(subnet_key, destination, table, how)
    if table is None or destination is None:
        return result
    best: Route | None = None
    for route in table.routes:
        if route.destination is None:
            result.opaque.append(route)
            continue
        if route.destination.version != destination.version or not destination.subnet_of(route.destination):
            continue
        # Longest prefix wins; on a tie prefer an explicit over an implicit route, then a stable order.
        if best is None or (route.destination.prefixlen, not route.implicit) > (best.destination.prefixlen, not best.implicit):
            best = route
    result.route = best
    return result


def in_vpc(facts: NetworkFacts, vpc_key: str | None, destination: IPNetwork) -> bool:
    return any(c.version == destination.version and destination.subnet_of(c) for c in facts.vpc_cidrs(vpc_key))


def classify_subnet(facts: NetworkFacts, subnet_key: str) -> dict:
    """PUBLIC / PRIVATE / UNKNOWN from the subnet's effective route table."""
    subnet = facts.subnets.get(subnet_key)
    label = facts.label(subnet_key)
    rt_key, how = facts.effective_route_table(subnet_key)
    table = facts.route_tables.get(rt_key or "")
    out = {
        "subnet": subnet_key,
        "label": label,
        "cidr": ", ".join(str(c) for c in subnet.cidrs) if subnet else None,
        "route_table": rt_key,
        "association": how,
    }
    if table is None:
        return {**out, "classification": "UNKNOWN", "evidence": [f"{label}: {how}"]}
    igw = [r for r in table.routes if r.target_type == "internet_gateway" and r.state != "blackhole"]
    if igw:
        return {
            **out,
            "classification": "PUBLIC",
            "evidence": [f"{table.label} ({how}): {r.describe()} [{r.origin}]" for r in igw],
        }
    ambiguous = [r for r in table.routes if r.target_type == "unknown"]
    if ambiguous or table.notes:
        return {
            **out,
            "classification": "UNKNOWN",
            "evidence": [f"{table.label}: {r.describe()} target type cannot be determined [{r.origin}]" for r in ambiguous] + table.notes,
        }
    default = next((r for r in table.routes if r.destination is not None and r.destination.prefixlen == 0), None)
    detail = f"default route {default.describe()}" if default else "no default route"
    return {
        **out,
        "classification": "PRIVATE",
        "evidence": [f"{table.label} ({how}): no route to an internet gateway; {detail}"],
    }
