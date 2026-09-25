"""Deterministic reachability engine: can traffic flow from A to B on
protocol/port X, and if not, where is it blocked and why?

Graph connectivity is never taken as proof. The engine enumerates a bounded
set of candidate paths (direct, or through load balancers whose listeners
forward to target groups that reach the destination), evaluates every
network hop against routes, network ACLs and security groups, tracks the
port as it changes along the path, and picks the best candidate:
any ALLOWED path wins, otherwise an UNKNOWN one (a path *might* work),
otherwise the BLOCKED path that got furthest.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from flowlens.graph.traversal import resolve_node_ref, shortest_path
from flowlens.models.graph import Graph
from flowlens.reachability import nacl as nacl_eval
from flowlens.reachability import security_groups as sg_eval
from flowlens.reachability.facts import (
    Binding,
    Endpoint,
    Forward,
    Listener,
    NetworkFacts,
    TargetGroup,
    build_facts,
)
from flowlens.reachability.models import (
    CandidatePath,
    CheckStatus,
    ReachabilityCheck,
    ReachabilityHop,
    ReachabilityResult,
    TrafficContext,
    combine,
)
from flowlens.reachability.netutil import (
    ALL_PORTS,
    EPHEMERAL_PORTS,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    INTERNET_V4,
    INTERNET_V6,
    IPNetwork,
    PortRange,
    fmt_traffic,
    has_ports,
    is_private,
    normalize_protocol,
    parse_cidr,
)
from flowlens.reachability.routes import classify_subnet, in_vpc, lookup

#: Hard limits on candidate exploration (keeps the search polynomial).
MAX_CANDIDATES = 16
MAX_LB_HOPS = 2
MAX_PAIRS = 32

A, B, U, NA = CheckStatus.ALLOWED, CheckStatus.BLOCKED, CheckStatus.UNKNOWN, CheckStatus.NOT_APPLICABLE

INTERNET_ALIASES = {"internet", "0.0.0.0/0", "any", "world", "::/0"}
SUPPORTED_PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6", "all")


class EndpointError(ValueError):
    """The source/destination reference cannot be used as a traffic endpoint."""


@dataclass
class _Net:
    """A packet hop from src to dst on `port`."""

    src: Endpoint
    dst: Endpoint
    port: PortRange | None
    listener: Listener | None = None
    #: "n/a" (dst is not a load balancer), "match", "none", "unknown".
    listener_state: str = "n/a"
    via_lb: Endpoint | None = None
    #: Who the destination's SG sees as the source (NLB client IP
    #: preservation); None = src. "both" when preservation is unknown.
    client: Endpoint | None = None
    preserve: bool | None = False


@dataclass
class _Fwd:
    """A load balancer listener handing traffic to a target group."""

    lb: Endpoint
    listener: Listener
    forward: Forward | None
    tg: TargetGroup | None
    binding: Binding | None
    port_in: PortRange | None
    port_out: PortRange | None
    preserve: bool | None = False
    notes: list[str] = field(default_factory=list)


def _listener_transport(listener: Listener, lb: Endpoint) -> set[str]:
    proto = (listener.protocol or ("TCP" if lb.lb_type == "network" else "HTTP")).upper()
    if proto == "TCP_UDP":
        return {"tcp", "udp"}
    if proto in ("UDP", "GENEVE"):
        return {"udp"}
    return {"tcp"}


def _listener_text(listener: Listener, lb: Endpoint) -> str:
    proto = (listener.protocol or ("TCP" if lb.lb_type == "network" else "HTTP")).upper()
    return f"{proto}:{listener.port if listener.port is not None else '?'}"


class ReachabilityEngine:
    def __init__(self, graph: Graph, facts: NetworkFacts | None = None):
        self.graph = graph
        self.facts = facts or build_facts(graph)

    # --- endpoints ------------------------------------------------------------

    def resolve(self, ref: str) -> Endpoint:
        text = ref.strip()
        if text.lower() in INTERNET_ALIASES:
            net = INTERNET_V6 if text == "::/0" else INTERNET_V4
            return Endpoint(key="internet", label="Internet", kind="internet", external=True, in_vpc=False,
                            addresses=[net], sg_applicable=False, public_ip=True)
        net = parse_cidr(text)
        if net is not None:
            return self._address_endpoint(net)
        node_id = resolve_node_ref(self.graph, text)
        if node_id is None:
            raise EndpointError(f"No unique resource matches {ref!r} (try a node id, terraform address, ARN, cloud id or name)")
        node = self.graph.nodes[node_id]
        if node.resource_type == "listener":
            listener = self.facts.listeners.get(node_id)
            if listener and listener.lb in self.facts.endpoints:
                return self.facts.endpoints[listener.lb]
        if node_id not in self.facts.endpoints:
            raise EndpointError(
                f"{ref!r} is a {node.resource_type}, not a traffic endpoint. Use 'internet', an IP/CIDR, or a load balancer, "
                "ECS service, Lambda function, EC2 instance or RDS instance."
            )
        return self.facts.endpoints[node_id]

    def _address_endpoint(self, net: IPNetwork) -> Endpoint:
        for subnet in sorted(self.facts.subnets.values(), key=lambda s: s.key):
            if any(c.version == net.version and net.subnet_of(c) for c in subnet.cidrs):
                return Endpoint(
                    key=f"address:{net}", label=str(net), kind="address", vpc=subnet.vpc, subnets=[subnet.key], addresses=[net],
                    sgs_unresolved=[f"unknown network interface at {net}"],
                    notes=[f"{net} is inside {subnet.label}; the security groups of whatever uses this address are unknown"],
                )
        for vpc in self.facts.vpcs.values():
            if any(c.version == net.version and net.subnet_of(c) for c in vpc.cidrs):
                return Endpoint(key=f"address:{net}", label=str(net), kind="address", vpc=vpc.key, addresses=[net],
                                subnets_unresolved=[f"no known subnet contains {net}"], sgs_unresolved=[f"unknown interface at {net}"])
        return Endpoint(key=f"address:{net}", label=str(net), kind="address", external=True, in_vpc=False, addresses=[net],
                        sg_applicable=False, public_ip=not is_private(net))

    # --- addresses --------------------------------------------------------------

    def _subnet_addrs(self, ep: Endpoint) -> list[tuple[str | None, IPNetwork | None]]:
        """(subnet key, address range used there) for every place ep lives."""
        if ep.external or not ep.in_vpc:
            return [(None, a) for a in (ep.addresses or [None])]
        out: list[tuple[str | None, IPNetwork | None]] = []
        for s in ep.subnets:
            subnet = self.facts.subnets.get(s)
            cidrs = subnet.cidrs if subnet else []
            if ep.addresses:
                inside = [a for a in ep.addresses if any(a.version == c.version and a.subnet_of(c) for c in cidrs)]
                if inside:
                    out.extend((s, a) for a in inside)
                    continue
            v4 = [c for c in cidrs if c.version == 4] or cidrs
            out.append((s, v4[0] if v4 else None))
        if not ep.subnets and ep.addresses:
            out.extend((None, a) for a in ep.addresses)
        return out

    def _addrs(self, ep: Endpoint) -> list[IPNetwork] | None:
        if ep.addresses is not None:
            return ep.addresses
        addrs = [a for _s, a in self._subnet_addrs(ep) if a is not None]
        return addrs or None

    def _peer(self, ep: Endpoint) -> sg_eval.Peer:
        addrs = self._addrs(ep)
        if ep.sgs:
            label = f"{ep.display} ({', '.join(self.facts.label(s) for s in ep.sgs)})"
        elif addrs:
            label = f"{ep.display} ({', '.join(str(a) for a in addrs)})" if ep.kind != "address" else ep.display
        else:
            label = ep.display
        return sg_eval.Peer(label, addrs, list(ep.sgs), bool(ep.sgs_unresolved), ep.display, internet=ep.kind == "internet")

    # --- candidate enumeration --------------------------------------------------

    def _endpoint(self, key: str) -> Endpoint | None:
        return self.facts.endpoints.get(key)

    def _reaches(self, tg_key: str, dst: Endpoint, depth: int) -> bool:
        for b in self.facts.bindings_of(tg_key):
            if b.target == dst.key:
                return True
            target = self._endpoint(b.target)
            if target is not None and target.kind == "lb" and depth < MAX_LB_HOPS and self._lb_reaches(target, dst, depth + 1):
                return True
        return False

    def _lb_reaches(self, lb: Endpoint, dst: Endpoint, depth: int = 0) -> bool:
        return any(
            f.target_group and self._reaches(f.target_group, dst, depth)
            for li in self.facts.listeners_of(lb.key)
            for f in li.forwards
        )

    def _lb_maybe_reaches(self, lb: Endpoint, dst: Endpoint) -> bool:
        """LB has unresolved forwarding and dst is bound to a target group no
        resolved listener forwards to."""
        listeners = self.facts.listeners_of(lb.key)
        if not any(not li.actions_known or any(f.target_group is None for f in li.forwards) for li in listeners):
            return False
        forwarded = {f.target_group for li in self.facts.listeners.values() for f in li.forwards if f.target_group}
        return any(b.target == dst.key and b.target_group not in forwarded for b in self.facts.bindings)

    def _lb_entries(self, prev: Endpoint, lb: Endpoint, port: PortRange | None, protocol: str) -> list[_Net]:
        listeners = self.facts.listeners_of(lb.key)
        matching, unknown = [], []
        for li in listeners:
            if protocol not in _listener_transport(li, lb):
                continue
            if li.port is None:
                unknown.append(li)
            elif port is None or port.lo <= li.port <= port.hi:
                matching.append(li)
        if matching:
            return [_Net(prev, lb, PortRange(li.port, li.port), li, "match") for li in matching]
        if unknown:
            return [_Net(prev, lb, port, li, "unknown") for li in unknown]
        return [_Net(prev, lb, port, None, "none")]

    def _tg_hops(self, lb: Endpoint, entry: _Net, dst: Endpoint, depth: int) -> list[tuple[_Fwd, Endpoint | None]]:
        """Forward steps from one listener towards dst (or diagnostic dead ends)."""
        li = entry.listener
        out: list[tuple[_Fwd, Endpoint | None]] = []
        seen: set[str] = set()
        for fwd in li.forwards:
            if fwd.target_group is None:
                if self._lb_maybe_reaches(lb, dst):
                    out.append((_Fwd(lb, li, fwd, None, None, entry.port, None), None))
                continue
            if fwd.target_group in seen:
                continue
            seen.add(fwd.target_group)
            tg = self.facts.target_groups.get(fwd.target_group)
            for b in self.facts.bindings_of(fwd.target_group):
                target = self._endpoint(b.target)
                if target is None:
                    continue
                if b.target != dst.key and not (target.kind == "lb" and self._lb_reaches(target, dst, depth + 1)):
                    continue
                port_num = b.port if b.port is not None else (tg.port if tg else None)
                port_out = PortRange(port_num, port_num) if port_num is not None else None
                out.append((_Fwd(lb, li, fwd, tg, b, entry.port, port_out), target))
        if not out and (not li.actions_known or not li.forwards):
            out.append((_Fwd(lb, li, None, None, None, entry.port, None), None))
        return out

    def _through_lb(self, prev: Endpoint, lb: Endpoint, port, protocol, dst: Endpoint, prefix: list, depth: int, visited: set[str]):
        for entry in self._lb_entries(prev, lb, port, protocol):
            if entry.listener is None:
                yield prefix + [entry]
                continue
            for fwd, target in self._tg_hops(lb, entry, dst, depth):
                steps = prefix + [entry, fwd]
                if target is None:
                    yield steps
                    continue
                self._set_preserve(fwd)
                client = entry.client or prev
                if target.key == dst.key:
                    yield steps + [_Net(lb, dst, fwd.port_out, via_lb=lb, client=client, preserve=fwd.preserve)]
                elif target.kind == "lb" and depth + 1 < MAX_LB_HOPS and target.key not in visited:
                    yield from self._through_lb(lb, target, fwd.port_out, protocol, dst, steps, depth + 1, visited | {target.key})

    def _set_preserve(self, fwd: _Fwd) -> None:
        """Does the backend see the client's IP (NLB) or the LB's (ALB proxy)?"""
        if fwd.lb.lb_type != "network":
            fwd.preserve = False
            return
        tg = fwd.tg
        if tg is None:
            fwd.preserve = None
        elif tg.preserve_client_ip is not None:
            fwd.preserve = tg.preserve_client_ip
            fwd.notes.append(f"{tg.label} preserve_client_ip = {str(tg.preserve_client_ip).lower()}")
        elif (tg.target_type or "").lower() == "instance":
            fwd.preserve = True
            fwd.notes.append(f"{tg.label}: instance targets preserve the client IP by default")
        elif (tg.target_type or "").lower() == "ip" and (tg.protocol or "").upper() in ("TCP", "TLS"):
            fwd.preserve = False
            fwd.notes.append(f"{tg.label}: ip targets over TCP/TLS do not preserve the client IP by default")
        elif (tg.target_type or "").lower() == "ip":
            fwd.preserve = True
            fwd.notes.append(f"{tg.label}: ip targets over UDP preserve the client IP by default")
        else:
            fwd.preserve = None

    def candidates(self, src: Endpoint, dst: Endpoint, protocol: str, port: PortRange | None) -> tuple[list[list], bool]:
        paths: list[list] = []
        if dst.kind == "lb":
            paths.extend([e] for e in self._lb_entries(src, dst, port, protocol))
        else:
            paths.append([_Net(src, dst, port)])
        lbs = sorted((e for e in self.facts.endpoints.values() if e.kind == "lb"), key=lambda e: e.key)
        truncated = False
        for lb in lbs:
            if lb.key in (dst.key, src.key) or not (self._lb_reaches(lb, dst) or self._lb_maybe_reaches(lb, dst)):
                continue
            for path in self._through_lb(src, lb, port, protocol, dst, [], 0, {lb.key}):
                if len(paths) >= MAX_CANDIDATES:
                    truncated = True
                    break
                paths.append(path)
        return paths, truncated

    # --- evaluation ---------------------------------------------------------------

    def analyze(self, source: str, destination: str, protocol: str = "tcp", port: str | int | None = None) -> ReachabilityResult:
        proto = normalize_protocol(protocol)
        if proto not in SUPPORTED_PROTOCOLS:
            raise EndpointError(f"unsupported protocol {protocol!r}; use tcp, udp, icmp, icmpv6 or -1 (all)")
        req_port = PortRange.parse(port) if port not in (None, "") else None
        if not has_ports(proto) and proto not in ("icmp", "icmpv6"):
            req_port = None
        src, dst = self.resolve(source), self.resolve(destination)
        if src.key == dst.key:
            raise EndpointError("source and destination are the same endpoint")
        paths, truncated = self.candidates(src, dst, proto, req_port)
        evaluated = [self._evaluate(path, src, dst, proto, req_port) for path in paths]
        chosen = self._choose(evaluated)
        return self._result(chosen, evaluated, src, dst, proto, req_port, truncated, source, destination)

    def _evaluate(self, steps: list, src: Endpoint, dst: Endpoint, protocol: str, port: PortRange | None) -> CandidatePath:
        hops: list[ReachabilityHop] = []
        checks: list[ReachabilityCheck] = []
        for i, step in enumerate(steps, 1):
            if isinstance(step, _Net):
                hop_checks = self._eval_net(step, i, protocol)
                hop = ReachabilityHop(
                    i, "network", step.src.display, step.dst.display, protocol, step.port, step.port,
                    f"{step.src.display} -> {fmt_traffic(protocol, step.port)} -> {step.dst.display}"
                    + (f" (listener {_listener_text(step.listener, step.dst)})" if step.listener else ""),
                    step.src.node_id, step.dst.node_id,
                    [n for n in (step.src.node_id, step.dst.node_id, step.listener.key if step.listener else None) if n],
                )
            else:
                hop_checks = self._eval_fwd(step, i, protocol)
                tg_label = step.tg.label if step.tg else (step.forward.unresolved if step.forward else "no target group")
                hop = ReachabilityHop(
                    i, "forward", step.lb.display, f"target group {tg_label}", protocol, step.port_in, step.port_out,
                    f"listener {_listener_text(step.listener, step.lb)} -> target group {tg_label}"
                    + (f" -> port {step.port_out}" if step.port_out else ""),
                    step.lb.node_id, step.tg.key if step.tg else None,
                    [n for n in (step.listener.key, step.tg.key if step.tg else None) if n and n in self.graph.nodes],
                )
            hop.status = combine(c.status for c in hop_checks)
            hop.context = self._context(step, src, dst, protocol, port)
            hops.append(hop)
            checks.extend(hop_checks)
        return CandidatePath(self._path_label(steps, protocol), hops, checks, combine(c.status for c in checks))

    def _context(self, step, src: Endpoint, dst: Endpoint, protocol: str, original: PortRange | None) -> TrafficContext:
        a, b = (step.src, step.dst) if isinstance(step, _Net) else (step.lb, None)
        port = step.port if isinstance(step, _Net) else step.port_out
        return TrafficContext(
            protocol, a.display, b.display if b else f"target group {step.tg.label if step.tg else '?'}", port, original,
            [str(x) for x in self._addrs(a) or []] or None,
            ([str(x) for x in self._addrs(b) or []] or None) if b else None,
            list(a.sgs), list(b.sgs) if b else [],
        )

    def _path_label(self, steps: list, protocol: str) -> str:
        parts = [steps[0].src.display] if isinstance(steps[0], _Net) else [steps[0].lb.display]
        for step in steps:
            if isinstance(step, _Net):
                listener = f" (listener {_listener_text(step.listener, step.dst)})" if step.listener else ""
                parts.append(f"{fmt_traffic(protocol, step.port)} -> {step.dst.display}{listener}")
            else:
                tg = step.tg.label if step.tg else "?"
                parts.append(f"target group {tg}" + (f" (port {step.port_out})" if step.port_out else " (port ?)"))
        return " -> ".join(parts)

    @staticmethod
    def _check(check_type, status, src, dst, reason, evidence=None, suggestion=None, hop=None, resources=None) -> ReachabilityCheck:
        resources = list(dict.fromkeys(r for r in resources or [] if r))
        evidence = list(dict.fromkeys(e for e in evidence or [] if e))
        return ReachabilityCheck(check_type, status, src, dst, reason, evidence, suggestion, hop, resources)

    # network hop ------------------------------------------------------------------

    def _eval_net(self, step: _Net, hop: int, protocol: str) -> list[ReachabilityCheck]:
        a, b = step.src, step.dst
        checks: list[ReachabilityCheck] = []
        traffic = fmt_traffic(protocol, step.port)

        def add(check_type, status, reason, evidence=None, suggestion=None, resources=None):
            checks.append(self._check(check_type, status, a.display, b.display, reason, evidence, suggestion, hop, resources))

        if b.kind == "lb":
            listeners = self.facts.listeners_of(b.key)
            existing = [_listener_text(li, b) for li in listeners]
            if step.listener_state == "match":
                add("listener", A, f"{b.display} has a listener on {_listener_text(step.listener, b)}",
                    [f"listener {step.listener.label}: {_listener_text(step.listener, b)}"], resources=[step.listener.key])
            elif step.listener_state == "unknown":
                add("listener", U, f"listener port of {b.display} is unresolved", [f"listener {step.listener.label}: port unknown"],
                    f"Resolve the listener port of {b.display}.", resources=[step.listener.key])
            else:
                listing = f"; existing listeners: {', '.join(existing)}" if existing else "; no listeners found in the scanned data"
                add("listener", B, f"{b.display} has no listener for {traffic}{listing}",
                    [f"listeners on {b.label}: {', '.join(existing) or 'none'}"],
                    f"Check whether {b.display} should listen on {traffic}, or use one of its existing listener ports.",
                    resources=[b.node_id])
        if not b.accepts_inbound:
            if step.via_lb is not None:
                add("lambda_target", A,
                    f"{step.via_lb.display} invokes {b.display} through the Lambda service; no network path to the function is involved",
                    [f"target group target: {b.label} (target_type lambda)"],
                    resources=[b.node_id])
            else:
                add("inbound", B, f"{b.display} does not accept inbound network connections; Lambda is invoked via an API "
                                  "(ALB target group, API Gateway, SDK), not by connecting to it",
                    [f"{b.label}: resource type lambda"], "Reach the function through an ALB target group or API Gateway.",
                    resources=[b.node_id])
            return checks

        a_ext = a.external or not a.in_vpc
        b_ext = b.external or not b.in_vpc
        if a_ext and b_ext:
            if a.kind == "lambda" and b.external and not a.in_vpc:
                add("route", A, f"{a.display} is not attached to a VPC; it runs in the AWS-managed Lambda network, which has "
                                "internet egress", [f"{a.label}: no vpc_config"], resources=[a.node_id])
            else:
                add("route", U, "both ends are outside every known VPC; the network between them is not modelled",
                    suggestion="Choose a source or destination inside a scanned VPC.")
            return checks
        if a_ext:
            checks.extend(self._inbound_from_outside(step, hop, protocol))
        elif b_ext:
            checks.extend(self._outbound(step, hop, protocol))
        else:
            checks.extend(self._intra_vpc_routes(step, hop))
        checks.extend(self._nacl_checks(step, hop, protocol))
        checks.extend(self._sg_checks(step, hop, protocol))
        return checks

    def _unknown_subnets(self, ep: Endpoint) -> str | None:
        if ep.external or not ep.in_vpc:
            return None
        if not ep.subnets:
            return f"subnets of {ep.display} are unknown ({'; '.join(ep.subnets_unresolved) or 'none recorded'})"
        return None

    def _inbound_from_outside(self, step: _Net, hop: int, protocol: str) -> list[ReachabilityCheck]:
        a, b = step.src, step.dst
        out: list[ReachabilityCheck] = []

        def add(check_type, status, reason, evidence=None, suggestion=None, resources=None):
            out.append(self._check(check_type, status, a.display, b.display, reason, evidence, suggestion, hop, resources))

        public_src = a.kind == "internet" or not a.in_vpc and not a.external or any(not is_private(x) for x in a.addresses or [])
        if not public_src:
            add("exposure", U,
                f"{a.display} is a private address outside every known VPC; VPN/Direct Connect/peering paths are not evaluated")
            return out
        if b.kind == "lb":
            if b.internal is True:
                add("exposure", B, f"{b.display} is an internal load balancer; it has no public address", [b.public_ip_evidence],
                    f"Use an internet-facing load balancer or reach {b.display} from inside the VPC.", resources=[b.node_id])
            elif b.internal is None:
                add("exposure", U, f"scheme of {b.display} (internal / internet-facing) is unknown", [b.public_ip_evidence],
                    resources=[b.node_id])
            else:
                add("exposure", A, f"{b.display} is internet-facing", [b.public_ip_evidence], resources=[b.node_id])
        elif b.public_ip is True:
            add("exposure", A, f"{b.display} has a public IP address", [b.public_ip_evidence], resources=[b.node_id])
        elif b.public_ip is False:
            add("exposure", B, f"{b.display} has no public IP address, so it cannot be reached directly from the internet",
                [b.public_ip_evidence], f"Put a load balancer in front of {b.display} or give it a public IP (if that is intended).",
                resources=[b.node_id])
        else:
            add("exposure", U, f"whether {b.display} has a public IP address is unknown", [b.public_ip_evidence or "no data"],
                resources=[b.node_id])
        missing = self._unknown_subnets(b)
        if missing:
            add("route_return", U, missing)
            return out
        statuses, evidence, resources = [], [], []
        for s, _addr in self._subnet_addrs(b)[:MAX_PAIRS]:
            for client in a.addresses or [INTERNET_V4]:
                look = lookup(self.facts, s, client)
                evidence.append(look.evidence(self.facts))
                resources += [s, look.table.key if look.table else None]
                if look.table is None:
                    statuses.append(U)
                elif look.route is None:
                    statuses.append(B)
                elif look.route.state == "blackhole":
                    statuses.append(B)
                elif look.route.target_type == "internet_gateway":
                    statuses.append(A)
                elif look.route.target_type in ("nat_gateway", "egress_only_gateway", "local"):
                    statuses.append(B)
                else:
                    statuses.append(U)
        status = combine(statuses)
        reasons = {
            A: f"replies from {b.display} to {a.display} route to an internet gateway (subnet is PUBLIC)",
            B: f"replies from {b.display} to {a.display} do not route to an internet gateway (subnet is PRIVATE or has no route)",
            U: f"cannot determine how replies from {b.display} reach {a.display}",
        }
        add("route_return", status, reasons[status], evidence,
            None if status == A else f"Check the route tables of {b.display}'s subnets for a route to an internet gateway.",
            resources=resources)
        return out

    def _nat_status(self, nat_key: str | None) -> tuple[CheckStatus, str, list[str]]:
        nat = self.facts.nat_gateways.get(nat_key or "")
        label = self.facts.label(nat_key)
        if nat is None:
            return U, f"NAT gateway {label} is not in the scanned data", []
        if nat.get("connectivity_type") == "private":
            return B, f"NAT gateway {label} is a private NAT gateway (no internet access)", [f"{label} connectivity_type = private"]
        if nat.get("state") not in (None, "available", "pending"):
            return B, f"NAT gateway {label} is in state {nat['state']}", [f"{label} state = {nat['state']}"]
        if nat.get("subnet") is None:
            return U, f"subnet of NAT gateway {label} is unknown", []
        cls = classify_subnet(self.facts, nat["subnet"])
        ev = [f"{label} is in {cls['label']}: {cls['classification']}"] + cls["evidence"]
        if cls["classification"] == "PUBLIC":
            return A, f"NAT gateway {label} sits in a PUBLIC subnet", ev
        if cls["classification"] == "PRIVATE":
            return B, f"NAT gateway {label} sits in a PRIVATE subnet (no internet gateway route)", ev
        return U, f"cannot classify the subnet of NAT gateway {label}", ev

    def _outbound(self, step: _Net, hop: int, protocol: str) -> list[ReachabilityCheck]:
        a, b = step.src, step.dst
        out: list[ReachabilityCheck] = []
        missing = self._unknown_subnets(a)
        if missing:
            out.append(self._check("route", U, a.display, b.display, missing, hop=hop))
            return out
        statuses, evidence, resources = [], [], []
        private_dest = all(is_private(x) for x in b.addresses or [INTERNET_V4])
        for s, _addr in self._subnet_addrs(a)[:MAX_PAIRS]:
            for dest in b.addresses or [INTERNET_V4]:
                look = lookup(self.facts, s, dest)
                evidence.append(look.evidence(self.facts))
                resources += [s, look.table.key if look.table else None]
                route = look.route
                if look.table is None:
                    statuses.append(U)
                elif route is None or route.state == "blackhole":
                    statuses.append(B)
                elif route.target_type == "internet_gateway":
                    if private_dest:
                        statuses.append(U)
                    elif a.public_ip is True:
                        statuses.append(A)
                        evidence.append(a.public_ip_evidence)
                    elif a.public_ip is False:
                        statuses.append(B)
                        evidence.append(f"{a.public_ip_evidence} -> traffic via the internet gateway needs a public IP")
                    else:
                        statuses.append(U)
                        evidence.append(f"public IP of {a.display} unknown")
                elif route.target_type == "egress_only_gateway":
                    statuses.append(A if dest.version == 6 else B)
                elif route.target_type == "nat_gateway":
                    st, why, ev = self._nat_status(route.target)
                    statuses.append(st)
                    evidence += [why] + ev
                    resources.append(route.target)
                elif route.target_type == "vpc_peering":
                    statuses.append(U)
                else:
                    statuses.append(U)
        status = combine(statuses)
        reasons = {
            A: f"{a.display} has an internet path to {b.display}",
            B: f"no working route from {a.display} to {b.display}",
            U: f"cannot prove a route from {a.display} to {b.display}",
        }
        suggestion = None if status == A else f"Check the route tables of {a.display}'s subnets (default route, NAT gateway, public IP)."
        out.append(self._check("route", status, a.display, b.display, reasons[status], evidence, suggestion, hop, resources))
        return out

    def _route_leg(self, src: Endpoint, dst: Endpoint, hop: int, check_type: str) -> ReachabilityCheck:
        missing = self._unknown_subnets(src) or self._unknown_subnets(dst)
        if missing:
            return self._check(check_type, U, src.display, dst.display, missing, hop=hop)
        dest_addrs = self._addrs(dst)
        if dest_addrs is None:
            return self._check(check_type, U, src.display, dst.display, f"address range of {dst.display} is unknown", hop=hop)
        statuses, evidence, resources, notes = [], [], [], []
        for s, _a in self._subnet_addrs(src)[:MAX_PAIRS]:
            sub_vpc = self.facts.subnets[s].vpc if s in self.facts.subnets else src.vpc
            for dest in dest_addrs[:MAX_PAIRS]:
                look = lookup(self.facts, s, dest)
                resources += [s, look.table.key if look.table else None]
                local = in_vpc(self.facts, sub_vpc, dest)
                if look.table is None:
                    if local:
                        statuses.append(A)
                        evidence.append(f"{self.facts.label(s)}: route table unknown; {dest} is inside the VPC CIDR so the implicit "
                                        "local route applies")
                        notes.append(f"{self.facts.label(s)} route table unknown; relied on the VPC local route")
                    else:
                        statuses.append(U)
                        evidence.append(look.evidence(self.facts))
                    continue
                evidence.append(look.evidence(self.facts))
                route = look.route
                if route is None or route.state == "blackhole":
                    statuses.append(B)
                elif route.target_type == "local":
                    statuses.append(A)
                elif route.target_type == "vpc_peering" and not local:
                    statuses.append(A)
                    notes.append(f"{route.describe()}: VPC peering; the peer VPC's route back is checked on the return leg")
                else:
                    statuses.append(U)
                    notes.append(f"{route.describe()}: traffic is steered to {route.target_type}; forwarding beyond it is not evaluated")
        status = combine(statuses)
        word = "replies from" if check_type == "route_return" else "traffic from"
        reasons = {
            A: f"{word} {src.display} to {dst.display} is routable (" + ("local VPC route" if not notes else "; ".join(notes)) + ")",
            B: f"{word} {src.display} to {dst.display} has no usable route (missing or blackhole)",
            U: f"cannot prove a route for {word} {src.display} to {dst.display}" + (f": {'; '.join(notes)}" if notes else ""),
        }
        return self._check(check_type, status, src.display, dst.display, reasons[status], evidence,
                           None if status == A else f"Check the route tables of {src.display}'s subnets.", hop, resources)

    def _intra_vpc_routes(self, step: _Net, hop: int) -> list[ReachabilityCheck]:
        return [self._route_leg(step.src, step.dst, hop, "route"), self._route_leg(step.dst, step.src, hop, "route_return")]

    def _nacl_checks(self, step: _Net, hop: int, protocol: str) -> list[ReachabilityCheck]:
        a, b = step.src, step.dst
        if self._unknown_subnets(a) or self._unknown_subnets(b):
            return [self._check("nacl", U, a.display, b.display, "subnets unknown; network ACLs cannot be evaluated", hop=hop)]
        required = sg_eval.request_intervals(protocol, step.port)
        if protocol in ("icmp", "icmpv6"):
            reply = [(ICMP_ECHO_REPLY, ICMP_ECHO_REPLY)] if (step.port is None or step.port.lo == ICMP_ECHO_REQUEST) else [ALL_PORTS]
        elif protocol == "all":
            reply = [ALL_PORTS]
        else:
            reply = [EPHEMERAL_PORTS]
        legs = {  # check_type -> list of (status, evidence, detail)
            "nacl_egress": [], "nacl_ingress": [], "nacl_return_egress": [], "nacl_return_ingress": [],
        }
        resources: list[str | None] = []
        pairs = [(sa, aa, sb, ab) for sa, aa in self._subnet_addrs(a) for sb, ab in self._subnet_addrs(b)][:MAX_PAIRS]
        crossing = [(sa, aa, sb, ab) for sa, aa, sb, ab in pairs if not (sa is not None and sa == sb)]
        if not crossing:
            return [self._check("nacl", NA, a.display, b.display,
                                "source and destination share the subnet; network ACLs only apply at subnet boundaries", hop=hop)]

        def run(leg, subnet, direction, ports, peer, partial, peer_ep):
            nacl_key, how = self.facts.effective_nacl(subnet)
            acl = self.facts.nacls.get(nacl_key or "")
            resources.extend([subnet, nacl_key])
            if acl is None:
                legs[leg].append((U, [f"{self.facts.label(subnet)}: {how}"], "no NACL data"))
                return
            v = nacl_eval.evaluate(acl, direction, protocol, ports, peer, partial_is_unknown=partial,
                                   peer_is_internet=peer_ep.kind == "internet")
            if not acl.complete and v.status == B:
                v.status = U
            legs[leg].append((v.status, [f"{self.facts.label(subnet)} uses {acl.label} ({how})"] + v.evidence, v.detail))

        for sa, aa, sb, ab in crossing:
            if sa is not None:
                run("nacl_egress", sa, "egress", required, ab, False, b)
                run("nacl_return_ingress", sa, "ingress", reply, ab, True, b)
            if sb is not None:
                run("nacl_ingress", sb, "ingress", required, aa, False, a)
                run("nacl_return_egress", sb, "egress", reply, aa, True, a)
        texts = {
            "nacl_egress": (a, b, f"{a.display} subnet NACL egress {fmt_traffic(protocol, step.port)} to {b.display}"),
            "nacl_ingress": (a, b, f"{b.display} subnet NACL ingress {fmt_traffic(protocol, step.port)} from {a.display}"),
            "nacl_return_egress": (b, a, f"{b.display} subnet NACL egress for replies to {a.display} (ephemeral ports, stateless)"),
            "nacl_return_ingress": (b, a, f"{a.display} subnet NACL ingress for replies from {b.display} (ephemeral ports, stateless)"),
        }
        out = []
        for leg, results in legs.items():
            if not results:
                continue
            status = combine(s for s, _e, _d in results)
            src_ep, dst_ep, text = texts[leg]
            details = sorted({d for s, _e, d in results if s == status and d})
            evidence = [e for _s, ev, _d in results for e in ev]
            verb = {A: "allows", B: "blocks", U: "cannot be proven for"}[status]
            reason = f"{text}: {verb}" + (f" ({'; '.join(details)})" if details and status != A else "")
            suggestion = None if status == A else (
                f"Check the network ACL rules ({leg.replace('_', ' ')}); NACLs are stateless and need rules in both directions."
            )
            out.append(self._check(leg, status, src_ep.display, dst_ep.display, reason, evidence, suggestion, hop, resources))
        return out

    def _sg_checks(self, step: _Net, hop: int, protocol: str) -> list[ReachabilityCheck]:
        a, b = step.src, step.dst
        out: list[ReachabilityCheck] = []
        sg_res = lambda ep: [s for s in ep.sgs if s in self.graph.nodes]  # noqa: E731
        if not (a.external or not a.in_vpc):
            if a.sg_applicable:
                v = sg_eval.evaluate(self.facts, owner_label=a.display, sg_keys=a.sgs, sg_unresolved=a.sgs_unresolved,
                                     direction="egress", protocol=protocol, port=step.port, peer=self._peer(b))
                out.append(self._check("security_group_egress", v.status, a.display, b.display, v.reason, v.evidence,
                                       v.suggestion, hop, sg_res(a)))
            else:
                out.append(self._check("security_group_egress", NA, a.display, b.display, f"{a.display} has no security groups", hop=hop))
        if not (b.external or not b.in_vpc):
            if b.sg_applicable:
                clients = [a] if not (step.via_lb and step.via_lb.lb_type == "network") else (
                    [step.client] if step.preserve is True else [a] if step.preserve is False else [a, step.client]
                )
                verdicts = [
                    sg_eval.evaluate(self.facts, owner_label=b.display, sg_keys=b.sgs, sg_unresolved=b.sgs_unresolved,
                                     direction="ingress", protocol=protocol, port=step.port, peer=self._peer(c))
                    for c in clients if c is not None
                ]
                v = verdicts[0]
                if len({x.status for x in verdicts}) > 1:
                    v = sg_eval.Verdict(U, f"{b.display} ingress depends on whether the NLB preserves the client IP (unknown): "
                                           + " / ".join(x.reason for x in verdicts),
                                        [e for x in verdicts for e in x.evidence])
                out.append(self._check("security_group_ingress", v.status, a.display, b.display, v.reason, v.evidence,
                                       v.suggestion, hop, sg_res(b)))
            else:
                out.append(self._check("security_group_ingress", NA, a.display, b.display,
                                       f"{b.display} has no security groups (e.g. NLB without SGs); not applicable", hop=hop))
        if out:
            out.append(self._check("security_group_return", NA, b.display, a.display,
                                   "security groups are stateful: replies to an allowed connection are permitted automatically "
                                   "(no reverse rule needed)", hop=hop))
        return out

    # forward hop ------------------------------------------------------------------

    def _eval_fwd(self, step: _Fwd, hop: int, protocol: str) -> list[ReachabilityCheck]:
        lb, li = step.lb, step.listener
        out: list[ReachabilityCheck] = []
        ltext = _listener_text(li, lb)

        def add(check_type, status, reason, evidence=None, suggestion=None, resources=None, dst=None):
            out.append(self._check(check_type, status, lb.display, dst or (f"target group {step.tg.label}" if step.tg else "?"),
                                   reason, evidence, suggestion, hop, resources))

        if step.forward is None:
            types = [t for t in li.action_types if t] or ["unknown"]
            if not li.actions_known or types == ["unknown"]:
                add("listener_action", U, f"actions of listener {ltext} on {lb.display} are unknown", [f"listener {li.label}"],
                    f"Resolve the default action of listener {li.label}.", [li.key])
            else:
                add("listener_action", B,
                    f"listener {ltext} on {lb.display} does not forward to a target group (action: {', '.join(types)})",
                    [f"listener {li.label} actions: {', '.join(types)}"],
                    f"Check whether listener {ltext} should forward to the destination's target group.", [li.key])
            return out
        if step.forward.target_group is None:
            add("listener_action", U, f"listener {ltext} forwards to an unresolved target group ({step.forward.unresolved})",
                [step.forward.origin], "Provide Terraform state or scan AWS so the target group can be resolved.", [li.key])
            return out
        if step.tg is None:
            add("listener_action", U, f"target group {self.facts.label(step.forward.target_group)} is not in the scanned data",
                [step.forward.origin], resources=[li.key])
            return out
        tg, binding = step.tg, step.binding
        add("listener_action", A, f"listener {ltext} forwards to target group {tg.label}", [step.forward.origin],
            resources=[li.key, tg.key])
        target = self._endpoint(binding.target) if binding else None
        target_label = target.display if target else self.facts.label(binding.target if binding else None)
        add("target_registration", A, f"{target_label} is registered with target group {tg.label}", [binding.origin],
            resources=[tg.key, binding.target], dst=target_label)

        if (tg.target_type or "").lower() == "lambda":
            add("target_port", NA, "Lambda targets have no port", [f"{tg.label} target_type = lambda"], dst=target_label)
            return out
        evidence = []
        if tg.port is not None:
            evidence.append(f"target group {tg.label} port {tg.port} ({tg.protocol or '?'})")
        if binding.port is not None:
            who = f"container {binding.container_name}:" if binding.container_name else "port "
            evidence.append(f"{binding.origin} registers {who}{binding.port}")
            if tg.port is not None and tg.port != binding.port:
                evidence.append(f"registered target port {binding.port} overrides the target group default port {tg.port}")
        td = self.facts.task_definitions.get(target.extra.get("task_definition") or "") if target else None
        network_mode = (td or {}).get("network_mode")
        if target and target.kind == "ecs_service" and network_mode in ("bridge", None) and (tg.target_type or "") == "instance":
            host_ports = [m.get("host_port") for m in (td or {}).get("port_mappings") or [] if m.get("container_port") == binding.port]
            if not host_ports or any(hp in (None, 0) for hp in host_ports):
                add("target_port", U, f"{target_label} uses bridge networking with a dynamic host port; the port traffic arrives on is "
                                      "chosen at runtime", evidence + [f"task definition network_mode = {network_mode or 'unknown'}"],
                    "Security groups must allow the ECS dynamic port range (32768-65535) from the load balancer.", dst=target_label)
                return out
        if step.port_out is None:
            add("target_port", U, f"target port for {target_label} is unknown (no target group port or registered container port)",
                evidence or [f"target group {tg.label}: port unresolved"],
                f"Provide the target group port / container port for {target_label}.", [tg.key], dst=target_label)
            return out
        add("target_port", A, f"port transition: listener {li.port} -> target port {step.port_out}", evidence, resources=[tg.key],
            dst=target_label)
        if target and target.kind == "ecs_service" and td is not None:
            mappings = td.get("port_mappings")
            if mappings is None:
                add("container_port", NA, f"task definition port mappings of {target_label} are not available; relying on the "
                                          f"service's registered container port {step.port_out}", [td.get("label", "")], dst=target_label)
            else:
                ports = sorted({m.get("container_port") for m in mappings if m.get("container_port") is not None})
                if step.port_out.lo in ports:
                    add("container_port", A, f"task definition exposes container port {step.port_out}",
                        [f"{td.get('label')}: portMappings containerPort {', '.join(map(str, ports))}"], dst=target_label)
                else:
                    add("container_port", B, f"task definition does not expose container port {step.port_out} "
                                             f"(exposed: {', '.join(map(str, ports)) or 'none'})",
                        [f"{td.get('label')}: portMappings {ports or 'none'}"],
                        f"Check the containerPort mappings of {td.get('label')} against the load balancer binding.", dst=target_label)
        if step.notes:
            out[-1].evidence.extend(step.notes)
        return out

    # --- selection & result --------------------------------------------------------

    @staticmethod
    def _progress(c: CandidatePath) -> tuple:
        blocking = c.first_blocking
        passed = sum(1 for x in c.checks if x.status == A)
        return (blocking.hop_index if blocking else 99, passed)

    def _choose(self, evaluated: list[CandidatePath]) -> CandidatePath:
        allowed = [c for c in evaluated if c.status == A]
        if allowed:
            return min(allowed, key=lambda c: (len(c.hops), c.label))
        unknown = [c for c in evaluated if c.status == U]
        if unknown:
            return max(unknown, key=lambda c: (self._progress(c), -len(c.hops)))
        return max(evaluated, key=lambda c: (self._progress(c), -len(c.hops)))

    def _candidate_summary(self, cand: CandidatePath, chosen: CandidatePath, dst: Endpoint) -> dict:
        """Summary of one candidate for the result.

        Presentation only (selection already happened): when the chosen path reaches a
        destination without a public IP privately through a load balancer, the direct
        internet -> destination candidate's "no public IP" exposure check does not apply
        to how the traffic flows, so it is reported NOT_APPLICABLE rather than a failure.
        """
        summary = dict(cand.summary(), chosen=cand is chosen)
        via = next((h.from_label for h in chosen.hops if h.kind == "forward"), None)
        if cand is chosen or via is None or dst.kind == "lb" or dst.public_ip is not False or len(cand.hops) != 1:
            return summary
        for i, c in enumerate(cand.checks):
            if c.check_type == "exposure" and c.status == B and c.destination == dst.display:
                reason = f"{dst.display} public IP not required for this path: it is reached privately through {via}"
                cand.checks[i] = self._check("exposure", NA, c.source, c.destination, reason, c.evidence, None,
                                             c.hop_index, c.resources)
                summary.update(status=NA.value, reason=reason)
        return summary

    def _result(self, chosen, evaluated, src, dst, protocol, port, truncated, source_ref, dest_ref) -> ReachabilityResult:
        status = chosen.status
        result = ReachabilityResult(
            source=source_ref, destination=dest_ref, protocol=protocol, port=port, overall_status=status,
            path=chosen.hops, checks=chosen.checks, source_node=src.node_id, destination_node=dst.node_id,
            path_label=chosen.label,
            limits={"max_candidates": MAX_CANDIDATES, "max_lb_hops": MAX_LB_HOPS, "evaluated_candidates": len(evaluated),
                    "truncated": int(truncated)},
        )
        result.candidates = [self._candidate_summary(c, chosen, dst) for c in evaluated]
        decisive = chosen.first_blocking if status == B else chosen.first_unknown if status == U else None
        if decisive is not None:
            hop = chosen.hops[decisive.hop_index - 1] if decisive.hop_index else None
            where = f"hop {hop.index} ({hop.from_label} -> {hop.to_label}): " if hop else ""
            result.blocked_at = where + decisive.check_type
            result.reason = decisive.reason
        else:
            required = [c for c in chosen.checks if c.status != NA]
            result.reason = f"all {len(required)} required checks passed on {chosen.label}"
        seen: set[str] = set()
        for c in chosen.checks:
            for e in c.evidence:
                if e and e not in seen:
                    seen.add(e)
                    result.evidence.append(e)
        result.suggestions = list(dict.fromkeys(c.suggestion for c in chosen.checks if c.suggestion and c.status in (B, U)))
        uncertainties = [c.reason for c in chosen.checks if c.status == U]
        endpoints = [src, dst] + [h for h in (self._endpoint(n) for hop in chosen.hops for n in (hop.from_node, hop.to_node) if n) if h]
        for ep in endpoints:
            uncertainties += ep.notes
            for sg in ep.sgs:
                if sg in self.facts.security_groups:
                    uncertainties += self.facts.security_groups[sg].notes
        uncertainties += self.facts.orphan_sg_rules
        if any(h.kind == "forward" for h in chosen.hops):
            uncertainties.append("target health (registered targets passing health checks) is runtime state and is not evaluated")
            if any("rule" in (c.evidence[0] if c.evidence else "") and c.check_type == "listener_action" for c in chosen.checks):
                uncertainties.append("listener rule conditions (host/path/header) are not evaluated; only matching requests are forwarded")
        if dst.kind == "lambda" and status == A:
            uncertainties.append("Lambda resource-based permissions (IAM) are not evaluated")
        result.uncertainties = list(dict.fromkeys(u for u in uncertainties if u))
        subnet_keys: list[str] = []
        for ep in endpoints:
            subnet_keys += [s for s in ep.subnets if s not in subnet_keys]
        result.subnets = [classify_subnet(self.facts, s) for s in subnet_keys if s in self.facts.subnets]
        if src.node_id and dst.node_id:
            result.topology_connected = shortest_path(self.graph, src.node_id, dst.node_id, directed=False) is not None
        return result

    def traffic_context(self, source: str, destination: str, protocol: str, port) -> TrafficContext:
        """TrafficContext for the first hop (exposed for API/UI consumers)."""
        src, dst = self.resolve(source), self.resolve(destination)
        p = PortRange.parse(port) if port not in (None, "") else None
        return TrafficContext(
            normalize_protocol(protocol) or protocol, src.display, dst.display, p, p,
            [str(a) for a in self._addrs(src) or []] or None, [str(a) for a in self._addrs(dst) or []] or None,
            list(src.sgs), list(dst.sgs),
        )


def analyze(graph: Graph, source: str, destination: str, protocol: str = "tcp", port: str | int | None = None) -> ReachabilityResult:
    return ReachabilityEngine(graph).analyze(source, destination, protocol, port)
