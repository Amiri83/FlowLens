"""Normalize the FlowLens graph into network facts the evaluators consume.

The graph stores raw resource attributes from two vocabularies that were
deliberately aligned upstream: Terraform (desired_state) and read-only AWS
discovery (actual_state). For reachability the *runtime* view wins: a node's
actual_state is used when present, otherwise its desired_state.

Anything that cannot be resolved to a concrete value (a `var.x` reference, a
dynamic block, a resource that was never scanned) is recorded as unresolved
instead of being guessed, so evaluators can return UNKNOWN.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from flowlens.ids import make_node_id
from flowlens.linking.linker import LOAD_BALANCER_TYPES, Resolver
from flowlens.models.graph import Graph, Node
from flowlens.reachability.netutil import (
    Interval,
    IPNetwork,
    normalize_protocol,
    parse_cidr,
    rule_port_interval,
)

_LITERAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-:/.]*$")
_TF_EXPRESSION = re.compile(r"\$\{|^(var|local|module|data)\.")

SG_TYPES = ("security_group", "default_security_group")
RT_TYPES = ("route_table", "default_route_table")
NACL_TYPES = ("network_acl", "default_network_acl")
WORKLOAD_TYPES = ("ecs_service", "lambda", "instance", "db_instance")


def _nice_name(node: Node) -> str | None:
    state, _ = _state(node)
    tags = state.get("tags") if isinstance(state.get("tags"), dict) else {}
    for value in (tags.get("Name"), state.get("name"), state.get("function_name"), state.get("identifier")):
        if isinstance(value, str) and value and "${" not in value:
            return value
    return None


def node_label(node: Node) -> str:
    """Human label. AWS-discovered: cloud id plus name ("sg-0abc (web)").
    Terraform config-only: the resource's name/Name tag, else its address.
    """
    nice = _nice_name(node)
    if node.id.startswith("tf:"):
        return nice or node.terraform_address or node.id
    ident = node.id.split(":", 1)[-1]
    if node.aws_arn and ident == node.aws_arn:
        return nice or node.name or ident
    if nice and nice != ident:
        return f"{ident} ({nice})"
    return ident


def _state(node: Node) -> tuple[dict[str, Any], str]:
    if node.actual_state is not None:
        return node.actual_state, "aws"
    return node.desired_state or {}, "terraform"


def _block(value) -> dict[str, Any] | None:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    if isinstance(value, dict):
        return value
    return None


def _blocks(value) -> list[dict[str, Any]] | None:
    """A list of nested blocks; None when the value is an unresolvable expression."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return None


def _as_list(value) -> list | None:
    """Normalize a list-valued attribute. None if it is an unresolved expression."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str) and _TF_EXPRESSION.search(value):
        return None
    return [value]


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


# --- fact types ---------------------------------------------------------------


@dataclass
class SGRule:
    direction: str  # "ingress" | "egress"
    protocol: str | None  # canonical, None = unresolved
    ports: Interval | None  # None = unresolved
    cidrs: list[IPNetwork] = field(default_factory=list)
    sg_refs: list[str] = field(default_factory=list)
    self_ref: bool = False
    prefix_lists: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    origin: str = ""

    def describe(self, labels: dict[str, str] | None = None) -> str:
        proto = "ALL" if self.protocol == "all" else (self.protocol or "?").upper()
        if self.protocol == "all" or self.ports is None:
            port = "" if self.protocol == "all" else "/?"
        elif self.ports == (0, 65535):
            port = "/0-65535"
        else:
            port = f"/{self.ports[0]}" if self.ports[0] == self.ports[1] else f"/{self.ports[0]}-{self.ports[1]}"
        peers = [str(c) for c in self.cidrs]
        peers += [(labels or {}).get(s, s.split(":", 1)[-1]) for s in self.sg_refs]
        if self.self_ref:
            peers.append("self")
        peers += self.prefix_lists + self.unresolved
        word = "from" if self.direction == "ingress" else "to"
        return f"{self.direction} {proto}{port} {word} {', '.join(peers) or 'nothing'}"


@dataclass
class SecurityGroup:
    key: str
    label: str
    vpc: str | None
    ingress: list[SGRule] = field(default_factory=list)
    egress: list[SGRule] = field(default_factory=list)
    #: False when some rules could not be read (dynamic blocks, expressions).
    complete: bool = True
    notes: list[str] = field(default_factory=list)
    source: str = "terraform"


@dataclass
class Route:
    destination: IPNetwork | None
    destination_raw: str
    target_type: str  # local, internet_gateway, nat_gateway, transit_gateway, vpc_peering, ...
    target: str | None  # node id or raw id
    target_label: str
    state: str = "active"
    origin: str = ""
    implicit: bool = False

    def describe(self) -> str:
        suffix = " (blackhole)" if self.state == "blackhole" else ""
        return f"{self.destination_raw} -> {self.target_label}{suffix}"


@dataclass
class RouteTable:
    key: str
    label: str
    vpc: str | None
    is_main: bool = False
    routes: list[Route] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Subnet:
    key: str
    label: str
    vpc: str | None
    cidrs: list[IPNetwork] = field(default_factory=list)
    cidr_unresolved: bool = False
    map_public_ip: bool | None = None


@dataclass
class Vpc:
    key: str
    label: str
    cidrs: list[IPNetwork] = field(default_factory=list)


@dataclass
class NaclRule:
    rule_no: int | None
    action: str | None  # "allow" | "deny"
    protocol: str | None
    cidr: IPNetwork | None
    ports: Interval | None
    icmp_type: int | None = None
    origin: str = ""
    unresolved: bool = False

    def describe(self) -> str:
        proto = "ALL" if self.protocol == "all" else (self.protocol or "?").upper()
        port = ""
        if self.protocol in ("tcp", "udp") and self.ports:
            port = f"/{self.ports[0]}" if self.ports[0] == self.ports[1] else f"/{self.ports[0]}-{self.ports[1]}"
        return f"rule {self.rule_no} {(self.action or '?').upper()} {proto}{port} {self.cidr or '?'}"


@dataclass
class Nacl:
    key: str
    label: str
    vpc: str | None
    is_default: bool = False
    subnets: list[str] = field(default_factory=list)
    ingress: list[NaclRule] = field(default_factory=list)
    egress: list[NaclRule] = field(default_factory=list)
    complete: bool = True


@dataclass
class Forward:
    target_group: str | None
    unresolved: str | None
    origin: str


@dataclass
class Listener:
    key: str
    label: str
    lb: str | None
    port: int | None
    protocol: str | None  # raw LB protocol (HTTP, HTTPS, TCP, ...)
    forwards: list[Forward] = field(default_factory=list)
    action_types: list[str] = field(default_factory=list)
    actions_known: bool = True


@dataclass
class TargetGroup:
    key: str
    label: str
    port: int | None
    protocol: str | None
    target_type: str | None
    vpc: str | None
    preserve_client_ip: bool | None = None


@dataclass
class Binding:
    """A target group -> backend registration and the port traffic arrives on."""

    target_group: str
    target: str
    port: int | None
    origin: str
    container_name: str | None = None


@dataclass
class Endpoint:
    key: str
    label: str
    kind: str  # internet, address, lb, ecs_service, lambda, instance, db_instance
    node_id: str | None = None
    vpc: str | None = None
    subnets: list[str] = field(default_factory=list)
    subnets_unresolved: list[str] = field(default_factory=list)
    sgs: list[str] = field(default_factory=list)
    sgs_unresolved: list[str] = field(default_factory=list)
    sg_applicable: bool = True
    #: Explicit addresses (instance private IP, external CIDR). None = derive
    #: from subnets.
    addresses: list[IPNetwork] | None = None
    public_ip: bool | None = None
    public_ip_evidence: str = ""
    external: bool = False
    in_vpc: bool = True
    accepts_inbound: bool = True
    lb_type: str | None = None
    internal: bool | None = None
    notes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def display(self) -> str:
        kind = {
            "internet": "",
            "address": "",
            "lb": {"network": "NLB ", "gateway": "GWLB "}.get(self.lb_type or "", "ALB "),
            "ecs_service": "ECS service ",
            "lambda": "Lambda ",
            "instance": "EC2 ",
            "db_instance": "RDS ",
        }.get(self.kind, "")
        return f"{kind}{self.label}"


@dataclass
class NetworkFacts:
    graph: Graph
    labels: dict[str, str] = field(default_factory=dict)
    vpcs: dict[str, Vpc] = field(default_factory=dict)
    subnets: dict[str, Subnet] = field(default_factory=dict)
    route_tables: dict[str, RouteTable] = field(default_factory=dict)
    subnet_route_table: dict[str, str] = field(default_factory=dict)
    main_route_table: dict[str, str] = field(default_factory=dict)
    security_groups: dict[str, SecurityGroup] = field(default_factory=dict)
    #: Separate SG rule resources whose target SG could not be resolved.
    orphan_sg_rules: list[str] = field(default_factory=list)
    nacls: dict[str, Nacl] = field(default_factory=dict)
    subnet_nacl: dict[str, str] = field(default_factory=dict)
    default_nacl: dict[str, str] = field(default_factory=dict)
    nat_gateways: dict[str, dict[str, Any]] = field(default_factory=dict)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    listeners: dict[str, Listener] = field(default_factory=dict)
    target_groups: dict[str, TargetGroup] = field(default_factory=dict)
    bindings: list[Binding] = field(default_factory=list)
    task_definitions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def label(self, key: str | None) -> str:
        if key is None:
            return "?"
        return self.labels.get(key, key.split(":", 1)[-1])

    def listeners_of(self, lb_key: str) -> list[Listener]:
        return sorted((li for li in self.listeners.values() if li.lb == lb_key), key=lambda li: (li.port or 0, li.key))

    def bindings_of(self, tg_key: str) -> list[Binding]:
        return sorted((b for b in self.bindings if b.target_group == tg_key), key=lambda b: (b.target, b.port or 0))

    def effective_route_table(self, subnet_key: str) -> tuple[str | None, str]:
        """(route table key, how it was determined)."""
        if subnet_key in self.subnet_route_table:
            return self.subnet_route_table[subnet_key], "explicit association"
        subnet = self.subnets.get(subnet_key)
        if subnet and subnet.vpc in self.main_route_table:
            return self.main_route_table[subnet.vpc], "VPC main route table (no explicit association)"
        return None, "no explicit association and the VPC main route table is unknown"

    def effective_nacl(self, subnet_key: str) -> tuple[str | None, str]:
        if subnet_key in self.subnet_nacl:
            return self.subnet_nacl[subnet_key], "explicit association"
        subnet = self.subnets.get(subnet_key)
        if subnet and subnet.vpc in self.default_nacl:
            return self.default_nacl[subnet.vpc], "VPC default network ACL"
        return None, "no network ACL data for this subnet (and the VPC default NACL is unknown)"

    def vpc_cidrs(self, vpc_key: str | None) -> list[IPNetwork]:
        vpc = self.vpcs.get(vpc_key or "")
        return vpc.cidrs if vpc else []


# --- builder ------------------------------------------------------------------


class _Builder:
    def __init__(self, graph: Graph):
        self.graph = graph
        self.base_resolver = Resolver(graph)
        #: Resolves relative to the module instance of the node being
        #: handled (see enter); references never cross module instances.
        self.resolver = self.base_resolver
        self.facts = NetworkFacts(graph=graph, labels={nid: node_label(n) for nid, n in graph.nodes.items()})
        self.pending_sg_rules: list[tuple[str, SGRule]] = []
        self.pending_nacl_rules: list[tuple[str, str, NaclRule]] = []
        self.pending_rules: list[tuple[Node, dict[str, Any]]] = []

    # resolution ---------------------------------------------------------------

    def enter(self, node: Node) -> None:
        """Resolve subsequent references from `node`'s point of view."""
        self.resolver = self.base_resolver.for_node(node)

    def refs(self, value, types: tuple[str, ...]) -> tuple[list[str], list[str]]:
        """Resolve an id/ARN/interpolation (or list of them) to node ids.

        A literal cloud id that is not in the graph still becomes a
        deterministic key ("<type>:<id>") so e.g. two references to the same
        un-scanned security group compare equal. Expressions that cannot be
        resolved are returned in the second list.
        """
        values = value if isinstance(value, list) else [value]
        keys: list[str] = []
        unresolved: list[str] = []
        for v in values:
            if v is None or v == "":
                continue
            if not isinstance(v, str):
                unresolved.append(repr(v))
                continue
            found: list[str] = []
            for t in types:
                found = self.resolver.resolve(v, t)
                if found:
                    break
            if found:
                keys.extend(k for k in found if k not in keys)
            elif _LITERAL_ID.match(v) and not _TF_EXPRESSION.search(v) and not v.startswith("aws_"):
                keys.append(make_node_id(types[0], v))
            else:
                unresolved.append(v)
        return keys, unresolved

    def ref1(self, value, types: tuple[str, ...]) -> str | None:
        keys, _ = self.refs(value, types)
        return keys[0] if keys else None

    def node_type(self, key: str | None) -> str | None:
        node = self.graph.nodes.get(key or "")
        return node.resource_type if node else None

    # parsing ------------------------------------------------------------------

    def sg_rule(self, block: dict[str, Any], direction: str, origin: str, *, owner: str | None = None) -> SGRule:
        protocol = normalize_protocol(block.get("protocol", block.get("ip_protocol")))
        ports = rule_port_interval(protocol, block.get("from_port"), block.get("to_port")) if protocol else None
        rule = SGRule(direction=direction, protocol=protocol, ports=ports, origin=origin)
        if protocol is None:
            rule.unresolved.append(f"protocol={block.get('protocol', block.get('ip_protocol'))!r}")
        for attr in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
            values = _as_list(block.get(attr))
            if values is None:
                rule.unresolved.append(str(block.get(attr)))
                continue
            for v in values:
                net = parse_cidr(v)
                if net is None:
                    rule.unresolved.append(str(v))
                else:
                    rule.cidrs.append(net)
        for attr in ("security_groups", "source_security_group_id", "referenced_security_group_id"):
            keys, unresolved = self.refs(block.get(attr), SG_TYPES)
            rule.sg_refs.extend(k for k in keys if k not in rule.sg_refs)
            rule.unresolved.extend(unresolved)
        if _bool(block.get("self")):
            rule.self_ref = True
        for attr in ("prefix_list_ids", "prefix_list_id"):
            values = _as_list(block.get(attr)) or []
            rule.prefix_lists.extend(str(v) for v in values if v)
        if owner and owner in rule.sg_refs:
            rule.self_ref = True
            rule.sg_refs.remove(owner)
        return rule

    def nacl_rule(self, block: dict[str, Any], origin: str) -> NaclRule:
        protocol = normalize_protocol(block.get("protocol"))
        rule_no = _int(block.get("rule_no", block.get("rule_number")))
        action = block.get("action", block.get("rule_action"))
        action = str(action).lower() if isinstance(action, str) and "${" not in action else None
        cidr_raw = block.get("cidr_block") or block.get("ipv6_cidr_block")
        cidr = parse_cidr(cidr_raw)
        if protocol in ("icmp", "icmpv6"):
            ports = (0, 65535)
            icmp_type = _int(block.get("icmp_type"))
        else:
            icmp_type = None
            ports = rule_port_interval(protocol, block.get("from_port"), block.get("to_port")) if protocol else None
            if protocol in ("tcp", "udp") and block.get("from_port") in (None, 0) and block.get("to_port") in (None, 0):
                ports = (0, 65535)  # AWS/Terraform: 0-0 on a NACL entry means all ports
        unresolved = protocol is None or rule_no is None or action not in ("allow", "deny") or cidr is None or ports is None
        return NaclRule(rule_no, action, protocol, cidr, ports, icmp_type, origin, unresolved)

    def route(self, block: dict[str, Any], origin: str) -> Route:
        dest_raw = block.get("destination_cidr_block") or block.get("cidr_block") or block.get("destination_ipv6_cidr_block") or block.get(
            "ipv6_cidr_block"
        )
        prefix_list = block.get("destination_prefix_list_id")
        destination = parse_cidr(dest_raw)
        if destination is None:
            dest_raw = str(dest_raw or prefix_list or "?")
        state = str(block.get("state") or "active").lower()
        target_type = block.get("target_type")
        target: str | None = block.get("target_id")
        if target_type:
            key = None
            if target_type == "internet_gateway":
                key = self.ref1(target, ("internet_gateway",))
            elif target_type == "nat_gateway":
                key = self.ref1(target, ("nat_gateway",))
            target = key or target
        else:
            target_type, target = self._classify_tf_route_target(block)
        label = "local" if target_type == "local" else f"{self.facts.label(target) if target else '?'} ({target_type})"
        if target_type == "local":
            target = "local"
        return Route(destination, str(dest_raw), target_type, target, label, state, origin)

    def _classify_tf_route_target(self, block: dict[str, Any]) -> tuple[str, str | None]:
        typed_fields = (
            ("nat_gateway_id", "nat_gateway", ("nat_gateway",)),
            ("transit_gateway_id", "transit_gateway", ("ec2_transit_gateway",)),
            ("vpc_peering_connection_id", "vpc_peering", ("vpc_peering_connection",)),
            ("network_interface_id", "network_interface", ("network_interface",)),
            ("egress_only_gateway_id", "egress_only_gateway", ("egress_only_internet_gateway",)),
            ("vpc_endpoint_id", "vpc_endpoint", ("vpc_endpoint",)),
            ("instance_id", "instance", ("instance",)),
            ("local_gateway_id", "local_gateway", ("local_gateway",)),
            ("carrier_gateway_id", "carrier_gateway", ("carrier_gateway",)),
            ("core_network_arn", "core_network", ("core_network",)),
        )
        gateway = block.get("gateway_id")
        if gateway:
            if gateway == "local":
                return "local", "local"
            keys, _ = self.refs(gateway, ("internet_gateway",))
            key = keys[0] if keys else None
            node_type = self.node_type(key)
            if node_type == "internet_gateway" or str(gateway).startswith("igw-"):
                return "internet_gateway", key or gateway
            if node_type == "vpn_gateway" or str(gateway).startswith("vgw-"):
                return "vpn_gateway", key or gateway
            return "unknown", str(gateway)
        for attr, target_type, types in typed_fields:
            value = block.get(attr)
            if value:
                keys, _ = self.refs(value, types)
                return target_type, keys[0] if keys else str(value)
        return "unknown", None

    # per-resource handlers ----------------------------------------------------

    def build(self) -> NetworkFacts:
        nodes = sorted(self.graph.nodes.values(), key=lambda n: n.id)
        # Pass 1: containers other things reference.
        for node in nodes:
            state, source = _state(node)
            handler = getattr(self, f"_h_{node.resource_type}", None)
            if handler is not None and node.resource_type in ("vpc", "vpc_ipv4_cidr_block_association", "subnet"):
                self.enter(node)
                handler(node, state, source)
        for node in nodes:
            state, source = _state(node)
            handler = getattr(self, f"_h_{node.resource_type}", None)
            if handler is not None and node.resource_type not in ("vpc", "vpc_ipv4_cidr_block_association", "subnet"):
                self.enter(node)
                handler(node, state, source)
        self._finish()
        return self.facts

    def _h_vpc(self, node: Node, state: dict, source: str) -> None:
        cidrs = []
        for v in [state.get("cidr_block"), *(state.get("cidr_blocks") or []), state.get("ipv6_cidr_block"),
                  *(state.get("ipv6_cidr_blocks") or [])]:
            net = parse_cidr(v)
            if net is not None and net not in cidrs:
                cidrs.append(net)
        self.facts.vpcs[node.id] = Vpc(node.id, self.facts.label(node.id), cidrs)

    def _h_vpc_ipv4_cidr_block_association(self, node: Node, state: dict, source: str) -> None:
        vpc = self.ref1(state.get("vpc_id"), ("vpc",))
        net = parse_cidr(state.get("cidr_block"))
        if vpc in self.facts.vpcs and net is not None:
            self.facts.vpcs[vpc].cidrs.append(net)

    def _h_subnet(self, node: Node, state: dict, source: str) -> None:
        cidrs = [n for n in (parse_cidr(state.get("cidr_block")), parse_cidr(state.get("ipv6_cidr_block"))) if n is not None]
        subnet = Subnet(
            node.id,
            self.facts.label(node.id),
            self.ref1(state.get("vpc_id"), ("vpc",)),
            cidrs,
            cidr_unresolved=parse_cidr(state.get("cidr_block")) is None,
            map_public_ip=_bool(state.get("map_public_ip_on_launch")),
        )
        self.facts.subnets[node.id] = subnet
        rt = self.ref1(state.get("route_table_id"), RT_TYPES)
        if rt:
            self.facts.subnet_route_table[node.id] = rt

    def _route_table(self, node: Node) -> RouteTable:
        rt = self.facts.route_tables.get(node.id)
        if rt is None:
            rt = RouteTable(node.id, self.facts.label(node.id), None)
            self.facts.route_tables[node.id] = rt
        return rt

    def _h_route_table(self, node: Node, state: dict, source: str) -> None:
        rt = self._route_table(node)
        rt.vpc = self.ref1(state.get("vpc_id"), ("vpc",))
        routes = _blocks(state.get("route"))
        if routes is None:
            rt.notes.append(f"{rt.label}: inline routes are an unresolved expression")
        for i, block in enumerate(routes or []):
            rt.routes.append(self.route(block, f"{rt.label} route #{i}"))
        if state.get("main") is True and rt.vpc:
            rt.is_main = True
            self.facts.main_route_table[rt.vpc] = rt.key
        for sn in self.refs(state.get("subnet_ids"), ("subnet",))[0]:
            self.facts.subnet_route_table[sn] = rt.key

    def _h_default_route_table(self, node: Node, state: dict, source: str) -> None:
        rt = self._route_table(node)
        owner = self.ref1(state.get("default_route_table_id"), ("route_table",))
        vpc = owner if self.node_type(owner) == "vpc" else self.ref1(state.get("vpc_id"), ("vpc",))
        rt.vpc = vpc
        rt.is_main = True
        if vpc:
            self.facts.main_route_table[vpc] = rt.key
        routes = _blocks(state.get("route"))
        for i, block in enumerate(routes or []):
            rt.routes.append(self.route(block, f"{rt.label} route #{i}"))

    def _h_route(self, node: Node, state: dict, source: str) -> None:
        rt_key = self.ref1(state.get("route_table_id"), RT_TYPES)
        if rt_key is None:
            return
        rt = self.facts.route_tables.get(rt_key)
        if rt is None:
            rt = RouteTable(rt_key, self.facts.label(rt_key), None)
            self.facts.route_tables[rt_key] = rt
        rt.routes.append(self.route(state, self.facts.label(node.id)))

    def _h_route_table_association(self, node: Node, state: dict, source: str) -> None:
        sn = self.ref1(state.get("subnet_id"), ("subnet",))
        rt = self.ref1(state.get("route_table_id"), RT_TYPES)
        if sn and rt:
            self.facts.subnet_route_table[sn] = rt

    def _h_main_route_table_association(self, node: Node, state: dict, source: str) -> None:
        vpc = self.ref1(state.get("vpc_id"), ("vpc",))
        rt = self.ref1(state.get("route_table_id"), RT_TYPES)
        if vpc and rt:
            self.facts.main_route_table[vpc] = rt

    def _sg(self, node: Node, state: dict, source: str) -> None:
        label = self.facts.label(node.id)
        sg = SecurityGroup(node.id, label, self.ref1(state.get("vpc_id"), ("vpc",)), source=source)
        if "dynamic" in state:
            sg.complete = False
            sg.notes.append(f"{label}: uses dynamic rule blocks that FlowLens cannot expand")
        for direction in ("ingress", "egress"):
            blocks = _blocks(state.get(direction))
            if blocks is None:
                sg.complete = False
                sg.notes.append(f"{label}: {direction} rules are an unresolved expression")
                continue
            if direction == "egress" and source == "terraform" and state.get("egress") is None:
                sg.notes.append(
                    f"{label}: no egress declared in Terraform; Terraform removes AWS's default allow-all egress rule"
                )
            for i, block in enumerate(blocks):
                getattr(sg, direction).append(self.sg_rule(block, direction, f"{label} {direction} rule #{i}", owner=node.id))
        self.facts.security_groups[node.id] = sg

    _h_security_group = _sg
    _h_default_security_group = _sg

    def _h_security_group_rule(self, node: Node, state: dict, source: str) -> None:
        direction = state.get("type") if state.get("type") in ("ingress", "egress") else None
        self._separate_sg_rule(node, state, direction)

    def _h_vpc_security_group_ingress_rule(self, node: Node, state: dict, source: str) -> None:
        self._separate_sg_rule(node, state, "ingress")

    def _h_vpc_security_group_egress_rule(self, node: Node, state: dict, source: str) -> None:
        self._separate_sg_rule(node, state, "egress")

    def _separate_sg_rule(self, node: Node, state: dict, direction: str | None) -> None:
        label = self.facts.label(node.id)
        owner = self.ref1(state.get("security_group_id"), SG_TYPES)
        if owner is None or direction is None:
            self.facts.orphan_sg_rules.append(f"{label}: target security group/direction could not be resolved")
            return
        self.pending_sg_rules.append((owner, self.sg_rule(state, direction, label, owner=owner)))

    def _nacl(self, node: Node, state: dict, source: str, *, default: bool) -> None:
        label = self.facts.label(node.id)
        vpc = self.ref1(state.get("vpc_id"), ("vpc",))
        if default:
            owner = self.ref1(state.get("default_network_acl_id"), ("network_acl",))
            if self.node_type(owner) == "vpc":
                vpc = owner
        nacl = Nacl(node.id, label, vpc, is_default=default or bool(state.get("is_default")))
        nacl.subnets = self.refs(state.get("subnet_ids"), ("subnet",))[0]
        for direction in ("ingress", "egress"):
            blocks = _blocks(state.get(direction))
            if blocks is None:
                nacl.complete = False
                continue
            for i, block in enumerate(blocks):
                getattr(nacl, direction).append(self.nacl_rule(block, f"{label} {direction} #{i}"))
        self.facts.nacls[node.id] = nacl

    def _h_network_acl(self, node: Node, state: dict, source: str) -> None:
        self._nacl(node, state, source, default=False)

    def _h_default_network_acl(self, node: Node, state: dict, source: str) -> None:
        self._nacl(node, state, source, default=True)

    def _h_network_acl_rule(self, node: Node, state: dict, source: str) -> None:
        owner = self.ref1(state.get("network_acl_id"), NACL_TYPES)
        if owner:
            direction = "egress" if _bool(state.get("egress")) else "ingress"
            self.pending_nacl_rules.append((owner, direction, self.nacl_rule(state, self.facts.label(node.id))))

    def _h_network_acl_association(self, node: Node, state: dict, source: str) -> None:
        sn = self.ref1(state.get("subnet_id"), ("subnet",))
        acl = self.ref1(state.get("network_acl_id"), NACL_TYPES)
        if sn and acl:
            self.facts.subnet_nacl[sn] = acl

    def _h_nat_gateway(self, node: Node, state: dict, source: str) -> None:
        self.facts.nat_gateways[node.id] = {
            "subnet": self.ref1(state.get("subnet_id"), ("subnet",)),
            "connectivity_type": state.get("connectivity_type") or "public",
            "state": state.get("state"),
        }

    # load balancing ---------------------------------------------------------------

    def _h_alb(self, node: Node, state: dict, source: str) -> None:
        lb_type = str(state.get("load_balancer_type") or state.get("type") or "application").lower()
        internal = _bool(state.get("internal"))
        if internal is None and state.get("scheme"):
            internal = state["scheme"] == "internal"
        if internal is None and source == "terraform" and "internal" not in state:
            internal = False  # Terraform default: internet-facing
        subnets, sn_unresolved = self.refs(state.get("subnets"), ("subnet",))
        for mapping in _blocks(state.get("subnet_mapping")) or []:
            keys, unresolved = self.refs(mapping.get("subnet_id"), ("subnet",))
            subnets += [k for k in keys if k not in subnets]
            sn_unresolved += unresolved
        sgs, sg_unresolved = self.refs(state.get("security_groups"), SG_TYPES)
        ep = Endpoint(
            key=node.id,
            label=self.facts.label(node.id),
            kind="lb",
            node_id=node.id,
            subnets=subnets,
            subnets_unresolved=sn_unresolved,
            sgs=sgs,
            sgs_unresolved=sg_unresolved,
            lb_type=lb_type,
            internal=internal,
            public_ip=None if internal is None else not internal,
            public_ip_evidence=f"{self.facts.label(node.id)} scheme: {_scheme(internal)}",
        )
        if lb_type != "application" and not sgs and not sg_unresolved:
            ep.sg_applicable = False
            ep.notes.append(f"{ep.label}: {lb_type} load balancer has no security groups; SG checks do not apply to it")
        self.facts.endpoints[node.id] = ep

    _h_nlb = _h_alb  # same endpoint model; lb_type drives the NLB-specific rules

    def _forwards(self, actions, origin: str) -> tuple[list[Forward], list[str], bool]:
        blocks = _blocks(actions)
        if blocks is None:
            return [], [], False
        forwards: list[Forward] = []
        types: list[str] = []
        for i, action in enumerate(blocks):
            atype = str(action.get("type") or ("forward" if action.get("target_group_arn") else "")).lower()
            types.append(atype)
            values = []
            if action.get("target_group_arn"):
                values.append(action["target_group_arn"])
            for fwd in _blocks(action.get("forward")) or []:
                for tg in _blocks(fwd.get("target_group")) or []:
                    if tg.get("arn"):
                        values.append(tg["arn"])
            for v in values:
                keys, unresolved = self.refs(v, ("target_group",))
                for k in keys:
                    forwards.append(Forward(k, None, f"{origin} action #{i}"))
                for u in unresolved:
                    forwards.append(Forward(None, u, f"{origin} action #{i}"))
        return forwards, types, True

    def _h_listener(self, node: Node, state: dict, source: str) -> None:
        label = self.facts.label(node.id)
        lb = self.ref1(state.get("load_balancer_arn"), LOAD_BALANCER_TYPES)
        forwards, types, known = self._forwards(state.get("default_action"), f"{label} default")
        if state.get("default_action_types"):
            types = [str(t) for t in state["default_action_types"]]
        listener = Listener(node.id, label, lb, _int(state.get("port")), state.get("protocol"), forwards, types, known)
        if "default_action" not in state:
            listener.actions_known = False
        self.facts.listeners[node.id] = listener

    def _h_listener_rule(self, node: Node, state: dict, source: str) -> None:
        if state.get("is_default"):
            return  # duplicates the listener's default action
        self.pending_rules.append((node, state))

    def _h_target_group(self, node: Node, state: dict, source: str) -> None:
        target_type = state.get("target_type") or ("instance" if source == "terraform" else None)
        self.facts.target_groups[node.id] = TargetGroup(
            node.id,
            self.facts.label(node.id),
            _int(state.get("port")),
            state.get("protocol"),
            target_type,
            self.ref1(state.get("vpc_id"), ("vpc",)),
            _bool(state.get("preserve_client_ip")),
        )

    def _h_lb_target_group_attachment(self, node: Node, state: dict, source: str) -> None:
        tg = self.ref1(state.get("target_group_arn"), ("target_group",))
        target = self.ref1(state.get("target_id"), ("instance", "lambda", "alb"))
        if tg and target:
            self.facts.bindings.append(Binding(tg, target, _int(state.get("port")), self.facts.label(node.id)))

    # workloads --------------------------------------------------------------------

    def _h_ecs_task_definition(self, node: Node, state: dict, source: str) -> None:
        mappings = state.get("port_mappings")
        if mappings is None:
            mappings = _container_port_mappings(state.get("container_definitions"))
        self.facts.task_definitions[node.id] = {
            "network_mode": state.get("network_mode") or ("bridge" if source == "terraform" else None),
            "port_mappings": mappings,
            "label": self.facts.label(node.id),
        }

    def _h_ecs_service(self, node: Node, state: dict, source: str) -> None:
        label = self.facts.label(node.id)
        ep = Endpoint(key=node.id, label=label, kind="ecs_service", node_id=node.id)
        net = _block(state.get("network_configuration"))
        if net is None:
            ep.notes.append(
                f"{label}: no awsvpc network_configuration; tasks use the container instances' network (subnets/SGs unknown)"
            )
            ep.subnets_unresolved.append("container instance network")
            ep.sgs_unresolved.append("container instance security groups")
        else:
            ep.subnets, ep.subnets_unresolved = self.refs(net.get("subnets"), ("subnet",))
            ep.sgs, ep.sgs_unresolved = self.refs(net.get("security_groups"), SG_TYPES)
            if not ep.sgs and not ep.sgs_unresolved:
                ep.sgs_unresolved.append("none specified (AWS attaches the VPC default security group)")
            assign = _bool(net.get("assign_public_ip"))
            ep.public_ip = bool(assign) if assign is not None or source == "terraform" else None
            ep.public_ip_evidence = f"{label} network_configuration.assign_public_ip = {str(bool(assign)).lower()}"
        td = self.ref1(state.get("task_definition"), ("ecs_task_definition",))
        ep.extra["task_definition"] = td
        for lb in _blocks(state.get("load_balancer")) or []:
            for tg in self.refs(lb.get("target_group_arn"), ("target_group",))[0]:
                self.facts.bindings.append(
                    Binding(tg, node.id, _int(lb.get("container_port")), f"{label} load_balancer", lb.get("container_name"))
                )
        self.facts.endpoints[node.id] = ep

    def _h_lambda(self, node: Node, state: dict, source: str) -> None:
        label = self.facts.label(node.id)
        ep = Endpoint(key=node.id, label=label, kind="lambda", node_id=node.id, accepts_inbound=False, public_ip=False)
        vpc_cfg = _block(state.get("vpc_config"))
        if vpc_cfg is None or not (vpc_cfg.get("subnet_ids") or vpc_cfg.get("security_group_ids")):
            ep.in_vpc = False
            ep.notes.append(f"{label}: not attached to a VPC (runs in the AWS-managed Lambda network)")
        else:
            ep.subnets, ep.subnets_unresolved = self.refs(vpc_cfg.get("subnet_ids"), ("subnet",))
            ep.sgs, ep.sgs_unresolved = self.refs(vpc_cfg.get("security_group_ids"), SG_TYPES)
        ep.public_ip_evidence = "Lambda ENIs never receive public IP addresses"
        self.facts.endpoints[node.id] = ep

    def _h_instance(self, node: Node, state: dict, source: str) -> None:
        label = self.facts.label(node.id)
        ep = Endpoint(key=node.id, label=label, kind="instance", node_id=node.id)
        ep.subnets, ep.subnets_unresolved = self.refs(state.get("subnet_id"), ("subnet",))
        ep.sgs, ep.sgs_unresolved = self.refs(state.get("vpc_security_group_ids"), SG_TYPES)
        ip = parse_cidr(state.get("private_ip"))
        if ip is not None:
            ep.addresses = [ip]
        if state.get("public_ip"):
            ep.public_ip, ep.public_ip_evidence = True, f"{label} public IP {state['public_ip']}"
        elif _bool(state.get("associate_public_ip_address")) is not None:
            ep.public_ip = _bool(state.get("associate_public_ip_address"))
            ep.public_ip_evidence = f"{label} associate_public_ip_address = {str(ep.public_ip).lower()}"
        elif source == "aws":
            ep.public_ip, ep.public_ip_evidence = False, f"{label} has no public IP"
        ep.extra["map_public_ip_from_subnet"] = True
        self.facts.endpoints[node.id] = ep

    def _h_db_instance(self, node: Node, state: dict, source: str) -> None:
        label = self.facts.label(node.id)
        ep = Endpoint(key=node.id, label=label, kind="db_instance", node_id=node.id)
        ep.sgs, ep.sgs_unresolved = self.refs(state.get("vpc_security_group_ids"), SG_TYPES)
        group = self.ref1(state.get("db_subnet_group_name"), ("db_subnet_group",))
        group_node = self.graph.nodes.get(group or "")
        if group_node is None:
            ep.subnets_unresolved.append(f"db_subnet_group_name={state.get('db_subnet_group_name')!r}")
        else:
            gstate, _ = _state(group_node)
            self.enter(group_node)
            ep.subnets, ep.subnets_unresolved = self.refs(gstate.get("subnet_ids"), ("subnet",))
            self.enter(node)
        publicly = _bool(state.get("publicly_accessible"))
        ep.public_ip = bool(publicly) if publicly is not None or source == "terraform" else None
        ep.public_ip_evidence = f"{label} publicly_accessible = {str(bool(publicly)).lower()}"
        self.facts.endpoints[node.id] = ep

    # finishing --------------------------------------------------------------------

    def _finish(self) -> None:
        facts = self.facts
        for owner, rule in self.pending_sg_rules:
            sg = facts.security_groups.get(owner)
            if sg is None:
                sg = SecurityGroup(owner, facts.label(owner), None, complete=False)
                sg.notes.append(f"{sg.label}: security group itself is not in the graph; only separate rule resources are known")
                facts.security_groups[owner] = sg
            getattr(sg, rule.direction).append(rule)
        for owner, direction, rule in self.pending_nacl_rules:
            nacl = facts.nacls.get(owner)
            if nacl is not None:
                getattr(nacl, direction).append(rule)
        for nacl in facts.nacls.values():
            for sn in nacl.subnets:
                facts.subnet_nacl[sn] = nacl.key
            if nacl.is_default and nacl.vpc:
                facts.default_nacl[nacl.vpc] = nacl.key
        for rt in facts.route_tables.values():
            if rt.vpc is None:
                continue
            # The VPC local route exists in every route table and cannot be removed.
            present = {r.destination for r in rt.routes if r.target_type == "local"}
            for cidr in facts.vpc_cidrs(rt.vpc):
                if cidr not in present:
                    rt.routes.append(
                        Route(cidr, str(cidr), "local", "local", "local", origin=f"{rt.label} implicit VPC local route", implicit=True)
                    )
        for node, state in self.pending_rules:
            self.enter(node)
            label = facts.label(node.id)
            listener = facts.listeners.get(self.ref1(state.get("listener_arn"), ("listener",)) or "")
            if listener is None:
                continue
            forwards, types, _known = self._forwards(state.get("action"), label)
            if state.get("action_types"):
                types = [str(t) for t in state["action_types"]]
            listener.forwards.extend(forwards)
            listener.action_types.extend(types)
        # Endpoint VPCs follow from their subnets.
        for ep in facts.endpoints.values():
            vpcs = {facts.subnets[s].vpc for s in ep.subnets if s in facts.subnets}
            if len(vpcs) == 1:
                ep.vpc = vpcs.pop()
            if ep.kind == "instance" and ep.public_ip is None:
                subnet = facts.subnets.get(ep.subnets[0]) if ep.subnets else None
                if subnet and subnet.map_public_ip is not None:
                    ep.public_ip = subnet.map_public_ip
                    ep.public_ip_evidence = f"{subnet.label} map_public_ip_on_launch = {str(subnet.map_public_ip).lower()}"


def _scheme(internal: bool | None) -> str:
    return "unknown" if internal is None else ("internal" if internal else "internet-facing")


def _container_port_mappings(value) -> list[dict[str, Any]] | None:
    """Port mappings from a task definition's container_definitions: a JSON
    string (state/AWS) or a `jsonencode(...)` expression (config). None when
    they cannot be determined.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if not text.startswith("${"):
        try:
            containers = json.loads(text)
        except ValueError:
            return None
        return [
            {
                "container_name": c.get("name"),
                "container_port": pm.get("containerPort"),
                "host_port": pm.get("hostPort"),
                "protocol": pm.get("protocol", "tcp"),
            }
            for c in containers if isinstance(c, dict)
            for pm in c.get("portMappings", []) or []
        ]
    if "jsonencode" not in text or re.search(r"\b(var|local|module)\.", text):
        return None
    out = []
    for block in re.findall(r"\{[^{}]*containerPort[^{}]*\}", text):
        cport = re.search(r"containerPort\s*[=:]\s*(\d+)", block)
        hport = re.search(r"hostPort\s*[=:]\s*(\d+)", block)
        out.append({
            "container_name": None,
            "container_port": int(cport.group(1)) if cport else None,
            "host_port": int(hport.group(1)) if hport else None,
            "protocol": "tcp",
        })
    return out


def build_facts(graph: Graph) -> NetworkFacts:
    return _Builder(graph).build()
