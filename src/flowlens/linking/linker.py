"""Semantic linking: turns generic resource attributes into typed edges
(contains, forwards_to, allows, ...) as described in the FlowLens graph
model. Works uniformly over nodes regardless of whether they came from
Terraform (desired_state) or AWS discovery (actual_state) — attribute names
are normalized to a common AWS-ish vocabulary (vpc_id, subnet_ids, ...) by
both the Terraform ingester and the AWS discoverer, so one rule set covers
both sources.

Also resolves unresolved Terraform interpolation strings (e.g.
"${aws_vpc.main.id}") against other resources' terraform_address, so
config-only ingestion (no state/AWS data yet) still yields semantic edges.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from flowlens.ids import make_node_id
from flowlens.models.graph import Edge, Graph, Node, RelationshipType, Source

_REF_PATTERN = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_-]*)")


def _state_of(node: Node) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    if node.actual_state:
        merged.update(node.actual_state)
    if node.desired_state:
        merged.update(node.desired_state)
    return merged


class _Resolver:
    """Resolves an attribute value (a raw cloud id, an ARN, an HCL
    interpolation string, or a list of any of those) to node ids already
    present in the graph.
    """

    def __init__(self, graph: Graph):
        self.graph = graph
        self.by_address: dict[str, str] = {
            n.terraform_address: n.id for n in graph.nodes.values() if n.terraform_address
        }
        self.by_arn: dict[str, str] = {n.aws_arn: n.id for n in graph.nodes.values() if n.aws_arn}

    def resolve(self, value: Any, expected_type: str) -> list[str]:
        if isinstance(value, list):
            out: list[str] = []
            for v in value:
                out.extend(self.resolve(v, expected_type))
            return out
        if not isinstance(value, str) or not value:
            return []
        if value in self.by_arn:
            return [self.by_arn[value]]
        candidate_id = make_node_id(expected_type, value)
        if candidate_id in self.graph.nodes:
            return [candidate_id]
        found = []
        for match in _REF_PATTERN.finditer(value):
            address = f"{match.group(1)}.{match.group(2)}"
            if address in self.by_address:
                found.append(self.by_address[address])
        return found


#: Public name for reuse (e.g. by flowlens.reachability) without duplicating
#: the id/ARN/Terraform-address resolution rules.
Resolver = _Resolver


def _edge(src: str, dst: str, rel: RelationshipType, *, protocol: str | None = None,
          port: int | None = None, metadata: dict[str, Any] | None = None) -> Edge:
    return Edge(
        id=f"{src}->{dst}:{rel.value}",
        source_node=src,
        target_node=dst,
        relationship_type=rel,
        protocol=protocol,
        port=port,
        metadata=metadata or {},
        source=Source.MERGED,
    )


# Each handler receives (node, state-dict, resolver) and yields Edge objects.
_HandlerT = Callable[[Node, dict[str, Any], _Resolver], "list[Edge]"]


def _link_subnet(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for vpc_id in r.resolve(state.get("vpc_id"), "vpc"):
        edges.append(_edge(vpc_id, node.id, RelationshipType.CONTAINS))
    for rt_id in r.resolve(state.get("route_table_id"), "route_table"):
        edges.append(_edge(node.id, rt_id, RelationshipType.ASSOCIATED_WITH))
    return edges


def _link_route_table(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for vpc_id in r.resolve(state.get("vpc_id"), "vpc"):
        edges.append(_edge(vpc_id, node.id, RelationshipType.CONTAINS))
    return edges


def _link_route(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for rt_id in r.resolve(state.get("route_table_id"), "route_table"):
        edges.append(_edge(rt_id, node.id, RelationshipType.CONTAINS))
    for igw_id in r.resolve(state.get("gateway_id"), "internet_gateway"):
        edges.append(_edge(node.id, igw_id, RelationshipType.ROUTES_TO))
    for nat_id in r.resolve(state.get("nat_gateway_id"), "nat_gateway"):
        edges.append(_edge(node.id, nat_id, RelationshipType.ROUTES_TO))
    return edges


def _link_internet_gateway(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    return [_edge(node.id, vpc_id, RelationshipType.ATTACHED_TO) for vpc_id in r.resolve(state.get("vpc_id"), "vpc")]


def _link_nat_gateway(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    return [_edge(node.id, sn_id, RelationshipType.MEMBER_OF) for sn_id in r.resolve(state.get("subnet_id"), "subnet")]


def _link_security_group(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for vpc_id in r.resolve(state.get("vpc_id"), "vpc"):
        edges.append(_edge(vpc_id, node.id, RelationshipType.CONTAINS))
    for other_sg in r.resolve(state.get("source_security_group_id"), "security_group"):
        edges.append(_edge(other_sg, node.id, RelationshipType.ALLOWS))
    return edges


def _link_alb(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for sn_id in r.resolve(state.get("subnets"), "subnet"):
        edges.append(_edge(node.id, sn_id, RelationshipType.MEMBER_OF))
    for sg_id in r.resolve(state.get("security_groups"), "security_group"):
        edges.append(_edge(sg_id, node.id, RelationshipType.ALLOWS))
    return edges


def _link_listener(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for alb_id in r.resolve(state.get("load_balancer_arn"), "alb"):
        edges.append(_edge(node.id, alb_id, RelationshipType.DEPENDS_ON))
    for action in state.get("default_action") or []:
        if isinstance(action, dict):
            for tg_id in r.resolve(action.get("target_group_arn"), "target_group"):
                edges.append(
                    _edge(node.id, tg_id, RelationshipType.FORWARDS_TO, protocol=state.get("protocol"), port=state.get("port"))
                )
    return edges


def _link_listener_rule(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for l_id in r.resolve(state.get("listener_arn"), "listener"):
        edges.append(_edge(node.id, l_id, RelationshipType.DEPENDS_ON))
    for action in state.get("action") or []:
        if isinstance(action, dict):
            for tg_id in r.resolve(action.get("target_group_arn"), "target_group"):
                edges.append(_edge(node.id, tg_id, RelationshipType.FORWARDS_TO))
    return edges


def _link_target_group(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    return [_edge(node.id, vpc_id, RelationshipType.MEMBER_OF) for vpc_id in r.resolve(state.get("vpc_id"), "vpc")]


def _link_ecs_service(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for cluster_id in r.resolve(state.get("cluster"), "ecs_cluster"):
        edges.append(_edge(cluster_id, node.id, RelationshipType.CONTAINS))
    for td_id in r.resolve(state.get("task_definition"), "ecs_task_definition"):
        edges.append(_edge(node.id, td_id, RelationshipType.DEPENDS_ON))
    for lb in state.get("load_balancer") or []:
        if isinstance(lb, dict):
            for tg_id in r.resolve(lb.get("target_group_arn"), "target_group"):
                edges.append(_edge(node.id, tg_id, RelationshipType.TARGETS))
    net_cfg = state.get("network_configuration")
    if isinstance(net_cfg, list) and net_cfg:
        net_cfg = net_cfg[0]
    if isinstance(net_cfg, dict):
        for sn_id in r.resolve(net_cfg.get("subnets"), "subnet"):
            edges.append(_edge(node.id, sn_id, RelationshipType.MEMBER_OF))
        for sg_id in r.resolve(net_cfg.get("security_groups"), "security_group"):
            edges.append(_edge(sg_id, node.id, RelationshipType.ALLOWS))
    return edges


def _link_lambda(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    vpc_cfg = state.get("vpc_config")
    if isinstance(vpc_cfg, list) and vpc_cfg:
        vpc_cfg = vpc_cfg[0]
    if isinstance(vpc_cfg, dict):
        for sn_id in r.resolve(vpc_cfg.get("subnet_ids"), "subnet"):
            edges.append(_edge(node.id, sn_id, RelationshipType.MEMBER_OF))
        for sg_id in r.resolve(vpc_cfg.get("security_group_ids"), "security_group"):
            edges.append(_edge(sg_id, node.id, RelationshipType.ALLOWS))
    return edges


def _link_api_gateway_integration(node: Node, state: dict, r: _Resolver) -> list[Edge]:
    edges = []
    for lambda_id in r.resolve(state.get("integration_uri") or state.get("uri"), "lambda"):
        edges.append(_edge(node.id, lambda_id, RelationshipType.INTEGRATES_WITH))
    return edges


_HANDLERS: dict[str, _HandlerT] = {
    "subnet": _link_subnet,
    "route_table": _link_route_table,
    "route": _link_route,
    "internet_gateway": _link_internet_gateway,
    "nat_gateway": _link_nat_gateway,
    "security_group": _link_security_group,
    "alb": _link_alb,
    "listener": _link_listener,
    "listener_rule": _link_listener_rule,
    "target_group": _link_target_group,
    "ecs_service": _link_ecs_service,
    "lambda": _link_lambda,
    "api_gateway_integration": _link_api_gateway_integration,
}


def link_graph(graph: Graph) -> Graph:
    """Add semantic edges to `graph` in place based on each node's resource
    attributes, and return it.
    """
    resolver = _Resolver(graph)
    for node in list(graph.nodes.values()):
        handler = _HANDLERS.get(node.resource_type)
        if handler is None:
            continue
        state = _state_of(node)
        for edge in handler(node, state, resolver):
            graph.add_edge(edge)
    return graph
