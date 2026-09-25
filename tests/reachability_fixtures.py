"""Small in-memory graph builder for reachability tests (AWS vocabulary,
same shape the read-only scanners produce). No AWS access involved.
"""
from __future__ import annotations

import copy

from flowlens.models.graph import Graph, Node, Source


def sg_rule(protocol="tcp", from_port=None, to_port=None, cidrs=(), ipv6=(), sgs=()):
    if from_port is not None and to_port is None:
        to_port = from_port
    return {
        "protocol": protocol,
        "from_port": 0 if protocol == "-1" else from_port,
        "to_port": 0 if protocol == "-1" else to_port,
        "cidr_blocks": list(cidrs),
        "ipv6_cidr_blocks": list(ipv6),
        "security_groups": list(sgs),
        "prefix_list_ids": [],
    }


def nacl_entry(rule_no, action, protocol="-1", cidr="0.0.0.0/0", from_port=None, to_port=None):
    return {"rule_no": rule_no, "action": action, "protocol": protocol, "cidr_block": cidr,
            "from_port": from_port, "to_port": to_port if to_port is not None else from_port}


ALLOW_ALL_NACL = [nacl_entry(100, "allow")]
ALB_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/1"
NLB_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb/2"
LISTENER_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/1/l443"
TG_ARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/1"
SVC_ARN = "arn:aws:ecs:us-east-1:123456789012:service/shop/app"
TD_ARN = "arn:aws:ecs:us-east-1:123456789012:task-definition/app:1"


class Stack:
    """Mutable description of a VPC with a public ALB in front of an ECS
    service in private subnets. Tests tweak `self.state[...]` and build().
    """

    def __init__(self):
        self.state: dict[str, tuple[str, dict]] = {
            "vpc-1": ("vpc", {"cidr_block": "10.0.0.0/16"}),
            "subnet-pub": ("subnet", {"vpc_id": "vpc-1", "cidr_block": "10.0.1.0/24"}),
            "subnet-app": ("subnet", {"vpc_id": "vpc-1", "cidr_block": "10.0.2.0/24"}),
            "igw-1": ("internet_gateway", {"vpc_id": "vpc-1"}),
            "nat-1": ("nat_gateway", {"subnet_id": "subnet-pub", "connectivity_type": "public", "state": "available"}),
            "rtb-main": ("route_table", {"vpc_id": "vpc-1", "main": True, "subnet_ids": []}),
            "rtb-pub": ("route_table", {"vpc_id": "vpc-1", "main": False, "subnet_ids": ["subnet-pub"]}),
            "rtb-app": ("route_table", {"vpc_id": "vpc-1", "main": False, "subnet_ids": ["subnet-app"]}),
            "rtb-main-local": ("route", self.route("rtb-main", "10.0.0.0/16", "local", "local")),
            "rtb-pub-local": ("route", self.route("rtb-pub", "10.0.0.0/16", "local", "local")),
            "rtb-pub-default": ("route", self.route("rtb-pub", "0.0.0.0/0", "internet_gateway", "igw-1")),
            "rtb-app-local": ("route", self.route("rtb-app", "10.0.0.0/16", "local", "local")),
            "rtb-app-default": ("route", self.route("rtb-app", "0.0.0.0/0", "nat_gateway", "nat-1")),
            "acl-default": ("network_acl", {"vpc_id": "vpc-1", "is_default": True, "subnet_ids": ["subnet-pub", "subnet-app"],
                                            "ingress": list(ALLOW_ALL_NACL), "egress": list(ALLOW_ALL_NACL)}),
            "sg-alb": ("security_group", {"vpc_id": "vpc-1", "name": "alb",
                                          "ingress": [sg_rule("tcp", 443, cidrs=["0.0.0.0/0"])],
                                          "egress": [sg_rule("-1", cidrs=["0.0.0.0/0"])]}),
            "sg-app": ("security_group", {"vpc_id": "vpc-1", "name": "app",
                                          "ingress": [sg_rule("tcp", 8080, sgs=["sg-alb"])],
                                          "egress": [sg_rule("-1", cidrs=["0.0.0.0/0"])]}),
            "sg-other": ("security_group", {"vpc_id": "vpc-1", "name": "other", "ingress": [], "egress": []}),
            ALB_ARN: ("alb", {"name": "web", "vpc_id": "vpc-1", "subnets": ["subnet-pub"], "security_groups": ["sg-alb"],
                              "scheme": "internet-facing", "internal": False, "type": "application"}),
            LISTENER_ARN: ("listener", {"load_balancer_arn": ALB_ARN, "protocol": "HTTPS", "port": 443,
                                        "default_action": [{"target_group_arn": TG_ARN}], "default_action_types": ["forward"]}),
            TG_ARN: ("target_group", {"name": "app-tg", "vpc_id": "vpc-1", "protocol": "HTTP", "port": 8080, "target_type": "ip"}),
            SVC_ARN: ("ecs_service", {"name": "app", "task_definition": TD_ARN,
                                      "load_balancer": [{"target_group_arn": TG_ARN, "container_name": "app", "container_port": 8080}],
                                      "network_configuration": [{"subnets": ["subnet-app"], "security_groups": ["sg-app"],
                                                                 "assign_public_ip": False}]}),
            TD_ARN: ("ecs_task_definition", {"family": "app", "network_mode": "awsvpc",
                                             "port_mappings": [{"container_name": "app", "container_port": 8080, "host_port": 8080}]}),
        }

    @staticmethod
    def route(rtb, dest, target_type, target_id, state="active"):
        return {"route_table_id": rtb, "destination_cidr_block": dest, "target_type": target_type, "target_id": target_id,
                "state": state, "gateway_id": target_id if target_type == "internet_gateway" else None,
                "nat_gateway_id": target_id if target_type == "nat_gateway" else None}

    def set(self, cloud_id: str, **changes) -> Stack:
        rtype, state = self.state[cloud_id]
        self.state[cloud_id] = (rtype, {**state, **changes})
        return self

    def add(self, cloud_id: str, rtype: str, state: dict) -> Stack:
        self.state[cloud_id] = (rtype, state)
        return self

    def remove(self, cloud_id: str) -> Stack:
        del self.state[cloud_id]
        return self

    def build(self) -> Graph:
        graph = Graph()
        for cloud_id, (rtype, state) in self.state.items():
            arn = cloud_id if cloud_id.startswith("arn:") else None
            graph.add_node(Node(id=f"{rtype}:{cloud_id}", name=state.get("name") or cloud_id, resource_type=rtype,
                                source=Source.AWS, aws_arn=arn, actual_state=copy.deepcopy(state)))
        return graph
