"""Read-only AWS runtime discovery.

Every AWS call in this module is a Describe*/List*/Get* call — nothing here
creates, modifies, or deletes anything. Uses the standard boto3 credential
and region resolution chain (env vars, shared config/credentials files,
instance profile, ...), so it works unmodified against real AWS or against
LocalStack when AWS_ENDPOINT_URL (and friends) point at http://localhost:4566.

Discovered attributes are normalized to the same attribute vocabulary the
Terraform ingester uses (vpc_id, subnets, security_groups, ...) so that
flowlens.linking.linker's rule set works identically over both sources.
"""
from __future__ import annotations

import os
import re
from typing import Any, Optional

import boto3

from flowlens.ids import make_node_id
from flowlens.models.graph import Graph, Node, Source

_ARN_PATTERN = re.compile(r"arn:aws[a-zA-Z0-9-]*:lambda:[^/:\s]+:[^/:\s]+:function:[^/:\s]+")


def _endpoint_for(service: str) -> Optional[str]:
    return os.environ.get(f"AWS_ENDPOINT_URL_{service.upper()}") or os.environ.get("AWS_ENDPOINT_URL")


class AWSDiscoverer:
    """Wraps boto3 clients for the MVP resource set and emits FlowLens Nodes
    with actual_state populated. Call discover_all() for everything, or the
    individual discover_* methods to scope discovery.
    """

    def __init__(self, region: Optional[str] = None, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session(region_name=region)
        self.region = self.session.region_name
        self.account_id: Optional[str] = None
        try:
            sts = self._client("sts")
            self.account_id = sts.get_caller_identity().get("Account")
        except Exception:
            self.account_id = None

    def _client(self, service: str):
        return self.session.client(service, endpoint_url=_endpoint_for(service))

    def _node(self, resource_type: str, cloud_id: str, name: str, actual_state: dict[str, Any], arn: Optional[str] = None) -> Node:
        return Node(
            id=make_node_id(resource_type, cloud_id),
            name=name or cloud_id,
            resource_type=resource_type,
            source=Source.AWS,
            aws_arn=arn,
            region=self.region,
            account_id=self.account_id,
            actual_state=actual_state,
        )

    @staticmethod
    def _tag_name(tags: Optional[list[dict[str, str]]], fallback: str) -> str:
        for t in tags or []:
            if t.get("Key") == "Name":
                return t.get("Value", fallback)
        return fallback

    # ---- networking ---------------------------------------------------

    def discover_vpcs(self) -> list[Node]:
        ec2 = self._client("ec2")
        nodes = []
        for vpc in ec2.describe_vpcs().get("Vpcs", []):
            nodes.append(
                self._node(
                    "vpc",
                    vpc["VpcId"],
                    self._tag_name(vpc.get("Tags"), vpc["VpcId"]),
                    {"cidr_block": vpc.get("CidrBlock"), "is_default": vpc.get("IsDefault")},
                )
            )
        return nodes

    def discover_subnets(self) -> list[Node]:
        ec2 = self._client("ec2")
        subnets = ec2.describe_subnets().get("Subnets", [])
        route_table_by_subnet = self._subnet_route_table_map(ec2)
        nodes = []
        for sn in subnets:
            sid = sn["SubnetId"]
            nodes.append(
                self._node(
                    "subnet",
                    sid,
                    self._tag_name(sn.get("Tags"), sid),
                    {
                        "vpc_id": sn.get("VpcId"),
                        "cidr_block": sn.get("CidrBlock"),
                        "availability_zone": sn.get("AvailabilityZone"),
                        "route_table_id": route_table_by_subnet.get(sid),
                    },
                )
            )
        return nodes

    @staticmethod
    def _subnet_route_table_map(ec2) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for rt in ec2.describe_route_tables().get("RouteTables", []):
            for assoc in rt.get("Associations", []):
                sid = assoc.get("SubnetId")
                if sid:
                    mapping[sid] = rt["RouteTableId"]
        return mapping

    def discover_route_tables(self) -> list[Node]:
        ec2 = self._client("ec2")
        nodes = []
        for rt in ec2.describe_route_tables().get("RouteTables", []):
            rtid = rt["RouteTableId"]
            nodes.append(
                self._node("route_table", rtid, self._tag_name(rt.get("Tags"), rtid), {"vpc_id": rt.get("VpcId")})
            )
            for i, route in enumerate(rt.get("Routes", [])):
                dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or f"local-{i}"
                route_id = f"{rtid}-{dest}"
                nodes.append(
                    self._node(
                        "route",
                        route_id,
                        route_id,
                        {
                            "route_table_id": rtid,
                            "destination_cidr_block": dest,
                            "gateway_id": route.get("GatewayId") if str(route.get("GatewayId", "")).startswith("igw-") else None,
                            "nat_gateway_id": route.get("NatGatewayId"),
                        },
                    )
                )
        return nodes

    def discover_security_groups(self) -> list[Node]:
        ec2 = self._client("ec2")
        nodes = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            peer_ids = [
                pair["GroupId"]
                for perm in sg.get("IpPermissions", [])
                for pair in perm.get("UserIdGroupPairs", [])
                if pair.get("GroupId")
            ]
            nodes.append(
                self._node(
                    "security_group",
                    sg["GroupId"],
                    sg.get("GroupName", sg["GroupId"]),
                    {"vpc_id": sg.get("VpcId"), "source_security_group_id": peer_ids or None},
                )
            )
        return nodes

    def discover_internet_gateways(self) -> list[Node]:
        ec2 = self._client("ec2")
        nodes = []
        for igw in ec2.describe_internet_gateways().get("InternetGateways", []):
            attachments = igw.get("Attachments", [])
            vpc_id = attachments[0]["VpcId"] if attachments else None
            gid = igw["InternetGatewayId"]
            nodes.append(self._node("internet_gateway", gid, self._tag_name(igw.get("Tags"), gid), {"vpc_id": vpc_id}))
        return nodes

    def discover_nat_gateways(self) -> list[Node]:
        ec2 = self._client("ec2")
        nodes = []
        try:
            gateways = ec2.describe_nat_gateways().get("NatGateways", [])
        except Exception:
            gateways = []
        for nat in gateways:
            nid = nat["NatGatewayId"]
            nodes.append(
                self._node("nat_gateway", nid, self._tag_name(nat.get("Tags"), nid), {"subnet_id": nat.get("SubnetId")})
            )
        return nodes

    # ---- load balancing -------------------------------------------------

    def discover_load_balancers(self) -> tuple[list[Node], list[Node], list[Node]]:
        """Returns (albs_and_nlbs, listeners, listener_rules)."""
        elbv2 = self._client("elbv2")
        lb_nodes, listener_nodes, rule_nodes = [], [], []
        for lb in elbv2.describe_load_balancers().get("LoadBalancers", []):
            arn = lb["LoadBalancerArn"]
            lb_nodes.append(
                self._node(
                    "alb",
                    arn,
                    lb.get("LoadBalancerName", arn),
                    {
                        "vpc_id": lb.get("VpcId"),
                        "subnets": [az["SubnetId"] for az in lb.get("AvailabilityZones", [])],
                        "security_groups": lb.get("SecurityGroups", []),
                        "scheme": lb.get("Scheme"),
                        "type": lb.get("Type"),
                    },
                    arn=arn,
                )
            )
            for listener in elbv2.describe_listeners(LoadBalancerArn=arn).get("Listeners", []):
                larn = listener["ListenerArn"]
                default_actions = [
                    {"target_group_arn": a["TargetGroupArn"]} for a in listener.get("DefaultActions", []) if a.get("TargetGroupArn")
                ]
                listener_nodes.append(
                    self._node(
                        "listener",
                        larn,
                        larn,
                        {
                            "load_balancer_arn": arn,
                            "protocol": listener.get("Protocol"),
                            "port": listener.get("Port"),
                            "default_action": default_actions,
                        },
                        arn=larn,
                    )
                )
                for rule in elbv2.describe_rules(ListenerArn=larn).get("Rules", []):
                    rarn = rule["RuleArn"]
                    actions = [
                        {"target_group_arn": a["TargetGroupArn"]} for a in rule.get("Actions", []) if a.get("TargetGroupArn")
                    ]
                    rule_nodes.append(
                        self._node("listener_rule", rarn, rarn, {"listener_arn": larn, "action": actions}, arn=rarn)
                    )
        return lb_nodes, listener_nodes, rule_nodes

    def discover_target_groups(self) -> list[Node]:
        elbv2 = self._client("elbv2")
        nodes = []
        for tg in elbv2.describe_target_groups().get("TargetGroups", []):
            arn = tg["TargetGroupArn"]
            nodes.append(
                self._node(
                    "target_group",
                    arn,
                    tg.get("TargetGroupName", arn),
                    {"vpc_id": tg.get("VpcId"), "protocol": tg.get("Protocol"), "port": tg.get("Port")},
                    arn=arn,
                )
            )
        return nodes

    # ---- compute ---------------------------------------------------------

    def discover_ecs(self) -> tuple[list[Node], list[Node], list[Node]]:
        """Returns (clusters, services, task_definitions)."""
        ecs = self._client("ecs")
        cluster_nodes, service_nodes, taskdef_nodes = [], [], []
        cluster_arns = ecs.list_clusters().get("clusterArns", [])
        if not cluster_arns:
            return cluster_nodes, service_nodes, taskdef_nodes
        clusters = ecs.describe_clusters(clusters=cluster_arns).get("clusters", [])
        seen_taskdefs: set[str] = set()
        for cluster in clusters:
            carn = cluster["clusterArn"]
            cluster_nodes.append(self._node("ecs_cluster", carn, cluster.get("clusterName", carn), {}, arn=carn))
            service_arns = ecs.list_services(cluster=carn).get("serviceArns", [])
            if not service_arns:
                continue
            services = ecs.describe_services(cluster=carn, services=service_arns).get("services", [])
            for svc in services:
                sarn = svc["serviceArn"]
                taskdef_arn = svc.get("taskDefinition")
                net_cfg = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                service_nodes.append(
                    self._node(
                        "ecs_service",
                        sarn,
                        svc.get("serviceName", sarn),
                        {
                            "cluster": carn,
                            "task_definition": taskdef_arn,
                            "load_balancer": [
                                {"target_group_arn": lb["targetGroupArn"]}
                                for lb in svc.get("loadBalancers", [])
                                if lb.get("targetGroupArn")
                            ],
                            "network_configuration": [
                                {
                                    "subnets": net_cfg.get("subnets", []),
                                    "security_groups": net_cfg.get("securityGroups", []),
                                }
                            ]
                            if net_cfg
                            else [],
                            "desired_count": svc.get("desiredCount"),
                            "running_count": svc.get("runningCount"),
                        },
                        arn=sarn,
                    )
                )
                if taskdef_arn and taskdef_arn not in seen_taskdefs:
                    seen_taskdefs.add(taskdef_arn)
        for taskdef_arn in seen_taskdefs:
            try:
                td = ecs.describe_task_definition(taskDefinition=taskdef_arn).get("taskDefinition", {})
            except Exception:
                continue
            taskdef_nodes.append(
                self._node(
                    "ecs_task_definition",
                    taskdef_arn,
                    td.get("family", taskdef_arn),
                    {
                        "cpu": td.get("cpu"),
                        "memory": td.get("memory"),
                        "container_definitions": [c.get("name") for c in td.get("containerDefinitions", [])],
                    },
                    arn=taskdef_arn,
                )
            )
        return cluster_nodes, service_nodes, taskdef_nodes

    # ---- serverless --------------------------------------------------------

    def discover_lambda_functions(self) -> list[Node]:
        lam = self._client("lambda")
        nodes = []
        for fn in lam.list_functions().get("Functions", []):
            arn = fn["FunctionArn"]
            vpc_config = fn.get("VpcConfig") or {}
            nodes.append(
                self._node(
                    "lambda",
                    arn,
                    fn.get("FunctionName", arn),
                    {
                        "runtime": fn.get("Runtime"),
                        "vpc_config": [
                            {
                                "subnet_ids": vpc_config.get("SubnetIds", []),
                                "security_group_ids": vpc_config.get("SecurityGroupIds", []),
                            }
                        ]
                        if vpc_config
                        else [],
                    },
                    arn=arn,
                )
            )
        return nodes

    # ---- API Gateway (REST / v1) --------------------------------------------

    def discover_api_gateways(self) -> tuple[list[Node], list[Node]]:
        """Returns (rest_apis, integrations). Integrations carry an
        `integration_uri` set to the bare Lambda ARN when the integration
        targets a Lambda function, so the linker can resolve it.
        """
        try:
            apigw = self._client("apigateway")
        except Exception:
            return [], []
        api_nodes, integration_nodes = [], []
        try:
            apis = apigw.get_rest_apis().get("items", [])
        except Exception:
            return [], []
        for api in apis:
            api_id = api["id"]
            api_nodes.append(self._node("api_gateway", api_id, api.get("name", api_id), {}))
            try:
                resources = apigw.get_resources(restApiId=api_id).get("items", [])
            except Exception:
                resources = []
            for res in resources:
                for method in (res.get("resourceMethods") or {}).keys():
                    try:
                        integration = apigw.get_integration(restApiId=api_id, resourceId=res["id"], httpMethod=method)
                    except Exception:
                        continue
                    uri = integration.get("uri", "")
                    match = _ARN_PATTERN.search(uri)
                    integration_id = f"{api_id}-{res['id']}-{method}"
                    integration_nodes.append(
                        self._node(
                            "api_gateway_integration",
                            integration_id,
                            integration_id,
                            {
                                "rest_api_id": api_id,
                                "http_method": method,
                                "integration_uri": match.group(0) if match else None,
                            },
                        )
                    )
        return api_nodes, integration_nodes

    def discover_all(self) -> Graph:
        """Run every discover_* method, tolerating individual failures (a
        service unavailable on this AWS/LocalStack edition, missing IAM
        permissions, etc.) so one broken service doesn't abort the whole run.
        Returns the partial graph plus records what failed in `self.errors`.
        """
        graph = Graph()
        self.errors: list[str] = []

        def _run(label: str, fn) -> list[Node]:
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - discovery must degrade gracefully
                self.errors.append(f"{label}: {exc}")
                return []

        simple_steps = [
            ("vpcs", self.discover_vpcs),
            ("subnets", self.discover_subnets),
            ("route_tables", self.discover_route_tables),
            ("security_groups", self.discover_security_groups),
            ("internet_gateways", self.discover_internet_gateways),
            ("nat_gateways", self.discover_nat_gateways),
            ("target_groups", self.discover_target_groups),
            ("lambda_functions", self.discover_lambda_functions),
        ]
        for label, fn in simple_steps:
            for node in _run(label, fn):
                graph.add_node(node)

        for node in _run("load_balancers", lambda: [n for group in self.discover_load_balancers() for n in group]):
            graph.add_node(node)
        for node in _run("ecs", lambda: [n for group in self.discover_ecs() for n in group]):
            graph.add_node(node)
        for node in _run("api_gateways", lambda: [n for group in self.discover_api_gateways() for n in group]):
            graph.add_node(node)

        return graph


def discover_all(region: Optional[str] = None) -> Graph:
    return AWSDiscoverer(region=region).discover_all()
