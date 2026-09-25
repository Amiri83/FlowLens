"""Network detail the reachability engine needs from read-only AWS scans
(moto only; the conftest fixture keeps ambient AWS/LocalStack env out).
"""
import re
from pathlib import Path

import boto3
from moto import mock_aws

from flowlens.aws.resources import ec2, ecs, elbv2, vpc

REGION = "us-east-1"
SRC = Path(__file__).parent.parent / "src" / "flowlens"


def _by_type(items):
    out = {}
    for item in items:
        out.setdefault(item["resource_type"], []).append(item)
    return out


@mock_aws
def test_security_group_rules_routes_and_nacls_are_captured():
    c = boto3.client("ec2", region_name=REGION)
    v = c.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    sn = c.create_subnet(VpcId=v, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    igw = c.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    c.attach_internet_gateway(InternetGatewayId=igw, VpcId=v)
    rt = c.create_route_table(VpcId=v)["RouteTable"]["RouteTableId"]
    c.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    c.associate_route_table(RouteTableId=rt, SubnetId=sn)
    alb_sg = c.create_security_group(GroupName="alb", Description="d", VpcId=v)["GroupId"]
    app_sg = c.create_security_group(GroupName="app", Description="d", VpcId=v)["GroupId"]
    c.authorize_security_group_ingress(
        GroupId=alb_sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    c.authorize_security_group_ingress(
        GroupId=app_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [{"GroupId": alb_sg}]}],
    )

    session = boto3.Session(region_name=REGION)
    items = _by_type(vpc.scan(session, REGION) + ec2.scan(session, REGION))
    sgs = {i["cloud_id"]: i["actual_state"] for i in items["security_group"]}
    assert {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}.items() <= sgs[alb_sg]["ingress"][0].items()
    assert sgs[app_sg]["ingress"][0]["security_groups"] == [alb_sg]
    assert sgs[app_sg]["egress"][0]["protocol"] == "-1"  # AWS default allow-all egress

    routes = [i["actual_state"] for i in items["route"] if i["actual_state"]["route_table_id"] == rt]
    assert {"target_type": "internet_gateway", "target_id": igw, "destination_cidr_block": "0.0.0.0/0"}.items() <= next(
        r for r in routes if r["destination_cidr_block"] == "0.0.0.0/0"
    ).items()
    assert any(r["target_type"] == "local" for r in routes)
    tables = {i["cloud_id"]: i["actual_state"] for i in items["route_table"]}
    assert tables[rt]["subnet_ids"] == [sn] and tables[rt]["main"] is False
    assert any(t["main"] and t["vpc_id"] == v for t in tables.values())

    acls = [i["actual_state"] for i in items["network_acl"] if i["actual_state"]["vpc_id"] == v]
    default = next(a for a in acls if a["is_default"])
    assert sn in default["subnet_ids"]
    assert any(e["action"] == "allow" and e["protocol"] == "-1" for e in default["ingress"])


@mock_aws
def test_listener_target_group_and_ecs_port_detail():
    c = boto3.client("ec2", region_name=REGION)
    v = c.create_vpc(CidrBlock="10.8.0.0/16")["Vpc"]["VpcId"]
    s1 = c.create_subnet(VpcId=v, CidrBlock="10.8.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    s2 = c.create_subnet(VpcId=v, CidrBlock="10.8.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    lbc = boto3.client("elbv2", region_name=REGION)
    lb = lbc.create_load_balancer(Name="web", Subnets=[s1, s2], Scheme="internet-facing")["LoadBalancers"][0]["LoadBalancerArn"]
    tg = lbc.create_target_group(Name="app", Protocol="HTTP", Port=8080, VpcId=v, TargetType="ip")["TargetGroups"][0]["TargetGroupArn"]
    lbc.create_listener(LoadBalancerArn=lb, Protocol="HTTP", Port=80, DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])

    ecsc = boto3.client("ecs", region_name=REGION)
    cluster = ecsc.create_cluster(clusterName="shop")["cluster"]["clusterArn"]
    td = ecsc.register_task_definition(
        family="app",
        networkMode="awsvpc",
        containerDefinitions=[
            {"name": "app", "image": "nginx", "memory": 128, "portMappings": [{"containerPort": 8080, "hostPort": 8080}]}
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ecsc.create_service(
        cluster=cluster,
        serviceName="app",
        taskDefinition=td,
        desiredCount=1,
        loadBalancers=[{"targetGroupArn": tg, "containerName": "app", "containerPort": 8080}],
        networkConfiguration={"awsvpcConfiguration": {"subnets": [s1], "securityGroups": [], "assignPublicIp": "DISABLED"}},
    )

    session = boto3.Session(region_name=REGION)
    lb_items = _by_type(elbv2.scan(session, REGION))
    assert lb_items["listener"][0]["actual_state"]["default_action_types"] == ["forward"]
    assert lb_items["target_group"][0]["actual_state"]["target_type"] == "ip"
    assert lb_items["alb"][0]["actual_state"]["internal"] is False

    ecs_items = _by_type(ecs.scan(session, REGION))
    svc = ecs_items["ecs_service"][0]["actual_state"]
    assert svc["load_balancer"] == [{"target_group_arn": tg, "container_name": "app", "container_port": 8080}]
    assert svc["network_configuration"][0]["assign_public_ip"] is False
    tdef = ecs_items["ecs_task_definition"][0]["actual_state"]
    assert tdef["network_mode"] == "awsvpc"
    assert tdef["port_mappings"][0]["container_port"] == 8080


def test_source_tree_issues_no_mutating_aws_calls():
    """Read-only guarantee: no boto3 mutating API call anywhere in src/."""
    mutating = re.compile(
        r"\.(create|delete|put|modify|update|authorize|revoke|register|deregister|attach|detach|associate|disassociate|"
        r"replace|run|terminate|start|stop|reboot|tag|untag|set)_[a-z_]+\("
    )
    offenders = [
        f"{p.relative_to(SRC)}:{i}: {line.strip()}"
        for p in SRC.rglob("*.py")
        for i, line in enumerate(p.read_text().splitlines(), 1)
        if mutating.search(line)
    ]
    assert offenders == []
