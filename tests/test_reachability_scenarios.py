"""End-to-end reachability: Terraform-only scenarios through the CLI, the
HTTP API, and a moto-backed read-only AWS scan. No real AWS / LocalStack.
"""
import json
from pathlib import Path

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws
from typer.testing import CliRunner

from flowlens.api.app import create_app
from flowlens.cli import app
from flowlens.discover.aws import AWSDiscoverer
from flowlens.linking.linker import link_graph
from flowlens.reachability import ReachabilityEngine

SCENARIOS = Path(__file__).parent.parent / "examples" / "reachability"
runner = CliRunner()


def _run(*args):
    return runner.invoke(app, list(args), catch_exceptions=False)


def _scan(name: str, db: str) -> None:
    assert _run("scan", str(SCENARIOS / name), "--db", db).exit_code == 0


def _reach_json(db: str, *args) -> dict:
    result = _run("reachability", *args, "--json", "--db", db)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


@pytest.mark.parametrize(
    ("scenario", "expected", "blocked_check"),
    [("allowed", "ALLOWED", None), ("blocked", "BLOCKED", "security_group_ingress"), ("unknown", "UNKNOWN", "security_group")],
)
def test_terraform_scenarios(tmp_db_path, scenario, expected, blocked_check):
    _scan(scenario, tmp_db_path)
    data = _reach_json(tmp_db_path, "internet", "aws_ecs_service.app", "--protocol", "tcp", "--port", "443")
    assert data["overall_status"] == expected
    assert [h["kind"] for h in data["path"]] == ["network", "forward", "network"]
    assert data["path"][1]["port_in"] == "443" and data["path"][1]["port_out"] == "8080"
    if blocked_check:
        assert blocked_check in data["blocked_at"]


def test_connected_topology_but_blocked(tmp_db_path):
    """`flowlens path` finds a topology path, yet traffic is BLOCKED."""
    _scan("blocked", tmp_db_path)
    path = _run("path", "aws_lb.web", "aws_ecs_service.app", "--undirected", "--db", tmp_db_path)
    assert path.exit_code == 0 and "Path found" in path.output
    text = _run("reachability", "internet", "aws_ecs_service.app", "--port", "443", "--db", tmp_db_path).output
    assert "RESULT: BLOCKED" in text
    assert "[FAIL] hop 3 security_group_ingress: demo-app-sg does not permit TCP/8080 from ALB demo-alb" in text
    assert "ports allowed for this peer: 80" in text
    assert "Suggested investigation: Check whether demo-app-sg should allow ingress TCP/8080" in text


def test_connected_topology_but_unknown(tmp_db_path):
    _scan("unknown", tmp_db_path)
    data = _reach_json(tmp_db_path, "aws_lb.web", "aws_ecs_service.app", "--port", "8080")
    assert data["topology_connected"] is True
    assert data["overall_status"] == "UNKNOWN"
    assert any("var.app_security_group_ids" in u for u in data["uncertainties"])


def test_allowed_scenario_text_report(tmp_db_path):
    _scan("allowed", tmp_db_path)
    text = _run("reachability", "internet", "aws_ecs_service.app", "--protocol", "tcp", "--port", "443", "--db", tmp_db_path).output
    for expected in (
        "FlowLens Reachability Analysis",
        "PATH",
        "Internet -> TCP/443 -> ALB demo-alb (listener HTTPS:443) -> target group demo-app-tg (port 8080)"
        " -> TCP/8080 -> ECS service demo-app",
        "VALIDATION",
        "[PASS] hop 1 security_group_ingress: demo-alb-sg ingress permits TCP/443 from Internet",
        "[PASS] hop 2 target_port: port transition: listener 443 -> target port 8080",
        "PUBLIC  demo-public-a",
        "PRIVATE demo-private-a",
        "RESULT: ALLOWED",
    ):
        assert expected in text, expected
    assert "\x1b[" not in text  # readable without color


def test_multiple_candidates_one_allowed(tmp_db_path):
    _scan("allowed", tmp_db_path)
    data = _reach_json(tmp_db_path, "internet", "aws_ecs_service.app", "--port", "443")
    assert sorted(c["status"] for c in data["candidates"]) == ["ALLOWED", "NOT_APPLICABLE"]


def test_private_ecs_behind_alb_has_no_misleading_public_ip_failure(tmp_db_path):
    """The ECS service is reached privately through the ALB: its missing public IP
    is NOT_APPLICABLE to that path, not a [FAIL], and the result stays ALLOWED."""
    _scan("allowed", tmp_db_path)
    args = ("internet", "aws_ecs_service.app", "--protocol", "tcp", "--port", "443")
    data = _reach_json(tmp_db_path, *args)
    assert data["overall_status"] == "ALLOWED"
    direct = next(c for c in data["candidates"] if not c["chosen"])
    assert direct["status"] == "NOT_APPLICABLE"
    assert direct["reason"] == ("ECS service demo-app public IP not required for this path: "
                                "it is reached privately through ALB demo-alb")
    text = _run("reachability", *args, "--db", tmp_db_path).output
    assert "RESULT: ALLOWED" in text
    assert "no public IP" not in text and "[FAIL]" not in text
    assert "[ -- ] Internet -> TCP/443 -> ECS service demo-app" in text
    assert "public IP not required for this path" in text


def test_egress_from_private_service_via_nat(tmp_db_path):
    _scan("allowed", tmp_db_path)
    data = _reach_json(tmp_db_path, "aws_ecs_service.app", "internet", "--port", "443")
    assert data["overall_status"] == "ALLOWED"
    assert any("NAT gateway demo-nat sits in a PUBLIC subnet" in e for e in data["evidence"])


def test_reachability_cli_errors(tmp_db_path):
    _scan("allowed", tmp_db_path)
    bad = _run("reachability", "internet", "aws_vpc.main", "--port", "443", "--db", tmp_db_path)
    assert bad.exit_code == 1 and "not a traffic endpoint" in bad.output
    assert _run("reachability", "internet", "aws_lb.web", "--port", "99999", "--db", tmp_db_path).exit_code == 1


def test_reachability_listed_in_help_and_path_unchanged(tmp_db_path):
    assert "reachability" in _run("--help").output
    _run("scan", str(Path(__file__).parent.parent / "examples" / "terraform"), "--db", tmp_db_path)
    data = json.loads(_run("path", "aws_lb_listener.https", "aws_vpc.main", "--json", "--db", tmp_db_path).output)
    assert data["nodes"] == ["tf:aws_lb_listener.https", "tf:aws_lb_target_group.app", "tf:aws_vpc.main"]


def test_api_reachability_endpoints(tmp_db_path):
    _scan("blocked", tmp_db_path)
    client = TestClient(create_app(tmp_db_path))
    eps = client.get("/api/reachability/endpoints").json()["endpoints"]
    assert eps[0]["id"] == "internet" and any(e["id"] == "tf:aws_ecs_service.app" for e in eps)
    resp = client.post("/api/reachability", json={"source": "internet", "destination": "tf:aws_ecs_service.app",
                                                  "protocol": "tcp", "port": 443})
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_status"] == "BLOCKED" and data["checks"] and data["path"]
    assert all(h["status"] in ("ALLOWED", "BLOCKED", "UNKNOWN", "NOT_APPLICABLE") for h in data["path"])
    assert client.post("/api/reachability", json={"source": "internet", "destination": "nope"}).status_code == 400
    assert client.get("/api/graph").status_code == 200
    assert b"Analyze Reachability" in client.get("/").content


@mock_aws
def test_aws_scanned_stack_reachability_end_to_end():
    """Build a stack in moto, discover it read-only, and analyze it."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.40.0.0/16")["Vpc"]["VpcId"]
    pub = [ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.40.{i}.0/24", AvailabilityZone=f"us-east-1{z}")["Subnet"]["SubnetId"]
           for i, z in ((1, "a"), (2, "b"))]
    app_subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.40.11.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    for s in pub:
        ec2.associate_route_table(RouteTableId=rt, SubnetId=s)
    alb_sg = ec2.create_security_group(GroupName="alb", Description="d", VpcId=vpc)["GroupId"]
    app_sg = ec2.create_security_group(GroupName="app", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=alb_sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_ingress(
        GroupId=app_sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [{"GroupId": alb_sg}]}])

    elb = boto3.client("elbv2", region_name="us-east-1")
    lb = elb.create_load_balancer(Name="web", Subnets=pub, SecurityGroups=[alb_sg], Scheme="internet-facing")["LoadBalancers"][0]
    tg = elb.create_target_group(Name="app", Protocol="HTTP", Port=8080, VpcId=vpc, TargetType="ip")["TargetGroups"][0]["TargetGroupArn"]
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=443,
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
    ecs = boto3.client("ecs", region_name="us-east-1")
    cluster = ecs.create_cluster(clusterName="shop")["cluster"]["clusterArn"]
    td = ecs.register_task_definition(
        family="app", networkMode="awsvpc",
        containerDefinitions=[{"name": "app", "image": "nginx", "memory": 128, "portMappings": [{"containerPort": 8080}]}],
    )["taskDefinition"]["taskDefinitionArn"]
    svc = ecs.create_service(
        cluster=cluster, serviceName="app", taskDefinition=td, desiredCount=1,
        loadBalancers=[{"targetGroupArn": tg, "containerName": "app", "containerPort": 8080}],
        networkConfiguration={"awsvpcConfiguration": {"subnets": [app_subnet], "securityGroups": [app_sg], "assignPublicIp": "DISABLED"}},
    )["service"]["serviceArn"]

    graph = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1")).discover_all()
    link_graph(graph)
    engine = ReachabilityEngine(graph)
    result = engine.analyze("internet", svc, "tcp", 443)
    assert result.overall_status.value == "ALLOWED", [(c.check_type, c.status.value, c.reason) for c in result.checks]
    assert any(igw in e for e in result.evidence) and any(app_sg in e for e in result.evidence)

    ec2.revoke_security_group_ingress(
        GroupId=app_sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [{"GroupId": alb_sg}]}])
    graph = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1")).discover_all()
    blocked = ReachabilityEngine(link_graph(graph)).analyze("internet", svc, "tcp", 443)
    assert blocked.overall_status.value == "BLOCKED" and blocked.blocked_at.endswith("security_group_ingress")
