"""Regression tests: an `aws_lb` with load_balancer_type = "network" (and an
AWS load balancer with Type == "network") is an "nlb", not an "alb", on both
the Terraform and AWS sides, and every downstream consumer (linker, matcher,
reachability) still handles it.
"""
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from flowlens.aws.resources import elbv2
from flowlens.compare.matcher import match_nodes, split_graph
from flowlens.discover.aws import AWSDiscoverer
from flowlens.ingest.terraform import combine_config_and_state, ingest_path, parse_state_json
from flowlens.linking.linker import link_graph
from flowlens.models.graph import Graph, RelationshipType
from flowlens.reachability.engine import ReachabilityEngine

REGION = "us-east-1"


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _node(graph: Graph, address: str):
    return next(n for n in graph.nodes.values() if n.terraform_address == address)


def _edges(graph: Graph, rel: RelationshipType) -> set[tuple[str, str]]:
    by_id = {n.id: n.terraform_address or n.id for n in graph.nodes.values()}
    return {(by_id[e.source_node], by_id[e.target_node]) for e in graph.edges.values() if e.relationship_type == rel}


# ---- Terraform classification ------------------------------------------------


def test_terraform_network_lb_is_nlb(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_lb" "edge" {\n  name = "edge"\n  load_balancer_type = "network"\n}\n')
    node = _node(ingest_path(tmp_path), "aws_lb.edge")
    assert node.resource_type == "nlb"
    assert node.desired_state["load_balancer_type"] == "network"


def test_terraform_application_lb_is_alb(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_lb" "web" {\n  load_balancer_type = "application"\n}\n')
    assert _node(ingest_path(tmp_path), "aws_lb.web").resource_type == "alb"


def test_terraform_lb_without_type_defaults_to_alb(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_lb" "web" { name = "web" }\nresource "aws_alb" "legacy" { name = "old" }\n')
    graph = ingest_path(tmp_path)
    assert _node(graph, "aws_lb.web").resource_type == "alb"
    assert _node(graph, "aws_alb.legacy").resource_type == "alb"


def test_terraform_dynamic_lb_type_falls_back_to_alb(tmp_path):
    _write(tmp_path, "main.tf", """
variable "lb_type" { default = "network" }
resource "aws_lb" "dyn" {
  name               = "dyn"
  load_balancer_type = var.lb_type
}
resource "aws_lb" "gw" { load_balancer_type = "gateway" }
""")
    graph = ingest_path(tmp_path)  # must not raise
    dyn = _node(graph, "aws_lb.dyn")
    assert dyn.resource_type == "alb"  # not evaluated: deterministic fallback
    assert dyn.desired_state["load_balancer_type"] == "${var.lb_type}"
    assert _node(graph, "aws_lb.gw").resource_type == "alb"  # unsupported type: fallback


def test_terraform_nlb_with_count_and_dynamic_subnet_mapping(tmp_path):
    _write(tmp_path, "main.tf", """
locals { nlb_enabled = true }
resource "aws_lb" "nlb" {
  count              = local.nlb_enabled ? 1 : 0
  name               = "edge-nlb"
  load_balancer_type = "network"
  dynamic "subnet_mapping" {
    for_each = var.subnet_ids
    content { subnet_id = subnet_mapping.value }
  }
}
""")
    graph = ingest_path(tmp_path)
    node = _node(graph, "aws_lb.nlb")
    assert node.id == "tf:aws_lb.nlb"  # TF-only identity is type-independent
    assert node.resource_type == "nlb"


def test_terraform_state_nlb_gets_same_id_as_aws_discovery(tmp_path):
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/edge/1"
    state = parse_state_json({"values": {"root_module": {"resources": [
        {"mode": "managed", "type": "aws_lb", "name": "edge", "address": "aws_lb.edge",
         "values": {"id": arn, "arn": arn, "name": "edge", "load_balancer_type": "network"}},
        {"mode": "managed", "type": "aws_lb", "name": "web", "address": "aws_lb.web",
         "values": {"id": "arn:web", "arn": "arn:web", "name": "web", "load_balancer_type": "application"}},
    ]}}})
    assert f"nlb:{arn}" in state.nodes and state.nodes[f"nlb:{arn}"].resource_type == "nlb"
    assert "alb:arn:web" in state.nodes

    _write(tmp_path, "main.tf", 'resource "aws_lb" "edge" {\n  name = "edge"\n  load_balancer_type = "network"\n}\n')
    combined = combine_config_and_state(ingest_path(tmp_path), state)
    assert "tf:aws_lb.edge" not in combined.nodes
    assert combined.nodes[f"nlb:{arn}"].terraform_address == "aws_lb.edge"


# ---- AWS discovery -----------------------------------------------------------


def _lb_stack():
    ec2c = boto3.client("ec2", region_name=REGION)
    v = ec2c.create_vpc(CidrBlock="10.7.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2c.create_subnet(VpcId=v, CidrBlock="10.7.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    s2 = ec2c.create_subnet(VpcId=v, CidrBlock="10.7.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    lbc = boto3.client("elbv2", region_name=REGION)
    alb = lbc.create_load_balancer(Name="web", Subnets=[s1, s2], Type="application")["LoadBalancers"][0]["LoadBalancerArn"]
    nlb = lbc.create_load_balancer(Name="edge", Subnets=[s1, s2], Type="network")["LoadBalancers"][0]["LoadBalancerArn"]
    return v, (s1, s2), alb, nlb


@mock_aws
def test_aws_discovery_classifies_alb_and_nlb(aws_credentials):
    _v, _subnets, alb_arn, nlb_arn = _lb_stack()
    items = {i["arn"]: i for i in elbv2.scan_load_balancers(boto3.Session(region_name=REGION), REGION)}
    assert items[alb_arn]["resource_type"] == "alb"
    assert items[nlb_arn]["resource_type"] == "nlb"
    assert items[nlb_arn]["actual_state"]["load_balancer_type"] == "network"
    assert items[nlb_arn]["actual_state"]["type"] == "network"

    discoverer = AWSDiscoverer(region=REGION, session=boto3.Session(region_name=REGION))
    graph = discoverer.discover_all()
    assert graph.nodes[f"alb:{alb_arn}"].resource_type == "alb"
    assert graph.nodes[f"nlb:{nlb_arn}"].resource_type == "nlb"
    assert discoverer.report.scanned["alb"] == 1 and discoverer.report.scanned["nlb"] == 1
    # each load balancer is emitted exactly once by the module-level scan()
    assert sorted(i["arn"] for i in elbv2.scan(boto3.Session(region_name=REGION), REGION) if i["arn"] in (alb_arn, nlb_arn)) == sorted(
        [alb_arn, nlb_arn]
    )


# ---- TF <-> AWS matching -----------------------------------------------------


@mock_aws
def test_terraform_nlb_matches_aws_nlb(aws_credentials, tmp_path):
    _v, _subnets, alb_arn, nlb_arn = _lb_stack()
    _write(tmp_path, "main.tf", """
resource "aws_lb" "edge" {
  name               = "edge"
  load_balancer_type = "network"
}
resource "aws_lb" "web" {
  name               = "web"
  load_balancer_type = "application"
}
""")
    desired, _ = split_graph(ingest_path(tmp_path))
    _, actual = split_graph(AWSDiscoverer(region=REGION, session=boto3.Session(region_name=REGION)).discover_all())
    lbs = [a for a in actual if a.resource_type in ("alb", "nlb")]
    result = match_nodes(desired, lbs)
    pairs = {(d.terraform_address, a.id, by) for d, a, by in result.pairs}
    assert ("aws_lb.edge", f"nlb:{nlb_arn}", "name") in pairs
    assert ("aws_lb.web", f"alb:{alb_arn}", "name") in pairs
    assert not result.terraform_only and not result.aws_only


# ---- linking / reachability --------------------------------------------------

NLB_TO_ALB = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "a" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_subnet" "b" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
}
resource "aws_security_group" "alb" { vpc_id = aws_vpc.main.id }
resource "aws_lb" "nlb" {
  name               = "edge-nlb"
  load_balancer_type = "network"
  subnet_mapping { subnet_id = aws_subnet.a.id }
  subnet_mapping { subnet_id = aws_subnet.b.id }
}
resource "aws_lb" "alb" {
  name               = "app-alb"
  internal           = true
  load_balancer_type = "application"
  subnets            = [aws_subnet.a.id, aws_subnet.b.id]
  security_groups    = [aws_security_group.alb.id]
}
resource "aws_lb_target_group" "to_alb" {
  name        = "to-alb"
  port        = 443
  protocol    = "TCP"
  target_type = "alb"
  vpc_id      = aws_vpc.main.id
}
resource "aws_lb_target_group_attachment" "alb" {
  target_group_arn = aws_lb_target_group.to_alb.arn
  target_id        = aws_lb.alb.id
  port             = 443
}
resource "aws_lb_listener" "nlb" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.to_alb.arn
  }
}
"""


def test_nlb_to_target_group_to_alb_is_linked(tmp_path):
    _write(tmp_path, "main.tf", NLB_TO_ALB)
    graph = link_graph(ingest_path(tmp_path))
    assert _node(graph, "aws_lb.nlb").resource_type == "nlb"
    assert _node(graph, "aws_lb.alb").resource_type == "alb"

    assert ("aws_lb_listener.nlb", "aws_lb.nlb") in _edges(graph, RelationshipType.DEPENDS_ON)
    assert ("aws_lb_listener.nlb", "aws_lb_target_group.to_alb") in _edges(graph, RelationshipType.FORWARDS_TO)
    member_of = _edges(graph, RelationshipType.MEMBER_OF)
    assert {("aws_lb.nlb", "aws_subnet.a"), ("aws_lb.nlb", "aws_subnet.b")} <= member_of  # NLB handler ran
    assert {("aws_lb.alb", "aws_subnet.a"), ("aws_lb.alb", "aws_subnet.b")} <= member_of  # ALB unchanged
    assert ("aws_security_group.alb", "aws_lb.alb") in _edges(graph, RelationshipType.ALLOWS)

    # Reachability sees the NLB as a load balancer endpoint fronting the ALB.
    result = ReachabilityEngine(graph).analyze("internet", "aws_lb.alb", "tcp", 443)
    assert any("NLB edge-nlb (listener TCP:443) -> target group to-alb" in c["label"] for c in result.to_dict()["candidates"])


@mock_aws
def test_aws_nlb_listener_links_to_nlb(aws_credentials):
    v, _subnets, _alb, nlb_arn = _lb_stack()
    lbc = boto3.client("elbv2", region_name=REGION)
    tg = lbc.create_target_group(Name="tcp", Protocol="TCP", Port=443, VpcId=v, TargetType="instance")["TargetGroups"][0]
    listener = lbc.create_listener(LoadBalancerArn=nlb_arn, Protocol="TCP", Port=443,
                                   DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
    listener_arn = listener["Listeners"][0]["ListenerArn"]

    graph = link_graph(AWSDiscoverer(region=REGION, session=boto3.Session(region_name=REGION)).discover_all())
    pairs = _edges(graph, RelationshipType.DEPENDS_ON)
    assert (f"listener:{listener_arn}", f"nlb:{nlb_arn}") in pairs
    assert any(e.source_node == f"nlb:{nlb_arn}" and e.relationship_type == RelationshipType.MEMBER_OF for e in graph.edges.values())
