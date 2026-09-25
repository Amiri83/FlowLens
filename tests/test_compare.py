from flowlens.compare.diff import CompareStatus, compare_graph, compare_nodes, diff_attributes, summarize
from flowlens.compare.matcher import match_nodes, split_graph
from flowlens.models.graph import Graph, Node, Source


def tf(node_id, rtype, *, address=None, name=None, arn=None, **state):
    return Node(
        id=node_id,
        name=name or (address.split(".")[-1] if address else node_id),
        resource_type=rtype,
        source=Source.TERRAFORM,
        terraform_address=address,
        aws_arn=arn,
        desired_state=state,
    )


def aws(node_id, rtype, *, name=None, arn=None, **state):
    return Node(id=node_id, name=name or node_id, resource_type=rtype, source=Source.AWS, aws_arn=arn, actual_state=state)


# ---- matcher ---------------------------------------------------------------


def test_match_by_node_id():
    r = match_nodes([tf("vpc:vpc-1", "vpc", address="aws_vpc.main")], [aws("vpc:vpc-1", "vpc")])
    assert [(d.id, a.id, by) for d, a, by in r.pairs] == [("vpc:vpc-1", "vpc:vpc-1", "id")]


def test_match_by_arn():
    arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc"
    r = match_nodes([tf("tf:aws_lb_target_group.app", "target_group", address="aws_lb_target_group.app", arn=arn)],
                    [aws(f"target_group:{arn}", "target_group", arn=arn)])
    assert r.pairs[0][2] == "arn"


def test_match_by_resource_id_from_state():
    r = match_nodes([tf("tf:aws_subnet.a", "subnet", address="aws_subnet.a", id="subnet-9")], [aws("subnet:subnet-9", "subnet")])
    assert r.pairs[0][2] == "resource_id"


def test_match_by_terraform_address():
    actual = aws("sg:sg-1", "security_group")
    actual.terraform_address = "aws_security_group.web"
    r = match_nodes([tf("tf:aws_security_group.web", "security_group", address="aws_security_group.web")], [actual])
    assert r.pairs[0][2] == "terraform_address"


def test_match_by_unique_name_and_label_is_not_a_name():
    desired = [tf("tf:aws_lb.web", "alb", address="aws_lb.web", name="web")]
    desired[0].desired_state["name"] = "shop-alb"
    r = match_nodes(desired, [aws("alb:arn-x", "alb", name="shop-alb"), aws("alb:arn-y", "alb", name="web")])
    # Matched on the real `name` attribute, not on the Terraform label "web".
    assert [(a.id, by) for _d, a, by in r.pairs] == [("alb:arn-x", "name")]
    assert [a.id for a in r.aws_only] == ["alb:arn-y"]


def test_resource_type_must_agree():
    r = match_nodes([tf("tf:aws_vpc.x", "vpc", address="aws_vpc.x", id="shared")], [aws("subnet:shared", "subnet")])
    assert not r.pairs and len(r.terraform_only) == 1 and len(r.aws_only) == 1


def test_split_graph_puts_merged_node_on_both_sides():
    g = Graph()
    g.add_node(tf("vpc:vpc-1", "vpc", cidr_block="10.0.0.0/16"))
    g.add_node(aws("vpc:vpc-1", "vpc", cidr_block="10.0.0.0/16"))
    desired, actual = split_graph(g)
    assert [n.id for n in desired] == [n.id for n in actual] == ["vpc:vpc-1"]


# ---- statuses -----------------------------------------------------------------


def _status_of(results, rid):
    return next(r for r in results if rid in (r.desired_id, r.actual_id)).status


def test_status_matched():
    results = compare_nodes([tf("vpc:vpc-1", "vpc", cidr_block="10.0.0.0/16")], [aws("vpc:vpc-1", "vpc", cidr_block="10.0.0.0/16")])
    assert _status_of(results, "vpc:vpc-1") == CompareStatus.MATCHED


def test_status_different_reports_attribute():
    results = compare_nodes([tf("vpc:vpc-1", "vpc", cidr_block="10.0.0.0/16")], [aws("vpc:vpc-1", "vpc", cidr_block="10.9.0.0/16")])
    (r,) = results
    assert r.status == CompareStatus.DIFFERENT
    assert [(d.key, d.desired, d.actual) for d in r.differences] == [("cidr_block", "10.0.0.0/16", "10.9.0.0/16")]


def test_status_terraform_only():
    results = compare_nodes([tf("tf:aws_vpc.main", "vpc", address="aws_vpc.main")], [])
    assert _status_of(results, "tf:aws_vpc.main") == CompareStatus.TERRAFORM_ONLY


def test_status_aws_only():
    results = compare_nodes([], [aws("vpc:vpc-default", "vpc")])
    assert _status_of(results, "vpc:vpc-default") == CompareStatus.AWS_ONLY


def test_status_unknown_when_resource_type_was_not_readable():
    results = compare_nodes([tf("tf:aws_lambda_function.f", "lambda", address="aws_lambda_function.f")], [], ["lambda"])
    (r,) = results
    assert r.status == CompareStatus.UNKNOWN and "lambda" in r.reason


def test_status_unknown_when_name_is_ambiguous():
    d = tf("tf:aws_security_group.app", "security_group", address="aws_security_group.app", name="app-sg")
    results = compare_nodes([d], [aws("security_group:sg-1", "security_group", name="app-sg"),
                                  aws("security_group:sg-2", "security_group", name="app-sg")])
    assert _status_of(results, "tf:aws_security_group.app") == CompareStatus.UNKNOWN
    # The ambiguous candidates are not claimed as AWS_ONLY either.
    assert summarize(results) == {"MATCHED": 0, "TERRAFORM_ONLY": 0, "AWS_ONLY": 0, "DIFFERENT": 0, "UNKNOWN": 1}


def test_diff_ignores_interpolations_nested_blocks_and_type_noise():
    desired = {"vpc_id": "${aws_vpc.main.id}", "port": 443, "subnets": ["b", "a"], "ingress": [{"from_port": 1}], "cpu": "256"}
    actual = {"vpc_id": "vpc-1", "port": "443", "subnets": ["a", "b"], "ingress": [{"from_port": 2}], "cpu": 256}
    assert diff_attributes(desired, actual) == []


def test_compare_graph_uses_scan_report_for_unknown():
    g = Graph(metadata={"aws_scan": {"unresolved_resource_types": ["subnet"]}})
    g.add_node(tf("tf:aws_subnet.a", "subnet", address="aws_subnet.a"))
    g.add_node(tf("tf:aws_vpc.main", "vpc", address="aws_vpc.main"))
    statuses = {r.desired_id: r.status for r in compare_graph(g)}
    assert statuses == {"tf:aws_subnet.a": CompareStatus.UNKNOWN, "tf:aws_vpc.main": CompareStatus.TERRAFORM_ONLY}
