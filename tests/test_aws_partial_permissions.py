"""AccessDenied on one resource type must not abort the whole AWS scan."""
import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from flowlens.discover.aws import AWSDiscoverer, is_permission_error


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _deny(operation: str, code: str = "UnauthorizedOperation"):
    def handler(**_kwargs):
        raise ClientError(
            {"Error": {"Code": code, "Message": f"not authorized to perform {operation}"}, "ResponseMetadata": {"HTTPStatusCode": 403}},
            operation,
        )

    return handler


class DenyingSession(boto3.Session):
    """A real (moto-backed) session whose clients raise AccessDenied for the
    given "<service>.<Operation>" names, via botocore's before-call hook.
    """

    def __init__(self, denied: dict[str, str], **kwargs):
        super().__init__(**kwargs)
        self._denied = denied

    def client(self, service_name, *args, **kwargs):
        c = super().client(service_name, *args, **kwargs)
        for op, code in self._denied.items():
            svc, name = op.split(".")
            if svc == service_name:
                c.meta.events.register(f"before-call.{c.meta.service_model.service_id.hyphenize()}.{name}", _deny(name, code))
        return c


@mock_aws
def test_access_denied_on_one_resource_type_does_not_crash_scan():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")
    ec2.create_security_group(GroupName="web", Description="d", VpcId=vpc["VpcId"])

    session = DenyingSession({"ec2.DescribeSubnets": "UnauthorizedOperation"}, region_name="us-east-1")
    discoverer = AWSDiscoverer(region="us-east-1", session=session)
    graph = discoverer.discover_all()  # must not raise

    types = {n.resource_type for n in graph.nodes.values()}
    assert "subnet" not in types
    assert {"vpc", "security_group", "route_table"} <= types  # the rest of the scan carried on
    assert f"vpc:{vpc['VpcId']}" in graph.nodes

    report = graph.metadata["aws_scan"]
    assert report["partial"] is True
    assert report["unresolved_resource_types"] == ["subnet"]
    assert report["denied_permissions"] == ["ec2:DescribeSubnets"]
    assert report["denied"]["subnet"]["code"] == "UnauthorizedOperation"
    assert "subnet" not in report["scanned"] and report["scanned"]["vpc"] >= 1
    assert all(n.metadata.get("aws_scan_partial") for n in graph.nodes.values())
    assert any("subnet: access denied" in e for e in discoverer.errors)


@mock_aws
def test_denials_across_services_are_all_summarized():
    session = DenyingSession(
        {"lambda.ListFunctions": "AccessDeniedException", "ecs.ListClusters": "AccessDeniedException"},
        region_name="us-east-1",
    )
    discoverer = AWSDiscoverer(region="us-east-1", session=session)
    graph = discoverer.discover_all()
    report = graph.metadata["aws_scan"]
    assert report["denied_permissions"] == ["ecs:ListClusters", "lambda:ListFunctions"]
    assert set(report["unresolved_resource_types"]) == {"lambda", "ecs_cluster", "ecs_service", "ecs_task_definition"}
    assert "vpc" in report["scanned"]


@mock_aws
def test_non_permission_errors_are_recorded_separately(monkeypatch):
    from flowlens.aws.resources import vpc as vpc_module

    def boom(session, region):
        raise ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "DescribeNatGateways")

    monkeypatch.setitem(vpc_module.RESOURCE_SCANNERS, "nat_gateway", boom)
    discoverer = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1"))
    report = discoverer.discover_all().metadata["aws_scan"]
    assert report["denied"] == {}
    assert "nat_gateway" in report["errors"]
    assert report["unresolved_resource_types"] == ["nat_gateway"]


@mock_aws
def test_clean_scan_is_not_partial():
    discoverer = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1"))
    report = discoverer.discover_all().metadata["aws_scan"]
    assert report["partial"] is False and report["denied_permissions"] == []


def test_is_permission_error_classification():
    def err(code, status=400):
        return ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, "Op")

    assert is_permission_error(err("AccessDenied"))
    assert is_permission_error(err("AccessDeniedException"))
    assert is_permission_error(err("UnauthorizedOperation"))
    assert is_permission_error(err("SomethingElse", status=403))
    assert not is_permission_error(err("Throttling"))
    assert not is_permission_error(ValueError("x"))


@mock_aws
def test_denied_load_balancer_scan_marks_alb_and_nlb_unresolved():
    session = DenyingSession({"elbv2.DescribeLoadBalancers": "AccessDenied"}, region_name="us-east-1")
    report = AWSDiscoverer(region="us-east-1", session=session).discover_all().metadata["aws_scan"]
    # Both LB types come from one API call; a Terraform NLB must not look "terraform only".
    assert {"alb", "nlb"} <= set(report["unresolved_resource_types"])
    assert report["denied"]["nlb"]["permission"] == "elasticloadbalancing:DescribeLoadBalancers"
