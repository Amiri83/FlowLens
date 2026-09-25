"""Per-service scanners against moto (no real AWS account)."""
import io
import json
import zipfile

import boto3
import pytest
from moto import mock_aws

from flowlens.aws.resources import SERVICE_MODULES, apigateway, ec2, ecs, elbv2, lambda_, vpc
from flowlens.discover.aws import AWSDiscoverer
from flowlens.linking.linker import link_graph

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _by_type(items):
    out = {}
    for item in items:
        out.setdefault(item["resource_type"], []).append(item)
    return out


def test_every_module_exposes_scan_and_scanners():
    for module, _iam in SERVICE_MODULES:
        assert callable(module.scan)
        assert module.RESOURCE_SCANNERS


@mock_aws
def test_vpc_and_ec2_scanners():
    client = boto3.client("ec2", region_name=REGION)
    v = client.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    client.create_subnet(VpcId=v, CidrBlock="10.1.1.0/24")
    igw = client.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    client.attach_internet_gateway(InternetGatewayId=igw, VpcId=v)
    client.create_security_group(GroupName="web", Description="d", VpcId=v)

    session = boto3.Session(region_name=REGION)
    items = _by_type(vpc.scan(session, REGION) + ec2.scan(session, REGION))
    assert any(i["cloud_id"] == v and i["actual_state"]["cidr_block"] == "10.1.0.0/16" for i in items["vpc"])
    assert any(i["actual_state"]["vpc_id"] == v for i in items["subnet"])
    assert any(i["cloud_id"] == igw and i["actual_state"]["vpc_id"] == v for i in items["internet_gateway"])
    assert any(i["name"] == "web" for i in items["security_group"])
    assert "route_table" in items and "route" in items


@mock_aws
def test_elbv2_scanner_and_linking_listener_to_target_group():
    ec2c = boto3.client("ec2", region_name=REGION)
    v = ec2c.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2c.create_subnet(VpcId=v, CidrBlock="10.2.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    s2 = ec2c.create_subnet(VpcId=v, CidrBlock="10.2.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    lbc = boto3.client("elbv2", region_name=REGION)
    lb_arn = lbc.create_load_balancer(Name="web", Subnets=[s1, s2])["LoadBalancers"][0]["LoadBalancerArn"]
    tg_arn = lbc.create_target_group(Name="app", Protocol="HTTP", Port=8080, VpcId=v)["TargetGroups"][0]["TargetGroupArn"]
    lbc.create_listener(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    items = _by_type(elbv2.scan(boto3.Session(region_name=REGION), REGION))
    assert items["alb"][0]["arn"] == lb_arn and sorted(items["alb"][0]["actual_state"]["subnets"]) == sorted([s1, s2])
    assert items["target_group"][0]["actual_state"]["port"] == 8080
    assert items["listener"][0]["actual_state"]["default_action"] == [{"target_group_arn": tg_arn}]

    graph = AWSDiscoverer(region=REGION, session=boto3.Session(region_name=REGION)).discover_all()
    link_graph(graph)
    listener_id = f"listener:{items['listener'][0]['cloud_id']}"
    assert any(e.source_node == listener_id and e.target_node == f"target_group:{tg_arn}" for e in graph.edges.values())


@mock_aws
def test_ecs_scanner():
    ecsc = boto3.client("ecs", region_name=REGION)
    cluster = ecsc.create_cluster(clusterName="shop")["cluster"]["clusterArn"]
    td = ecsc.register_task_definition(family="shop-app", containerDefinitions=[{"name": "app", "image": "nginx", "memory": 128}])
    td_arn = td["taskDefinition"]["taskDefinitionArn"]
    ecsc.create_service(cluster=cluster, serviceName="shop-app", taskDefinition=td_arn, desiredCount=1)

    items = _by_type(ecs.scan(boto3.Session(region_name=REGION), REGION))
    assert items["ecs_cluster"][0]["arn"] == cluster
    assert items["ecs_service"][0]["actual_state"]["task_definition"] == td_arn
    assert items["ecs_task_definition"][0]["actual_state"]["container_definitions"] == ["app"]


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.py", "def handler(e, c):\n    return e\n")
    return buf.getvalue()


@mock_aws
def test_lambda_and_apigateway_scanners():
    iam = boto3.client("iam", region_name=REGION)
    role = iam.create_role(
        RoleName="fn",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
    )["Role"]["Arn"]
    fn_arn = boto3.client("lambda", region_name=REGION).create_function(
        FunctionName="hello", Runtime="python3.12", Role=role, Handler="app.handler", Code={"ZipFile": _zip()}
    )["FunctionArn"]

    apigw = boto3.client("apigateway", region_name=REGION)
    api_id = apigw.create_rest_api(name="shop-api")["id"]
    root = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{fn_arn}/invocations",
    )

    session = boto3.Session(region_name=REGION)
    fns = lambda_.scan(session, REGION)
    assert fns[0]["arn"] == fn_arn and fns[0]["actual_state"]["runtime"] == "python3.12"
    items = _by_type(apigateway.scan(session, REGION))
    assert items["api_gateway"][0]["name"] == "shop-api"
    assert items["api_gateway_integration"][0]["actual_state"]["integration_uri"] == fn_arn


def test_endpoint_env_vars_for_localstack(monkeypatch):
    from flowlens.aws.resources._common import endpoint_for

    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    monkeypatch.setenv("AWS_ENDPOINT_URL_ECS", "http://localhost:4567")
    assert endpoint_for("ec2") == "http://localhost:4566"
    assert endpoint_for("ecs") == "http://localhost:4567"
