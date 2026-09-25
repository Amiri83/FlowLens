import os

import boto3
import pytest
from moto import mock_aws

from flowlens.discover.aws import AWSDiscoverer


@pytest.fixture(autouse=True)
def aws_credentials():
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.pop("AWS_ENDPOINT_URL", None)


@mock_aws
def test_discover_vpc_and_subnet():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    ec2.create_tags(Resources=[vpc["VpcId"]], Tags=[{"Key": "Name", "Value": "test-vpc"}])
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]

    discoverer = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1"))
    vpc_nodes = {n.id: n for n in discoverer.discover_vpcs()}
    subnet_nodes = {n.id: n for n in discoverer.discover_subnets()}

    # moto seeds a default VPC per region, so only assert on the one we created.
    our_vpc = vpc_nodes[f"vpc:{vpc['VpcId']}"]
    assert our_vpc.name == "test-vpc"
    assert our_vpc.source.value == "aws"

    our_subnet = subnet_nodes[f"subnet:{subnet['SubnetId']}"]
    assert our_subnet.actual_state["vpc_id"] == vpc["VpcId"]


@mock_aws
def test_discover_all_is_read_only_and_does_not_raise():
    boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.0.0.0/16")
    discoverer = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1"))
    graph = discoverer.discover_all()
    assert len(graph.nodes) >= 1
    assert all(n.source.value == "aws" for n in graph.nodes.values())


@mock_aws
def test_discover_security_group_and_peer_reference():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg1 = ec2.create_security_group(GroupName="sg1", Description="d", VpcId=vpc["VpcId"])["GroupId"]
    sg2 = ec2.create_security_group(GroupName="sg2", Description="d", VpcId=vpc["VpcId"])["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg2,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": sg1}]}],
    )

    discoverer = AWSDiscoverer(region="us-east-1", session=boto3.Session(region_name="us-east-1"))
    sg_nodes = {n.id: n for n in discoverer.discover_security_groups()}
    assert sg_nodes[f"security_group:{sg2}"].actual_state["source_security_group_id"] == [sg1]
