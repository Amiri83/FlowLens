"""The autouse conftest fixture must neutralize any ambient AWS/LocalStack
configuration so moto-mocked tests never reach a live endpoint.
"""
import os

import boto3
from moto import mock_aws


def test_no_endpoint_or_profile_leaks_into_tests():
    leaked = [k for k in os.environ if k.startswith(("AWS_ENDPOINT_URL", "AWS_SSO_")) or k in ("AWS_PROFILE", "AWS_S3_ENDPOINT")]
    assert leaked == []
    assert os.environ["AWS_ACCESS_KEY_ID"] == "testing"


@mock_aws
def test_boto3_client_uses_default_endpoint_under_moto():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    assert "localhost" not in ec2.meta.endpoint_url
    assert ec2.describe_vpcs()["Vpcs"]  # moto's default VPC, not LocalStack
