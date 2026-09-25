"""Per-service, read-only AWS scanners.

Each module exposes `scan(session, region) -> list[dict]` plus a
`RESOURCE_SCANNERS` mapping of resource_type -> scanner so the orchestrator
(flowlens.discover.aws) can isolate failures per resource type.
"""
from flowlens.aws.resources import apigateway, ec2, ecs, elbv2, lambda_, vpc

#: (module, IAM action prefix) in scan order. The IAM prefix is used to
#: report denied permissions as e.g. "ec2:DescribeSubnets".
SERVICE_MODULES = [
    (vpc, "ec2"),
    (ec2, "ec2"),
    (elbv2, "elasticloadbalancing"),
    (ecs, "ecs"),
    (lambda_, "lambda"),
    (apigateway, "apigateway"),
]

__all__ = ["SERVICE_MODULES", "apigateway", "ec2", "ecs", "elbv2", "lambda_", "vpc"]
