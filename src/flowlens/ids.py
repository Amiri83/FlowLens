"""Shared conventions for turning provider-specific resource identifiers into
the normalized node ids used across the graph, so a Terraform-sourced node and
an AWS-discovered node for the *same* real resource land on the same node id
and get merged by Graph.add_node().

Node id shape: "<normalized_type>:<cloud_id>", e.g. "vpc:vpc-0abc123".
"""
from __future__ import annotations

#: Map a Terraform resource type (e.g. "aws_vpc") to FlowLens's normalized
#: resource_type (e.g. "vpc"). Anything not listed falls back to stripping
#: the leading "aws_" prefix, which covers most 1:1 cases automatically.
_TF_TYPE_OVERRIDES = {
    "aws_lb": "alb",
    "aws_alb": "alb",
    "aws_lb_listener": "listener",
    "aws_alb_listener": "listener",
    "aws_lb_listener_rule": "listener_rule",
    "aws_lb_target_group": "target_group",
    "aws_alb_target_group": "target_group",
    "aws_ecs_cluster": "ecs_cluster",
    "aws_ecs_service": "ecs_service",
    "aws_ecs_task_definition": "ecs_task_definition",
    "aws_lambda_function": "lambda",
    "aws_api_gateway_rest_api": "api_gateway",
    "aws_api_gateway_resource": "api_gateway_resource",
    "aws_api_gateway_method": "api_gateway_method",
    "aws_api_gateway_integration": "api_gateway_integration",
    "aws_apigatewayv2_api": "api_gateway",
    "aws_internet_gateway": "internet_gateway",
    "aws_nat_gateway": "nat_gateway",
    "aws_route_table": "route_table",
    "aws_route_table_association": "route_table_association",
    "aws_route": "route",
    "aws_security_group": "security_group",
    "aws_security_group_rule": "security_group_rule",
    "aws_subnet": "subnet",
    "aws_vpc": "vpc",
}


def normalize_terraform_type(tf_type: str) -> str:
    if tf_type in _TF_TYPE_OVERRIDES:
        return _TF_TYPE_OVERRIDES[tf_type]
    return tf_type[len("aws_"):] if tf_type.startswith("aws_") else tf_type


def make_node_id(resource_type: str, cloud_id: str) -> str:
    return f"{resource_type}:{cloud_id}"


def make_tf_only_node_id(terraform_address: str) -> str:
    """Fallback id for config-only resources that have no known cloud id yet."""
    return f"tf:{terraform_address}"
