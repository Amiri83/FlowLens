"""Shared conventions for turning provider-specific resource identifiers into
the normalized node ids used across the graph, so a Terraform-sourced node and
an AWS-discovered node for the *same* real resource land on the same node id
and get merged by Graph.add_node().

Node id shape: "<normalized_type>:<cloud_id>", e.g. "vpc:vpc-0abc123".
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

#: Map a Terraform resource type (e.g. "aws_vpc") to FlowLens's normalized
#: resource_type (e.g. "vpc"). Anything not listed falls back to stripping
#: the leading "aws_" prefix, which covers most 1:1 cases automatically.
#: aws_lb / aws_alb are classified from their attributes (see below).
_TF_TYPE_OVERRIDES = {
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


#: Terraform types whose normalized type depends on `load_balancer_type`.
_TF_LOAD_BALANCER_TYPES = frozenset({"aws_lb", "aws_alb"})


def load_balancer_resource_type(lb_type: Any) -> str:
    """Canonical resource_type for an ELBv2 load balancer given its type as
    reported by Terraform (`load_balancer_type`) or AWS (`Type`).

    Only a literal "network" yields "nlb". Anything else — "application",
    missing, an unresolved HCL expression such as "${var.lb_type}", or an
    unsupported type — deterministically falls back to "alb" (the historical
    behaviour), so both sources agree for equivalent infrastructure.
    """
    return "nlb" if isinstance(lb_type, str) and lb_type.strip().lower() == "network" else "alb"


def normalize_terraform_type(tf_type: str, attributes: Mapping[str, Any] | None = None) -> str:
    """Map a Terraform type to FlowLens's resource_type. `attributes` (the
    resource's parsed body / state values) is only consulted for types whose
    classification depends on it (aws_lb: ALB vs NLB); dynamic values are
    never evaluated.
    """
    if tf_type in _TF_LOAD_BALANCER_TYPES:
        return load_balancer_resource_type((attributes or {}).get("load_balancer_type"))
    if tf_type in _TF_TYPE_OVERRIDES:
        return _TF_TYPE_OVERRIDES[tf_type]
    return tf_type[len("aws_"):] if tf_type.startswith("aws_") else tf_type


def make_node_id(resource_type: str, cloud_id: str) -> str:
    return f"{resource_type}:{cloud_id}"


def make_tf_only_node_id(terraform_address: str) -> str:
    """Fallback id for config-only resources that have no known cloud id yet."""
    return f"tf:{terraform_address}"


#: Leading module path of a Terraform address: zero or more
#: `module.<name>` steps, each optionally with an instance key (`[0]`,
#: `["a.b"]`), each followed by a dot.
_MODULE_PATH = re.compile(r'^(?:module\.[A-Za-z_][A-Za-z0-9_-]*(?:\[(?:"[^"]*"|[^\]]*)\])?\.)*')


def terraform_module_scope(terraform_address: str | None) -> str:
    """The module scope an address lives in, as a prefix ending in "." —
    "" for the root module. References written inside that module
    (`aws_security_group.this`) are relative to it:

        "aws_instance.web"                            -> ""
        "module.a.module.b.aws_lambda_function.this"  -> "module.a.module.b."
        'module.w["x"].aws_lambda_function.this'      -> 'module.w["x"].'
        "module.a" (the module call itself)           -> "" (its caller)
    """
    if not terraform_address:
        return ""
    return _MODULE_PATH.match(terraform_address).group(0)
