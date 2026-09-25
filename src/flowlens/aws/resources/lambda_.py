"""Lambda functions (with VPC attachment). Read-only lambda List* calls only.
Module is named lambda_ because `lambda` is a Python keyword.
"""
from __future__ import annotations

from typing import Any

from flowlens.aws.resources._common import client, resource

SERVICE = "lambda"


def scan_functions(session, region: str | None) -> list[dict[str, Any]]:
    lam = client(session, SERVICE, region)
    out = []
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page.get("Functions", []):
            arn = fn["FunctionArn"]
            vpc_config = fn.get("VpcConfig") or {}
            out.append(
                resource(
                    "lambda",
                    arn,
                    fn.get("FunctionName"),
                    {
                        "function_name": fn.get("FunctionName"),
                        "runtime": fn.get("Runtime"),
                        "handler": fn.get("Handler"),
                        "vpc_config": [
                            {
                                "subnet_ids": vpc_config.get("SubnetIds", []),
                                "security_group_ids": vpc_config.get("SecurityGroupIds", []),
                            }
                        ]
                        if vpc_config.get("SubnetIds") or vpc_config.get("SecurityGroupIds")
                        else [],
                    },
                    arn=arn,
                )
            )
    return out


RESOURCE_SCANNERS = {
    "lambda": scan_functions,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
