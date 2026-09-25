"""API Gateway (REST / v1): REST APIs and their method integrations.
Read-only apigateway Get* calls only.

Integrations carry `integration_uri` set to the bare Lambda ARN when they
target a Lambda function, so the linker can draw integrates_with edges.
"""
from __future__ import annotations

import re
from typing import Any

from botocore.exceptions import ClientError

from flowlens.aws.resources._common import client, resource

SERVICE = "apigateway"

_LAMBDA_ARN = re.compile(r"arn:aws[a-zA-Z0-9-]*:lambda:[^/:\s]+:[^/:\s]+:function:[^/:\s]+")


def _rest_apis(apigw) -> list[dict[str, Any]]:
    return [api for page in apigw.get_paginator("get_rest_apis").paginate() for api in page.get("items", [])]


def scan_rest_apis(session, region: str | None) -> list[dict[str, Any]]:
    apigw = client(session, SERVICE, region)
    return [resource("api_gateway", api["id"], api.get("name"), {"name": api.get("name")}) for api in _rest_apis(apigw)]


def scan_integrations(session, region: str | None) -> list[dict[str, Any]]:
    apigw = client(session, SERVICE, region)
    out = []
    for api in _rest_apis(apigw):
        api_id = api["id"]
        for page in apigw.get_paginator("get_resources").paginate(restApiId=api_id):
            for res in page.get("items", []):
                for method in sorted((res.get("resourceMethods") or {}).keys()):
                    try:
                        integration = apigw.get_integration(restApiId=api_id, resourceId=res["id"], httpMethod=method)
                    except ClientError as exc:
                        # A method without an integration is normal, not a failure.
                        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                            continue
                        raise
                    match = _LAMBDA_ARN.search(integration.get("uri", "") or "")
                    integration_id = f"{api_id}-{res['id']}-{method}"
                    out.append(
                        resource(
                            "api_gateway_integration",
                            integration_id,
                            integration_id,
                            {
                                "rest_api_id": api_id,
                                "http_method": method,
                                "type": integration.get("type"),
                                "integration_uri": match.group(0) if match else None,
                            },
                        )
                    )
    return out


RESOURCE_SCANNERS = {
    "api_gateway": scan_rest_apis,
    "api_gateway_integration": scan_integrations,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
