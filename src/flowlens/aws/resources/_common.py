"""Shared helpers for the per-service scanners.

Every scanner returns plain dicts (not Nodes) so it stays trivially testable
and independent of the graph model; the orchestrator in
flowlens.discover.aws turns them into Nodes.
"""
from __future__ import annotations

import os
from typing import Any


def endpoint_for(service: str) -> str | None:
    """LocalStack / custom endpoint support: AWS_ENDPOINT_URL_<SERVICE> wins
    over AWS_ENDPOINT_URL; None means the normal AWS endpoint.
    """
    return os.environ.get(f"AWS_ENDPOINT_URL_{service.upper()}") or os.environ.get("AWS_ENDPOINT_URL")


def client(session, service: str, region: str | None = None):
    return session.client(service, region_name=region or session.region_name, endpoint_url=endpoint_for(service))


def tag_name(tags: list[dict[str, str]] | None, fallback: str) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", fallback)
    return fallback


def resource(
    resource_type: str,
    cloud_id: str,
    name: str | None,
    actual_state: dict[str, Any],
    arn: str | None = None,
) -> dict[str, Any]:
    return {
        "resource_type": resource_type,
        "cloud_id": cloud_id,
        "name": name or cloud_id,
        "arn": arn,
        "actual_state": actual_state,
    }
