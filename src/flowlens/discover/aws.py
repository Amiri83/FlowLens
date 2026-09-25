"""Read-only AWS runtime discovery orchestrator.

Runs the per-service scanners in flowlens.aws.resources one resource type at
a time. Every AWS call they make is a Describe*/List*/Get* call — nothing
creates, modifies, or deletes anything. Uses the standard boto3 credential
and region resolution chain (env vars, shared config/credentials files,
named profiles, instance profile, ...), so it works unmodified against real
AWS or against LocalStack when AWS_ENDPOINT_URL (or
AWS_ENDPOINT_URL_<SERVICE>) points at http://localhost:4566.

Partial permissions: if a scanner hits AccessDenied (or any other
permission-class ClientError), the denial is logged and recorded in the
ScanReport, that resource type is marked unresolved, and the scan carries on
with the remaining resource types.

Discovered attributes are normalized to the same attribute vocabulary the
Terraform ingester uses (vpc_id, subnets, security_groups, ...) so that
flowlens.linking.linker's rule set works identically over both sources.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from flowlens.aws.resources import SERVICE_MODULES
from flowlens.aws.resources._common import client
from flowlens.ids import make_node_id
from flowlens.models.graph import Graph, Node, Source

log = logging.getLogger(__name__)

#: ClientError codes that mean "you are not allowed to do this" rather than
#: "this broke". Matching is case-insensitive.
PERMISSION_ERROR_CODES = {
    "accessdenied",
    "accessdeniedexception",
    "unauthorizedoperation",
    "unauthorizedaccess",
    "unauthorizedexception",
    "authorizationerror",
    "authfailure",
    "forbidden",
    "forbiddenexception",
    "notauthorized",
    "unrecognizedclientexception",
    "invalidclienttokenid",
    "expiredtoken",
    "expiredtokenexception",
    "optinrequired",
}

def is_permission_error(exc: BaseException) -> bool:
    if isinstance(exc, NoCredentialsError):
        return True
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = str(error.get("Code", "")).lower()
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return code in PERMISSION_ERROR_CODES or status == 403
    return False


@dataclass
class ScanReport:
    """Summary of one discovery run."""

    region: str | None = None
    account_id: str | None = None
    scanned: dict[str, int] = field(default_factory=dict)  # resource_type -> count
    denied: dict[str, dict[str, Any]] = field(default_factory=dict)  # resource_type -> detail
    errors: dict[str, str] = field(default_factory=dict)  # resource_type -> message

    @property
    def unresolved_resource_types(self) -> list[str]:
        return sorted(set(self.denied) | set(self.errors))

    @property
    def partial(self) -> bool:
        return bool(self.denied or self.errors)

    @property
    def denied_permissions(self) -> list[str]:
        return sorted({d["permission"] for d in self.denied.values() if d.get("permission")})

    def to_dict(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "account_id": self.account_id,
            "partial": self.partial,
            "scanned": dict(sorted(self.scanned.items())),
            "unresolved_resource_types": self.unresolved_resource_types,
            "denied_permissions": self.denied_permissions,
            "denied": dict(sorted(self.denied.items())),
            "errors": dict(sorted(self.errors.items())),
        }


class AWSDiscoverer:
    """Emits FlowLens Nodes (actual_state populated) for the supported
    resource set. Call discover_all() for everything or discover(<type>) to
    scope discovery to one resource type.
    """

    def __init__(
        self,
        region: str | None = None,
        session: boto3.Session | None = None,
        profile: str | None = None,
    ):
        self.session = session or boto3.Session(profile_name=profile, region_name=region)
        self.region = region or self.session.region_name
        self.report = ScanReport(region=self.region)
        self.account_id: str | None = None
        try:
            self.account_id = client(self.session, "sts", self.region).get_caller_identity().get("Account")
        except (ClientError, BotoCoreError) as exc:
            log.warning("Could not resolve AWS account id via sts:GetCallerIdentity: %s", exc)
        self.report.account_id = self.account_id

        self.scanners: dict[str, tuple[str, Callable]] = {}
        for module, iam_prefix in SERVICE_MODULES:
            for resource_type, fn in module.RESOURCE_SCANNERS.items():
                self.scanners[resource_type] = (iam_prefix, fn)

    @property
    def errors(self) -> list[str]:
        """Flat, human-readable list of everything that went wrong."""
        out = [f"{rtype}: access denied ({d['permission'] or d['code']})" for rtype, d in sorted(self.report.denied.items())]
        out += [f"{rtype}: {msg}" for rtype, msg in sorted(self.report.errors.items())]
        return out

    def _to_node(self, item: dict[str, Any]) -> Node:
        return Node(
            id=make_node_id(item["resource_type"], item["cloud_id"]),
            name=item["name"],
            resource_type=item["resource_type"],
            source=Source.AWS,
            aws_arn=item.get("arn"),
            region=self.region,
            account_id=self.account_id,
            actual_state=item["actual_state"],
        )

    def discover(self, resource_type: str) -> list[Node]:
        """Scan one resource type. Never raises for AWS-side failures: those
        are recorded in self.report and an empty list is returned.
        """
        iam_prefix, fn = self.scanners[resource_type]
        try:
            items = fn(self.session, self.region)
        except Exception as exc:  # noqa: BLE001 - one broken resource type must not abort the scan
            if is_permission_error(exc):
                operation = getattr(exc, "operation_name", None)
                code = exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else type(exc).__name__
                permission = f"{iam_prefix}:{operation}" if operation else None
                log.warning("Access denied scanning %s (%s); continuing without it", resource_type, permission or code)
                self.report.denied[resource_type] = {"permission": permission, "code": code, "message": str(exc)}
            else:
                log.warning("Failed to scan %s: %s; continuing without it", resource_type, exc)
                self.report.errors[resource_type] = str(exc)
            return []
        self.report.scanned[resource_type] = len(items)
        return [self._to_node(item) for item in items]

    def discover_all(self) -> Graph:
        """Scan every supported resource type, degrading gracefully. The
        returned graph carries the scan summary in graph.metadata["aws_scan"],
        and nodes of a partially scanned account are flagged in metadata.
        """
        graph = Graph()
        for resource_type in self.scanners:
            for node in self.discover(resource_type):
                graph.add_node(node)
        report = self.report.to_dict()
        graph.metadata["aws_scan"] = report
        if self.report.partial:
            for node in graph.nodes.values():
                node.metadata["aws_scan_partial"] = True
        return graph


def discover_all(region: str | None = None, profile: str | None = None) -> Graph:
    return AWSDiscoverer(region=region, profile=profile).discover_all()
