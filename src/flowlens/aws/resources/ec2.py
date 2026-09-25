"""EC2 security groups (ingress peers become `allows` edges downstream).
Read-only EC2 Describe* calls only.
"""
from __future__ import annotations

from typing import Any

from flowlens.aws.resources._common import client, resource

SERVICE = "ec2"


def scan_security_groups(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    out = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        peer_ids = [
            pair["GroupId"]
            for perm in sg.get("IpPermissions", [])
            for pair in perm.get("UserIdGroupPairs", [])
            if pair.get("GroupId")
        ]
        out.append(
            resource(
                "security_group",
                sg["GroupId"],
                sg.get("GroupName", sg["GroupId"]),
                {"vpc_id": sg.get("VpcId"), "name": sg.get("GroupName"), "source_security_group_id": peer_ids or None},
            )
        )
    return out


RESOURCE_SCANNERS = {
    "security_group": scan_security_groups,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
