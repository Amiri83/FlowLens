"""EC2 security groups (ingress peers become `allows` edges downstream) and
instances. Read-only EC2 Describe* calls only.

Security group rules are normalized to the Terraform inline-block
vocabulary (protocol / from_port / to_port / cidr_blocks /
ipv6_cidr_blocks / security_groups / prefix_list_ids) so the reachability
engine evaluates Terraform- and AWS-sourced rules with one code path.
"""
from __future__ import annotations

from typing import Any

from flowlens.aws.resources._common import client, resource, tag_name

SERVICE = "ec2"


def normalize_permission(perm: dict[str, Any]) -> dict[str, Any]:
    """One EC2 IpPermission -> one Terraform-style rule dict."""
    protocol = str(perm.get("IpProtocol", "-1"))
    all_traffic = protocol == "-1"
    return {
        "protocol": protocol,
        "from_port": 0 if all_traffic else perm.get("FromPort"),
        "to_port": 0 if all_traffic else perm.get("ToPort"),
        "cidr_blocks": [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp")],
        "ipv6_cidr_blocks": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")],
        "security_groups": [p["GroupId"] for p in perm.get("UserIdGroupPairs", []) if p.get("GroupId")],
        "prefix_list_ids": [p["PrefixListId"] for p in perm.get("PrefixListIds", []) if p.get("PrefixListId")],
    }


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
                {
                    "vpc_id": sg.get("VpcId"),
                    "name": sg.get("GroupName"),
                    "source_security_group_id": peer_ids or None,
                    "ingress": [normalize_permission(p) for p in sg.get("IpPermissions", [])],
                    "egress": [normalize_permission(p) for p in sg.get("IpPermissionsEgress", [])],
                },
            )
        )
    return out


def scan_instances(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    out = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                iid = inst["InstanceId"]
                out.append(
                    resource(
                        "instance",
                        iid,
                        tag_name(inst.get("Tags"), iid),
                        {
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "vpc_security_group_ids": [g["GroupId"] for g in inst.get("SecurityGroups", []) if g.get("GroupId")],
                            "private_ip": inst.get("PrivateIpAddress"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "state": (inst.get("State") or {}).get("Name"),
                        },
                    )
                )
    return out


RESOURCE_SCANNERS = {
    "security_group": scan_security_groups,
    "instance": scan_instances,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
