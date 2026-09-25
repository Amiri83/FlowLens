"""VPC networking: VPCs, subnets, route tables + routes, internet gateways,
NAT gateways. Read-only EC2 Describe* calls only.
"""
from __future__ import annotations

from typing import Any

from flowlens.aws.resources._common import client, resource, tag_name

SERVICE = "ec2"


def scan_vpcs(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    return [
        resource(
            "vpc",
            vpc["VpcId"],
            tag_name(vpc.get("Tags"), vpc["VpcId"]),
            {"cidr_block": vpc.get("CidrBlock"), "is_default": vpc.get("IsDefault")},
        )
        for vpc in ec2.describe_vpcs().get("Vpcs", [])
    ]


def _subnet_route_table_map(ec2) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for rt in ec2.describe_route_tables().get("RouteTables", []):
        for assoc in rt.get("Associations", []):
            sid = assoc.get("SubnetId")
            if sid:
                mapping[sid] = rt["RouteTableId"]
    return mapping


def scan_subnets(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    subnets = ec2.describe_subnets().get("Subnets", [])
    route_table_by_subnet = _subnet_route_table_map(ec2)
    return [
        resource(
            "subnet",
            sn["SubnetId"],
            tag_name(sn.get("Tags"), sn["SubnetId"]),
            {
                "vpc_id": sn.get("VpcId"),
                "cidr_block": sn.get("CidrBlock"),
                "availability_zone": sn.get("AvailabilityZone"),
                "route_table_id": route_table_by_subnet.get(sn["SubnetId"]),
            },
        )
        for sn in subnets
    ]


def scan_route_tables(session, region: str | None) -> list[dict[str, Any]]:
    """Route tables plus one `route` resource per route entry."""
    ec2 = client(session, SERVICE, region)
    out = []
    for rt in ec2.describe_route_tables().get("RouteTables", []):
        rtid = rt["RouteTableId"]
        out.append(resource("route_table", rtid, tag_name(rt.get("Tags"), rtid), {"vpc_id": rt.get("VpcId")}))
        for i, route in enumerate(rt.get("Routes", [])):
            dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or f"local-{i}"
            route_id = f"{rtid}-{dest}"
            gateway = str(route.get("GatewayId") or "")
            out.append(
                resource(
                    "route",
                    route_id,
                    route_id,
                    {
                        "route_table_id": rtid,
                        "destination_cidr_block": dest,
                        "gateway_id": gateway if gateway.startswith("igw-") else None,
                        "nat_gateway_id": route.get("NatGatewayId"),
                    },
                )
            )
    return out


def scan_internet_gateways(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    out = []
    for igw in ec2.describe_internet_gateways().get("InternetGateways", []):
        attachments = igw.get("Attachments", [])
        gid = igw["InternetGatewayId"]
        vpc_id = attachments[0]["VpcId"] if attachments else None
        out.append(resource("internet_gateway", gid, tag_name(igw.get("Tags"), gid), {"vpc_id": vpc_id}))
    return out


def scan_nat_gateways(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    return [
        resource(
            "nat_gateway",
            nat["NatGatewayId"],
            tag_name(nat.get("Tags"), nat["NatGatewayId"]),
            {"subnet_id": nat.get("SubnetId")},
        )
        for nat in ec2.describe_nat_gateways().get("NatGateways", [])
    ]


#: resource_type -> scanner. The orchestrator runs these one at a time so a
#: permission failure on one resource type doesn't hide the others.
RESOURCE_SCANNERS = {
    "vpc": scan_vpcs,
    "subnet": scan_subnets,
    "route_table": scan_route_tables,
    "internet_gateway": scan_internet_gateways,
    "nat_gateway": scan_nat_gateways,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
