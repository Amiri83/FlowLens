"""VPC networking: VPCs, subnets, route tables + routes, internet gateways,
NAT gateways, network ACLs. Read-only EC2 Describe* calls only.
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
            {
                "cidr_block": vpc.get("CidrBlock"),
                "is_default": vpc.get("IsDefault"),
                "cidr_blocks": [
                    a["CidrBlock"]
                    for a in vpc.get("CidrBlockAssociationSet", [])
                    if a.get("CidrBlock") and (a.get("CidrBlockState") or {}).get("State", "associated") == "associated"
                ],
                "ipv6_cidr_blocks": [a["Ipv6CidrBlock"] for a in vpc.get("Ipv6CidrBlockAssociationSet", []) if a.get("Ipv6CidrBlock")],
            },
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
                "map_public_ip_on_launch": sn.get("MapPublicIpOnLaunch"),
                "ipv6_cidr_block": next(
                    (a["Ipv6CidrBlock"] for a in sn.get("Ipv6CidrBlockAssociationSet", []) if a.get("Ipv6CidrBlock")), None
                ),
            },
        )
        for sn in subnets
    ]


#: EC2 Route field -> FlowLens route target type.
_ROUTE_TARGET_FIELDS = (
    ("NatGatewayId", "nat_gateway"),
    ("TransitGatewayId", "transit_gateway"),
    ("VpcPeeringConnectionId", "vpc_peering"),
    ("NetworkInterfaceId", "network_interface"),
    ("EgressOnlyInternetGatewayId", "egress_only_gateway"),
    ("InstanceId", "instance"),
    ("LocalGatewayId", "local_gateway"),
    ("CarrierGatewayId", "carrier_gateway"),
    ("CoreNetworkArn", "core_network"),
)


def classify_route_target(route: dict[str, Any]) -> tuple[str, str | None]:
    """(target_type, target_id) for one EC2 Route entry."""
    gateway = str(route.get("GatewayId") or "")
    if gateway == "local":
        return "local", "local"
    if gateway.startswith("igw-"):
        return "internet_gateway", gateway
    if gateway.startswith("vgw-"):
        return "vpn_gateway", gateway
    if gateway.startswith("vpce-"):
        return "vpc_endpoint", gateway
    for field_name, target_type in _ROUTE_TARGET_FIELDS:
        if route.get(field_name):
            return target_type, route[field_name]
    if gateway:
        return "unknown", gateway
    return "unknown", None


def scan_route_tables(session, region: str | None) -> list[dict[str, Any]]:
    """Route tables plus one `route` resource per route entry."""
    ec2 = client(session, SERVICE, region)
    out = []
    for rt in ec2.describe_route_tables().get("RouteTables", []):
        rtid = rt["RouteTableId"]
        associations = rt.get("Associations", [])
        out.append(
            resource(
                "route_table",
                rtid,
                tag_name(rt.get("Tags"), rtid),
                {
                    "vpc_id": rt.get("VpcId"),
                    "main": any(a.get("Main") for a in associations),
                    "subnet_ids": sorted(a["SubnetId"] for a in associations if a.get("SubnetId")),
                },
            )
        )
        for i, route in enumerate(rt.get("Routes", [])):
            dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or f"local-{i}"
            if route.get("DestinationPrefixListId") and not route.get("DestinationCidrBlock"):
                dest = route["DestinationPrefixListId"]
            route_id = f"{rtid}-{dest}"
            gateway = str(route.get("GatewayId") or "")
            target_type, target_id = classify_route_target(route)
            out.append(
                resource(
                    "route",
                    route_id,
                    route_id,
                    {
                        "route_table_id": rtid,
                        "destination_cidr_block": route.get("DestinationCidrBlock"),
                        "destination_ipv6_cidr_block": route.get("DestinationIpv6CidrBlock"),
                        "destination_prefix_list_id": route.get("DestinationPrefixListId"),
                        "gateway_id": gateway if gateway.startswith("igw-") else None,
                        "nat_gateway_id": route.get("NatGatewayId"),
                        "target_type": target_type,
                        "target_id": target_id,
                        "state": route.get("State", "active"),
                    },
                )
            )
    return out


def _nacl_entry(entry: dict[str, Any]) -> dict[str, Any]:
    port_range = entry.get("PortRange") or {}
    icmp = entry.get("IcmpTypeCode") or {}
    return {
        "rule_no": entry.get("RuleNumber"),
        "action": entry.get("RuleAction"),
        "protocol": str(entry.get("Protocol", "-1")),
        "cidr_block": entry.get("CidrBlock"),
        "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
        "from_port": port_range.get("From"),
        "to_port": port_range.get("To"),
        "icmp_type": icmp.get("Type"),
        "icmp_code": icmp.get("Code"),
    }


def scan_network_acls(session, region: str | None) -> list[dict[str, Any]]:
    ec2 = client(session, SERVICE, region)
    out = []
    for acl in ec2.describe_network_acls().get("NetworkAcls", []):
        aid = acl["NetworkAclId"]
        entries = acl.get("Entries", [])
        out.append(
            resource(
                "network_acl",
                aid,
                tag_name(acl.get("Tags"), aid),
                {
                    "vpc_id": acl.get("VpcId"),
                    "is_default": acl.get("IsDefault", False),
                    "subnet_ids": sorted(a["SubnetId"] for a in acl.get("Associations", []) if a.get("SubnetId")),
                    "ingress": [_nacl_entry(e) for e in entries if not e.get("Egress")],
                    "egress": [_nacl_entry(e) for e in entries if e.get("Egress")],
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
            {"subnet_id": nat.get("SubnetId"), "connectivity_type": nat.get("ConnectivityType", "public"), "state": nat.get("State")},
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
    "network_acl": scan_network_acls,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
