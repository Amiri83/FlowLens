"""ECS: clusters, services, and the task definitions those services run.
Read-only ecs List*/Describe* calls only.
"""
from __future__ import annotations

from typing import Any

from flowlens.aws.resources._common import client, resource

SERVICE = "ecs"


def _clusters(ecs) -> list[dict[str, Any]]:
    arns = ecs.list_clusters().get("clusterArns", [])
    if not arns:
        return []
    return ecs.describe_clusters(clusters=arns).get("clusters", [])


def _services(ecs, cluster_arn: str) -> list[dict[str, Any]]:
    arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
    if not arns:
        return []
    return ecs.describe_services(cluster=cluster_arn, services=arns).get("services", [])


def scan_clusters(session, region: str | None) -> list[dict[str, Any]]:
    ecs = client(session, SERVICE, region)
    return [
        resource("ecs_cluster", c["clusterArn"], c.get("clusterName"), {"name": c.get("clusterName")}, arn=c["clusterArn"])
        for c in _clusters(ecs)
    ]


def scan_services(session, region: str | None) -> list[dict[str, Any]]:
    ecs = client(session, SERVICE, region)
    out = []
    for cluster in _clusters(ecs):
        carn = cluster["clusterArn"]
        for svc in _services(ecs, carn):
            sarn = svc["serviceArn"]
            net_cfg = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
            out.append(
                resource(
                    "ecs_service",
                    sarn,
                    svc.get("serviceName"),
                    {
                        "name": svc.get("serviceName"),
                        "cluster": carn,
                        "task_definition": svc.get("taskDefinition"),
                        "load_balancer": [
                            {"target_group_arn": lb["targetGroupArn"]}
                            for lb in svc.get("loadBalancers", [])
                            if lb.get("targetGroupArn")
                        ],
                        "network_configuration": [
                            {"subnets": net_cfg.get("subnets", []), "security_groups": net_cfg.get("securityGroups", [])}
                        ]
                        if net_cfg
                        else [],
                        "desired_count": svc.get("desiredCount"),
                        "running_count": svc.get("runningCount"),
                    },
                    arn=sarn,
                )
            )
    return out


def scan_task_definitions(session, region: str | None) -> list[dict[str, Any]]:
    """Only task definitions referenced by a running service (not every
    historical revision in the account).
    """
    ecs = client(session, SERVICE, region)
    arns = sorted({svc["taskDefinition"] for c in _clusters(ecs) for svc in _services(ecs, c["clusterArn"]) if svc.get("taskDefinition")})
    out = []
    for arn in arns:
        td = ecs.describe_task_definition(taskDefinition=arn).get("taskDefinition", {})
        out.append(
            resource(
                "ecs_task_definition",
                arn,
                td.get("family"),
                {
                    "family": td.get("family"),
                    "cpu": td.get("cpu"),
                    "memory": td.get("memory"),
                    "container_definitions": [c.get("name") for c in td.get("containerDefinitions", [])],
                },
                arn=arn,
            )
        )
    return out


RESOURCE_SCANNERS = {
    "ecs_cluster": scan_clusters,
    "ecs_service": scan_services,
    "ecs_task_definition": scan_task_definitions,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
