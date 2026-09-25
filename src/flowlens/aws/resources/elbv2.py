"""Elastic Load Balancing v2: ALBs/NLBs, listeners, listener rules, target
groups. Read-only elbv2 Describe* calls only.
"""
from __future__ import annotations

from typing import Any

from flowlens.aws.resources._common import client, resource

SERVICE = "elbv2"


def _load_balancers(elbv2) -> list[dict[str, Any]]:
    return elbv2.describe_load_balancers().get("LoadBalancers", [])


def scan_load_balancers(session, region: str | None) -> list[dict[str, Any]]:
    elbv2 = client(session, SERVICE, region)
    return [
        resource(
            "alb",
            lb["LoadBalancerArn"],
            lb.get("LoadBalancerName"),
            {
                "name": lb.get("LoadBalancerName"),
                "vpc_id": lb.get("VpcId"),
                "subnets": [az["SubnetId"] for az in lb.get("AvailabilityZones", [])],
                "security_groups": lb.get("SecurityGroups", []),
                "scheme": lb.get("Scheme"),
                "type": lb.get("Type"),
            },
            arn=lb["LoadBalancerArn"],
        )
        for lb in _load_balancers(elbv2)
    ]


def _target_group_actions(actions: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [{"target_group_arn": a["TargetGroupArn"]} for a in actions if a.get("TargetGroupArn")]


def scan_listeners(session, region: str | None) -> list[dict[str, Any]]:
    elbv2 = client(session, SERVICE, region)
    out = []
    for lb in _load_balancers(elbv2):
        for listener in elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", []):
            larn = listener["ListenerArn"]
            out.append(
                resource(
                    "listener",
                    larn,
                    larn,
                    {
                        "load_balancer_arn": lb["LoadBalancerArn"],
                        "protocol": listener.get("Protocol"),
                        "port": listener.get("Port"),
                        "default_action": _target_group_actions(listener.get("DefaultActions", [])),
                    },
                    arn=larn,
                )
            )
    return out


def scan_listener_rules(session, region: str | None) -> list[dict[str, Any]]:
    elbv2 = client(session, SERVICE, region)
    out = []
    for lb in _load_balancers(elbv2):
        for listener in elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", []):
            larn = listener["ListenerArn"]
            for rule in elbv2.describe_rules(ListenerArn=larn).get("Rules", []):
                rarn = rule["RuleArn"]
                out.append(
                    resource(
                        "listener_rule",
                        rarn,
                        rarn,
                        {"listener_arn": larn, "action": _target_group_actions(rule.get("Actions", []))},
                        arn=rarn,
                    )
                )
    return out


def scan_target_groups(session, region: str | None) -> list[dict[str, Any]]:
    elbv2 = client(session, SERVICE, region)
    return [
        resource(
            "target_group",
            tg["TargetGroupArn"],
            tg.get("TargetGroupName"),
            {"name": tg.get("TargetGroupName"), "vpc_id": tg.get("VpcId"), "protocol": tg.get("Protocol"), "port": tg.get("Port")},
            arn=tg["TargetGroupArn"],
        )
        for tg in elbv2.describe_target_groups().get("TargetGroups", [])
    ]


RESOURCE_SCANNERS = {
    "alb": scan_load_balancers,
    "listener": scan_listeners,
    "listener_rule": scan_listener_rules,
    "target_group": scan_target_groups,
}


def scan(session, region: str | None) -> list[dict[str, Any]]:
    return [r for fn in RESOURCE_SCANNERS.values() for r in fn(session, region)]
