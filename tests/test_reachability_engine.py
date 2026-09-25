"""Reachability engine: security groups, routes, NACLs, load balancer port
transitions and candidate selection. Pure unit tests over in-memory graphs.
"""
import ipaddress

import pytest

from flowlens.reachability import CheckStatus, EndpointError, ReachabilityEngine
from flowlens.reachability import nacl as nacl_eval
from flowlens.reachability import security_groups as sg_eval
from flowlens.reachability.facts import build_facts
from flowlens.reachability.netutil import PortRange
from flowlens.reachability.routes import classify_subnet, lookup
from reachability_fixtures import ALB_ARN, LISTENER_ARN, NLB_ARN, SVC_ARN, TG_ARN, Stack, nacl_entry, sg_rule

A, B, U, NA = CheckStatus.ALLOWED, CheckStatus.BLOCKED, CheckStatus.UNKNOWN, CheckStatus.NOT_APPLICABLE
net = ipaddress.ip_network


def check(result, check_type, hop=None):
    hits = [c for c in result.checks if c.check_type == check_type and (hop is None or c.hop_index == hop)]
    assert hits, f"no {check_type} check in {[c.check_type for c in result.checks]}"
    return hits[0]


def sg_verdict(stack: Stack, sg: str, direction: str, protocol: str, port, peer: sg_eval.Peer):
    facts = build_facts(stack.build())
    return sg_eval.evaluate(facts, owner_label=sg, sg_keys=[f"security_group:{sg}"], sg_unresolved=[], direction=direction,
                            protocol=protocol, port=PortRange.parse(port), peer=peer)


INTERNET = sg_eval.Peer("internet", [net("0.0.0.0/0")])


# --- security groups ----------------------------------------------------------


def test_sg_tcp_exact_port_from_cidr_allowed_with_rule_evidence():
    v = sg_verdict(Stack(), "sg-alb", "ingress", "tcp", 443, INTERNET)
    assert v.status == A
    assert any("ingress TCP/443 from 0.0.0.0/0" in e for e in v.evidence)


def test_sg_tcp_port_missing_is_blocked_and_lists_existing_rules():
    v = sg_verdict(Stack(), "sg-alb", "ingress", "tcp", 8443, INTERNET)
    assert v.status == B
    assert "does not permit TCP/8443" in v.reason
    assert any("existing ingress rules" in e and "TCP/443" in e for e in v.evidence)
    assert v.suggestion and "sg-alb" in v.suggestion


def test_sg_allowed_by_source_security_group_reference():
    peer = sg_eval.Peer("ALB", [net("10.0.1.0/24")], ["security_group:sg-alb"])
    assert sg_verdict(Stack(), "sg-app", "ingress", "tcp", 8080, peer).status == A


def test_sg_source_security_group_mismatch_is_blocked():
    peer = sg_eval.Peer("other", [net("10.0.1.0/24")], ["security_group:sg-other"])
    v = sg_verdict(Stack(), "sg-app", "ingress", "tcp", 8080, peer)
    assert v.status == B and "sg-app" in v.reason


def test_sg_protocol_all_matches_any_protocol_and_port():
    stack = Stack().set("sg-other", ingress=[sg_rule("-1", cidrs=["10.0.0.0/16"])])
    peer = sg_eval.Peer("vpc host", [net("10.0.2.0/24")])
    for proto, port in (("tcp", 5432), ("udp", 53), ("icmp", None)):
        assert sg_verdict(stack, "sg-other", "ingress", proto, port, peer).status == A


def test_sg_port_range_rule_and_partial_range_request():
    stack = Stack().set("sg-other", ingress=[sg_rule("tcp", 8000, 8100, cidrs=["10.0.0.0/16"])])
    peer = sg_eval.Peer("vpc host", [net("10.0.2.0/24")])
    assert sg_verdict(stack, "sg-other", "ingress", "tcp", 8050, peer).status == A
    assert sg_verdict(stack, "sg-other", "ingress", "tcp", "8000-8100", peer).status == A
    v = sg_verdict(stack, "sg-other", "ingress", "tcp", "8000-8200", peer)
    assert v.status == B and "8000-8100" in v.reason


def test_sg_ipv6_cidr_rules():
    stack = Stack().set("sg-other", ingress=[sg_rule("tcp", 443, cidrs=["0.0.0.0/0"]), sg_rule("tcp", 80, ipv6=["::/0"])])
    v6_peer = sg_eval.Peer("v6 client", [net("2001:db8::/64")])
    assert sg_verdict(stack, "sg-other", "ingress", "tcp", 80, v6_peer).status == A
    # An IPv4 0.0.0.0/0 rule does not admit IPv6 clients.
    assert sg_verdict(stack, "sg-other", "ingress", "tcp", 443, v6_peer).status == B


def test_sg_partial_cidr_overlap_is_unknown_not_guessed():
    stack = Stack().set("sg-other", ingress=[sg_rule("tcp", 443, cidrs=["203.0.113.0/24"])])
    v = sg_verdict(stack, "sg-other", "ingress", "tcp", 443, INTERNET)
    assert v.status == U and "203.0.113.0/24" in v.reason
    specific = sg_eval.Peer("client", [net("203.0.113.10/32")])
    assert sg_verdict(stack, "sg-other", "ingress", "tcp", 443, specific).status == A


def test_sg_unknown_port_only_allowed_by_all_ports_rule():
    peer = sg_eval.Peer("x", [net("10.0.2.0/24")])
    assert sg_verdict(Stack(), "sg-app", "egress", "tcp", None, peer).status == A  # egress -1 to 0.0.0.0/0
    assert sg_verdict(Stack(), "sg-alb", "ingress", "tcp", None, INTERNET).status == U


def test_sg_stateful_reply_not_evaluated_against_reverse_rules():
    # The app SG has *no* egress at all and the ALB SG has no ingress from the app:
    # replies must still flow because security groups are stateful.
    stack = Stack().set("sg-app", egress=[])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    assert result.overall_status == A
    assert check(result, "security_group_return", 3).status == NA
    assert "stateful" in check(result, "security_group_return", 3).reason


# --- routes -------------------------------------------------------------------


def test_route_local_default_igw_and_longest_prefix():
    stack = Stack().add("rtb-app-peer", "route", Stack.route("rtb-app", "10.0.2.0/24", "vpc_peering", "pcx-1"))
    facts = build_facts(stack.build())
    local = lookup(facts, "subnet:subnet-pub", net("10.0.2.15/32"))
    assert local.route.target_type == "local"  # 10.0.0.0/16 local beats 0.0.0.0/0 -> igw
    default = lookup(facts, "subnet:subnet-pub", net("8.8.8.8/32"))
    assert default.route.target_type == "internet_gateway" and default.route.target == "internet_gateway:igw-1"
    specific = lookup(facts, "subnet:subnet-app", net("10.0.2.15/32"))
    assert specific.route.target_type == "vpc_peering"  # /24 beats the /16 local route
    assert lookup(facts, "subnet:subnet-app", net("8.8.8.8/32")).route.target_type == "nat_gateway"


def test_route_main_table_fallback_and_subnet_classification_from_routes_not_names():
    stack = Stack().add("subnet-x", "subnet", {"vpc_id": "vpc-1", "cidr_block": "10.0.9.0/24", "tags": {"Name": "public-looking"}})
    facts = build_facts(stack.build())
    look = lookup(facts, "subnet:subnet-x", net("10.0.1.5/32"))
    assert look.table.key == "route_table:rtb-main" and "main route table" in look.how
    cls = classify_subnet(facts, "subnet:subnet-x")
    assert cls["classification"] == "PRIVATE"  # despite the "public" name: no IGW route
    assert classify_subnet(facts, "subnet:subnet-pub")["classification"] == "PUBLIC"
    assert "igw-1" in classify_subnet(facts, "subnet:subnet-pub")["evidence"][0]
    assert classify_subnet(facts, "subnet:subnet-app")["classification"] == "PRIVATE"


def test_route_missing_route_table_is_unknown():
    stack = Stack().remove("rtb-main").remove("rtb-main-local").set("rtb-app", subnet_ids=[])
    facts = build_facts(stack.build())
    assert classify_subnet(facts, "subnet:subnet-app")["classification"] == "UNKNOWN"
    result = ReachabilityEngine(stack.build()).analyze(f"ecs_service:{SVC_ARN}", "8.8.8.8", "tcp", 443)
    assert check(result, "route").status == U and result.overall_status == U


def test_route_blackhole_blocks_egress():
    stack = Stack().set("rtb-app-default", state="blackhole")
    result = ReachabilityEngine(stack.build()).analyze(f"ecs_service:{SVC_ARN}", "8.8.8.8", "tcp", 443)
    assert result.overall_status == B and check(result, "route").status == B
    assert any("blackhole" in e for e in check(result, "route").evidence)


def test_egress_via_nat_in_public_subnet_allowed_and_igw_without_public_ip_blocked():
    engine = ReachabilityEngine(Stack().build())
    ok = engine.analyze(f"ecs_service:{SVC_ARN}", "internet", "tcp", 443)
    assert ok.overall_status == A and any("nat-1" in e for e in check(ok, "route").evidence)
    # Move the service into the public subnet: IGW route but no public IP.
    stack = Stack().set(SVC_ARN, network_configuration=[{"subnets": ["subnet-pub"], "security_groups": ["sg-app"],
                                                         "assign_public_ip": False}])
    res = ReachabilityEngine(stack.build()).analyze(f"ecs_service:{SVC_ARN}", "internet", "tcp", 443)
    assert res.overall_status == B and "public IP" in " ".join(check(res, "route").evidence)


# --- NACLs --------------------------------------------------------------------


def _acl(stack: Stack):
    return build_facts(stack.build()).nacls["network_acl:acl-default"]


def test_nacl_rules_are_evaluated_in_rule_number_order():
    deny_first = Stack().set("acl-default", ingress=[nacl_entry(200, "allow"), nacl_entry(100, "deny", "tcp", from_port=443)])
    v = nacl_eval.evaluate(_acl(deny_first), "ingress", "tcp", [(443, 443)], net("0.0.0.0/0"))
    assert v.status == B and any("rule 100 DENY" in e for e in v.evidence)
    allow_first = Stack().set("acl-default", ingress=[nacl_entry(100, "allow"), nacl_entry(200, "deny", "tcp", from_port=443)])
    assert nacl_eval.evaluate(_acl(allow_first), "ingress", "tcp", [(443, 443)], net("0.0.0.0/0")).status == A


def test_nacl_explicit_deny_allow_and_implicit_deny():
    stack = Stack().set("acl-default", ingress=[nacl_entry(100, "allow", "tcp", "10.0.0.0/16", 80, 80)])
    acl = _acl(stack)
    assert nacl_eval.evaluate(acl, "ingress", "tcp", [(80, 80)], net("10.0.1.0/24")).status == A
    implicit = nacl_eval.evaluate(acl, "ingress", "tcp", [(22, 22)], net("10.0.1.0/24"))
    assert implicit.status == B and any("implicit" in e for e in implicit.evidence)
    assert nacl_eval.evaluate(acl, "ingress", "tcp", [(80, 80)], net("192.168.0.0/24")).status == B
    # A rule for a private range never matches the (public) Internet...
    assert nacl_eval.evaluate(acl, "ingress", "tcp", [(80, 80)], net("0.0.0.0/0"), peer_is_internet=True).status == B
    # ...but a partial overlap with the peer's range is UNKNOWN, not a guess.
    stack2 = Stack().set("acl-default", ingress=[nacl_entry(90, "deny", "tcp", "203.0.113.0/24", 443), nacl_entry(100, "allow")])
    assert nacl_eval.evaluate(_acl(stack2), "ingress", "tcp", [(443, 443)], net("0.0.0.0/0")).status == U


def test_nacl_stateless_reply_path_is_required():
    # Inbound 443 allowed, but outbound only allows 443 -> replies to the
    # client's ephemeral port are dropped. (An SG would not need this.)
    stack = Stack().set("acl-default", ingress=list(Stack().state["acl-default"][1]["ingress"]),
                        egress=[nacl_entry(100, "allow", "tcp", "0.0.0.0/0", 443, 443)])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"alb:{ALB_ARN}", "tcp", 443)
    assert check(result, "nacl_ingress").status == A
    assert check(result, "nacl_return_egress").status == B
    assert result.overall_status == B and result.blocked_at.endswith("nacl_return_egress")
    # Only part of the ephemeral range -> depends on the client OS -> UNKNOWN.
    partial = Stack().set("acl-default", egress=[nacl_entry(100, "allow", "tcp", "0.0.0.0/0", 32768, 65535)])
    res2 = ReachabilityEngine(partial.build()).analyze("internet", f"alb:{ALB_ARN}", "tcp", 443)
    assert check(res2, "nacl_return_egress").status == U and res2.overall_status == U


def test_nacl_not_applicable_within_one_subnet():
    stack = Stack().add("i-1", "instance", {"subnet_id": "subnet-app", "vpc_security_group_ids": ["sg-other"], "private_ip": "10.0.2.5"})
    stack.set("sg-other", egress=[sg_rule("-1", cidrs=["0.0.0.0/0"])])
    stack.set("sg-app", ingress=[sg_rule("tcp", 8080, sgs=["sg-alb", "sg-other"])])
    result = ReachabilityEngine(stack.build()).analyze("instance:i-1", f"ecs_service:{SVC_ARN}", "tcp", 8080)
    assert check(result, "nacl").status == NA
    assert result.overall_status == A


# --- load balancer paths ------------------------------------------------------


def test_full_internet_alb_ecs_allowed_with_port_transition():
    result = ReachabilityEngine(Stack().build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", "443")
    assert result.overall_status == A
    kinds = [(h.kind, str(h.port_in), str(h.port_out)) for h in result.path]
    assert kinds == [("network", "443", "443"), ("forward", "443", "8080"), ("network", "8080", "8080")]
    assert "TCP/443 -> ALB web (listener HTTPS:443)" in result.path_label and "TCP/8080 -> ECS service app" in result.path_label
    assert check(result, "target_port").reason == "port transition: listener 443 -> target port 8080"
    # The 443 client port is never checked against the ECS security group.
    assert "TCP/8080" in check(result, "security_group_ingress", 3).reason
    assert result.path[2].context.current_port == PortRange(8080, 8080) and result.path[2].context.original_port == PortRange(443, 443)


def test_alb_sg_allowed_but_ecs_sg_blocked():
    stack = Stack().set("sg-app", ingress=[sg_rule("tcp", 8080, sgs=["sg-other"])])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    assert check(result, "security_group_ingress", 1).status == A
    blocked = check(result, "security_group_ingress", 3)
    assert blocked.status == B and "sg-app (app) does not permit TCP/8080 from ALB web" in blocked.reason
    assert result.overall_status == B and result.blocked_at.startswith("hop 3")
    assert any("sg-other" in e for e in blocked.evidence)


def test_missing_target_info_is_unknown():
    stack = Stack().set(TG_ARN, port=None).set(SVC_ARN, load_balancer=[{"target_group_arn": TG_ARN, "container_name": "app"}])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    assert check(result, "target_port").status == U
    assert result.overall_status == U


def test_unresolved_listener_forward_is_unknown():
    stack = Stack().set(LISTENER_ARN, default_action=[{"target_group_arn": "${var.tg_arn}"}], default_action_types=["forward"])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    assert result.overall_status == U and check(result, "listener_action").status == U


def test_no_listener_on_requested_port_is_blocked_and_lists_listeners():
    result = ReachabilityEngine(Stack().build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 80)
    assert result.overall_status == B
    listener = check(result, "listener")
    assert listener.status == B and "HTTPS:443" in listener.reason


def test_redirect_only_listener_does_not_reach_targets():
    stack = Stack().add("arn:l80", "listener", {"load_balancer_arn": ALB_ARN, "protocol": "HTTP", "port": 80,
                                                 "default_action": [], "default_action_types": ["redirect"]})
    stack.set("sg-alb", ingress=[sg_rule("tcp", 80, cidrs=["0.0.0.0/0"]), sg_rule("tcp", 443, cidrs=["0.0.0.0/0"])])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 80)
    assert result.overall_status == B and "redirect" in check(result, "listener_action").reason


def test_internal_alb_is_not_reachable_from_internet():
    stack = Stack().set(ALB_ARN, scheme="internal", internal=True)
    result = ReachabilityEngine(stack.build()).analyze("internet", f"alb:{ALB_ARN}", "tcp", 443)
    assert result.overall_status == B and check(result, "exposure").status == B


def test_nlb_instance_targets_see_client_ip():
    stack = Stack()
    stack.add(NLB_ARN, "alb", {"name": "nlb", "vpc_id": "vpc-1", "subnets": ["subnet-pub"], "security_groups": [],
                               "scheme": "internet-facing", "internal": False, "type": "network"})
    stack.add("arn:nlb-l", "listener", {"load_balancer_arn": NLB_ARN, "protocol": "TCP", "port": 5000,
                                        "default_action": [{"target_group_arn": "arn:tg-i"}], "default_action_types": ["forward"]})
    stack.add("arn:tg-i", "target_group", {"name": "tg-i", "vpc_id": "vpc-1", "protocol": "TCP", "port": 5000, "target_type": "instance"})
    stack.add("i-1", "instance", {"subnet_id": "subnet-app", "vpc_security_group_ids": ["sg-other"], "private_ip": "10.0.2.5"})
    stack.add("att", "lb_target_group_attachment", {"target_group_arn": "arn:tg-i", "target_id": "i-1", "port": 5000})
    stack.set("sg-other", ingress=[sg_rule("tcp", 5000, cidrs=["10.0.1.0/24"])], egress=[])
    result = ReachabilityEngine(stack.build()).analyze("internet", "instance:i-1", "tcp", 5000)
    # Instance targets preserve the client IP: the SG must allow the internet, not the NLB subnet.
    assert result.overall_status == B
    assert "Internet" in check(result, "security_group_ingress", 3).reason
    assert check(result, "security_group_ingress", 1).status == NA  # NLB without SGs
    stack.set("sg-other", ingress=[sg_rule("tcp", 5000, cidrs=["0.0.0.0/0"])])
    assert ReachabilityEngine(stack.build()).analyze("internet", "instance:i-1", "tcp", 5000).overall_status == A


# --- candidates & general -----------------------------------------------------


def test_multiple_candidates_prefers_allowed_path():
    result = ReachabilityEngine(Stack().build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    statuses = sorted(c["status"] for c in result.candidates)
    # Via the ALB, and direct: the ECS service has no public IP, which is not a failure
    # when it is reached privately through the ALB.
    assert statuses == ["ALLOWED", "NOT_APPLICABLE"]
    chosen = next(c for c in result.candidates if c["chosen"])
    assert chosen["status"] == "ALLOWED" and "ALB" in chosen["label"]
    assert result.limits["max_candidates"] >= result.limits["evaluated_candidates"]


def test_direct_path_without_public_ip_and_no_lb_is_still_blocked():
    stack = Stack().remove(LISTENER_ARN).remove(TG_ARN).remove(ALB_ARN)
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    assert result.overall_status == B
    assert check(result, "exposure").status == B and "has no public IP" in check(result, "exposure").reason
    assert [c["status"] for c in result.candidates] == ["BLOCKED"]


def test_blocked_path_reported_is_the_one_that_got_furthest():
    stack = Stack().set("sg-app", ingress=[])
    result = ReachabilityEngine(stack.build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443)
    assert result.overall_status == B and "ALB" in result.path_label and result.blocked_at.startswith("hop 3")


def test_lambda_does_not_accept_inbound_connections():
    stack = Stack().add("arn:fn", "lambda", {"function_name": "fn", "vpc_config": [{"subnet_ids": ["subnet-app"],
                                                                                   "security_group_ids": ["sg-other"]}]})
    result = ReachabilityEngine(stack.build()).analyze("internet", "fn", "tcp", 443)
    assert result.overall_status == B and check(result, "inbound").status == B


def test_unknown_endpoint_and_non_endpoint_errors():
    engine = ReachabilityEngine(Stack().build())
    with pytest.raises(EndpointError):
        engine.analyze("internet", "nope", "tcp", 443)
    with pytest.raises(EndpointError, match="not a traffic endpoint"):
        engine.analyze("internet", "vpc:vpc-1", "tcp", 443)
    with pytest.raises(EndpointError, match="unsupported protocol"):
        engine.analyze("internet", f"alb:{ALB_ARN}", "sctp", 443)


def test_evidence_is_retained_on_result():
    data = ReachabilityEngine(Stack().build()).analyze("internet", f"ecs_service:{SVC_ARN}", "tcp", 443).to_dict()
    assert data["overall_status"] == "ALLOWED"
    assert any("sg-alb" in e and "TCP/443" in e for e in data["evidence"])
    assert any("rtb-pub" in e and "igw-1" in e for e in data["evidence"])
    assert all({"check_type", "status", "evidence", "reason"} <= c.keys() for c in data["checks"])
    assert {s["classification"] for s in data["subnets"]} == {"PUBLIC", "PRIVATE"}


def test_nothing_proven_is_unknown_never_allowed():
    # Two addresses outside every known VPC: no check can prove anything.
    result = ReachabilityEngine(Stack().build()).analyze("internet", "203.0.113.7", "tcp", 443)
    assert result.overall_status == U
    from flowlens.reachability.models import combine

    assert combine([NA, NA]) == U and combine([]) == U and combine([A, NA]) == A


def test_private_address_inside_vpc_has_unknown_security_groups():
    result = ReachabilityEngine(Stack().build()).analyze(f"alb:{ALB_ARN}", "10.0.2.9", "tcp", 8080)
    assert result.overall_status == U
    assert check(result, "security_group_ingress").status == U
