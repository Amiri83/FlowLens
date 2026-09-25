"""Small, dependency-free helpers for protocols, port intervals and CIDRs.

Everything here is pure and deterministic so the evaluators built on top of
it (security groups, NACLs, routes) stay easy to unit test.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

ALL_PORTS = (0, 65535)
#: Client-side ephemeral range used by AWS-managed clients (ALB, NLB, NAT
#: gateway) and the widest range any OS uses; NACL return rules must cover it.
EPHEMERAL_PORTS = (1024, 65535)
#: ICMP type used when --protocol icmp is given without --port.
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

_PROTOCOL_ALIASES = {
    "-1": "all",
    "all": "all",
    "any": "all",
    "tcp": "tcp",
    "6": "tcp",
    "udp": "udp",
    "17": "udp",
    "icmp": "icmp",
    "1": "icmp",
    "icmpv6": "icmpv6",
    "icmp6": "icmpv6",
    "58": "icmpv6",
    # Load balancer / target group protocols (transport they ride on).
    "http": "tcp",
    "https": "tcp",
    "tls": "tcp",
    "tcp_udp": "tcp_udp",
    "geneve": "udp",
}


def normalize_protocol(value) -> str | None:
    """Canonical protocol name ("tcp", "udp", "icmp", "icmpv6", "all" or a raw
    IANA number as a string). None when the value is missing/unresolvable.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or "${" in text:
        return None
    return _PROTOCOL_ALIASES.get(text, text)


def protocol_label(protocol: str) -> str:
    return "ALL" if protocol == "all" else protocol.upper()


def has_ports(protocol: str) -> bool:
    return protocol in ("tcp", "udp")


@dataclass(frozen=True)
class PortRange:
    lo: int
    hi: int

    @classmethod
    def parse(cls, text: str | int | None) -> PortRange | None:
        """"443" -> 443-443, "8000-8100" -> 8000-8100, None/"" -> None."""
        if text is None or text == "":
            return None
        if isinstance(text, int):
            return cls(text, text)
        s = str(text).strip()
        if "-" in s.lstrip("-"):
            lo, hi = s.split("-", 1)
            r = cls(int(lo), int(hi))
        else:
            r = cls(int(s), int(s))
        if r.lo > r.hi or r.lo < 0 or r.hi > 65535:
            raise ValueError(f"invalid port range: {text}")
        return r

    @property
    def interval(self) -> tuple[int, int]:
        return (self.lo, self.hi)

    def __str__(self) -> str:
        return str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}"


def fmt_traffic(protocol: str, port: PortRange | None) -> str:
    """"TCP/443", "UDP/53", "ICMP", "TCP/?" (unknown port), "ALL"."""
    if protocol == "all":
        return "ALL"
    if has_ports(protocol):
        return f"{protocol_label(protocol)}/{port if port is not None else '?'}"
    if protocol in ("icmp", "icmpv6") and port is not None:
        return f"{protocol_label(protocol)} type {port}"
    return protocol_label(protocol)


# --- port intervals -----------------------------------------------------------

Interval = tuple[int, int]


def merge(intervals: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def intersect(a: list[Interval], b: list[Interval]) -> list[Interval]:
    out = []
    for alo, ahi in a:
        for blo, bhi in b:
            lo, hi = max(alo, blo), min(ahi, bhi)
            if lo <= hi:
                out.append((lo, hi))
    return merge(out)


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    out = merge(a)
    for blo, bhi in merge(b):
        nxt = []
        for lo, hi in out:
            if bhi < lo or blo > hi:
                nxt.append((lo, hi))
                continue
            if lo < blo:
                nxt.append((lo, blo - 1))
            if hi > bhi:
                nxt.append((bhi + 1, hi))
        out = nxt
    return out


def fmt_intervals(intervals: list[Interval]) -> str:
    return ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in merge(intervals)) or "none"


def rule_port_interval(protocol: str, from_port, to_port) -> Interval | None:
    """Port interval a rule covers for port-bearing protocols. -1/None bounds
    or an all-traffic rule mean every port. None when ports are unresolvable.
    """
    if protocol == "all":
        return ALL_PORTS
    try:
        lo = -1 if from_port is None else int(from_port)
        hi = -1 if to_port is None else int(to_port)
    except (TypeError, ValueError):
        return None
    if lo == -1 and hi == -1:
        return ALL_PORTS
    if protocol in ("icmp", "icmpv6"):
        # For ICMP, from_port is the ICMP type (-1 = all types).
        return ALL_PORTS if lo == -1 else (lo, lo)
    return (max(lo, 0), min(hi if hi >= 0 else 65535, 65535))


# --- CIDRs --------------------------------------------------------------------


def parse_cidr(value) -> IPNetwork | None:
    if not isinstance(value, str) or not value or "${" in value:
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def is_cidr_literal(value: str) -> bool:
    return parse_cidr(value) is not None


def cidr_relation(rule_cidr: IPNetwork, peer: IPNetwork) -> str:
    """"covers" (peer inside rule), "overlaps" (partially), or "disjoint"."""
    if rule_cidr.version != peer.version:
        return "disjoint"
    if peer.subnet_of(rule_cidr):
        return "covers"
    if rule_cidr.overlaps(peer):
        return "overlaps"
    return "disjoint"


def is_private(net: IPNetwork) -> bool:
    return net.is_private and net.prefixlen > 0


INTERNET_V4 = ipaddress.ip_network("0.0.0.0/0")
INTERNET_V6 = ipaddress.ip_network("::/0")
