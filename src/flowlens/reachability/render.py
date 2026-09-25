"""Plain-text rendering of a ReachabilityResult for terminals and logs.

No color is required to read it: every status carries a text label
([PASS] / [FAIL] / [ ?? ] / [ -- ]).
"""
from __future__ import annotations

from flowlens.reachability.models import CheckStatus, ReachabilityResult
from flowlens.reachability.netutil import protocol_label


def render_text(result: ReachabilityResult, *, verbose: bool = False) -> str:
    lines: list[str] = []
    add = lines.append
    add("FlowLens Reachability Analysis")
    port = str(result.port) if result.port else "-"
    add(f"Source: {result.source}   Destination: {result.destination}   Protocol: {protocol_label(result.protocol)}   Port: {port}")
    if result.topology_connected is not None:
        state = "connected" if result.topology_connected else "NOT connected"
        add(f"Topology: {state} in the resource graph (shown for contrast only; connectivity is not proof of reachability)")
    add("")
    add("PATH")
    add(result.path_label or "(no candidate path)")
    add("")
    add("HOPS")
    for hop in result.path:
        ports = f"{hop.port_in} -> {hop.port_out}" if hop.kind == "forward" else (str(hop.port_out) if hop.port_out else "-")
        add(f"  {hop.index}. {hop.status.label} {hop.from_label} -> {hop.to_label}  [{hop.kind}, port {ports}]")
    add("")
    add("VALIDATION")
    for check in result.checks:
        if check.status == CheckStatus.NOT_APPLICABLE and not verbose:
            add(f"{check.status.label} hop {check.hop_index} {check.check_type}: {check.reason}")
            continue
        add(f"{check.status.label} hop {check.hop_index} {check.check_type}: {check.reason}")
        shown = check.evidence if verbose else check.evidence[: 2 if check.status == CheckStatus.ALLOWED else 6]
        for ev in shown:
            add(f"         evidence: {ev}")
        if len(check.evidence) > len(shown):
            add(f"         ... {len(check.evidence) - len(shown)} more evidence lines (use --verbose)")
    if result.subnets:
        add("")
        add("SUBNETS (classified from routing evidence, never from names)")
        for sn in result.subnets:
            add(f"  {sn['classification']:<7} {sn['label']}  {sn.get('cidr') or ''}")
            for ev in sn["evidence"][:2]:
                add(f"          evidence: {ev}")
    others = [c for c in result.candidates if not c.get("chosen")]
    if others:
        add("")
        add(f"OTHER CANDIDATE PATHS ({len(others)} evaluated, limit {result.limits.get('max_candidates')})")
        for c in others:
            label = CheckStatus(c["status"]).label
            add(f"  {label} {c['label']}")
            if c.get("reason"):
                add(f"         {c['reason']}")
    if result.uncertainties:
        add("")
        add("UNCERTAINTIES / NOT EVALUATED")
        for u in result.uncertainties:
            add(f"  - {u}")
    add("")
    add(f"RESULT: {result.overall_status.value}")
    if result.blocked_at:
        add(f"{'Blocked at' if result.overall_status == CheckStatus.BLOCKED else 'Undetermined at'}: {result.blocked_at}")
    add(f"Reason: {result.reason}")
    for s in result.suggestions[:3]:
        add(f"Suggested investigation: {s}")
    return "\n".join(lines)
