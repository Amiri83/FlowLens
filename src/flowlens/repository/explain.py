"""Explanations: inference -> evidence -> facts -> artifact + locator.

Fixed template (proposal §40)::

    <conclusion> (<confidence>) [rule] because: <supporting>; despite: <contrary>;
    missing: <missing>; alternatives: <alternatives>

Rendering only - no scoring, no I/O.
"""
from __future__ import annotations

from flowlens.repository.evidence import Evidence, Inference, ObservedFact
from flowlens.repository.model import (
    DeploymentContext,
    DesiredResourceInstance,
    ModuleInstance,
    RepositoryModel,
    TerraformConfiguration,
)


def _evidence_line(model: RepositoryModel, evidence_id: str) -> str:
    ev = model.get(evidence_id)
    if not isinstance(ev, Evidence):
        return f"    - {evidence_id} (missing)"
    sources = []
    for fid in ev.facts:
        fact = model.get(fid)
        if isinstance(fact, ObservedFact):
            loc = fact.locator.render()
            sources.append(fact.artifact + (f"#{loc}" if loc else ""))
    hint = " name-hint" if ev.basis.value == "NAME_HINT" else ""
    text = f"    - [{ev.kind.value}{hint}] {ev.claim} ({ev.strength.value})"
    if ev.detail:
        text += f": {ev.detail}"
    if sources:
        text += f" @ {', '.join(sources)}"
    return text


def render_inference(model: RepositoryModel, inf: Inference) -> str:
    rule = f"rule {inf.rule_id}" if inf.rule_id else "ASSERTED"
    lines = [f"  {inf.conclusion} ({inf.confidence.value}) [{rule}]"]
    lines.append("  because:")
    lines.extend(_evidence_line(model, e) for e in inf.supporting)
    if not inf.supporting:
        lines.append("    (nothing)")
    if inf.contrary:
        lines.append("  despite:")
        lines.extend(_evidence_line(model, e) for e in inf.contrary)
    if inf.missing:
        lines.append(f"  missing: {', '.join(inf.missing)}")
    if inf.alternatives:
        lines.append("  alternatives: " + ", ".join(f"{a.conclusion} ({a.confidence.value})" for a in inf.alternatives))
    return "\n".join(lines)


def _explain_configuration(model: RepositoryModel, cfg: TerraformConfiguration) -> list[str]:
    lines = [f"{cfg.id}: stage {cfg.lifecycle.stage.value}"]
    cl = cfg.classification
    if cl is not None:
        lines[0] += f", role {cl.role.value} ({cl.confidence.value})"
        for label, ra in (("root_role", cl.root_role), ("module_role", cl.module_role)):
            missing = f"; missing: {', '.join(ra.missing)}" if ra.missing else ""
            lines.append(f"  {label}: {ra.status.value} ({ra.confidence.value}){missing}")
    rec = cfg.lifecycle.instantiation
    if rec is not None:
        text = f"  instantiation: {rec.status.value}" + (f" ({rec.reason.value})" if rec.reason else "")
        if rec.contexts:
            text += f"; contexts: {', '.join(rec.contexts)}"
        if rec.instances:
            text += f"; module instances: {', '.join(rec.instances)}"
        lines.append(text)
    for inf in model.inferences_about(cfg.id):
        lines.append(render_inference(model, inf))
    for amb in model.ambiguities:
        if amb.subject == cfg.id:
            lines.append(f"  ambiguity {amb.kind.value}: " + " | ".join(f"{a.conclusion} ({a.confidence.value})" for a in amb.alternatives))
            if amb.resolution_hints:
                lines.append(f"  would change if: {', '.join(amb.resolution_hints)}")
    return lines


def explain(model: RepositoryModel, subject: str) -> str:
    """Why does the model believe what it believes about `subject` (any id)?"""
    entity = model.get(subject)
    lines: list[str] = []
    if isinstance(entity, DesiredResourceInstance):
        lines.append(
            f"{entity.id}: desired instance of {entity.declaration} in {entity.context} "
            f"(context_role {entity.context_role.value}, confidence {entity.confidence.value}, "
            f"{'template, ' if entity.template else ''}{entity.cardinality.render()})"
        )
        entity = model.get(entity.context)
    if isinstance(entity, ModuleInstance):
        lines.append(f"{entity.id}: module instance of {entity.source} via {entity.call} ({entity.cardinality.render()})")
        entity = model.get(entity.context)
    if isinstance(entity, DeploymentContext):
        lines.append(f"{entity.id}: deployment context ({entity.basis}, {entity.role.value}, {entity.confidence.value})")
        entity = model.get(entity.root)
    if isinstance(entity, TerraformConfiguration):
        lines.extend(_explain_configuration(model, entity))
    elif isinstance(entity, Inference):
        lines.append(render_inference(model, entity))
    elif entity is None and not lines:
        infs = model.inferences_about(subject)
        if not infs:
            return f"{subject}: nothing known"
        lines.append(f"{subject}:")
        lines.extend(render_inference(model, i) for i in infs)
    elif not lines:
        lines.append(f"{subject}: {type(entity).__name__}")
        lines.extend(render_inference(model, i) for i in model.inferences_about(subject))
    return "\n".join(lines)
