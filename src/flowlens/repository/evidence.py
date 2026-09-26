"""Facts, evidence, inferences and ambiguity: the provenance chain (ADR 0004, 0006).

Pipeline (each stage consumes only earlier stages)::

    RawArtifact -> ObservedFact -> Evidence (OBSERVED / STRUCTURAL / INFERRED / ASSERTED)
                -> Inference -> Classification / instantiation decision

Rules encoded here:

- An :class:`ObservedFact` is a parser-level statement ("file X contains
  ``backend "s3"``"). It never says "X is a root" or "X is prod".
- OBSERVED/STRUCTURAL/INFERRED evidence must cite the facts it rests on; only
  ASSERTED evidence may cite none. INFERRED evidence is at most HIGH.
- **Names are weak hints.** Evidence whose basis is a directory/file *name*
  (``modules/``, ``prod/``) is ``EvidenceBasis.NAME_HINT``: it must be INFERRED
  and at most LOW, so it can never, alone or against contrary structural
  evidence, move a decision (a ``modules/`` segment is not proof of
  MODULE_SOURCE; ``prod/`` is not proof of environment=prod).
- **Corroboration means independence.** A future "two MEDIUM signals ->
  stronger" rule (C-corroborate) may only count evidence items that are
  *independent*: different claims resting on disjoint source artifacts.
  Two observations of the same HCL construct are one signal. Every Evidence
  keeps its facts, and every fact keeps (artifact, locator), so
  :func:`independent` can decide this. No scoring is implemented here.
- Free-text details are redacted on construction, so repr/JSON never expose
  secret-shaped values.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from flowlens.repository import ids
from flowlens.repository.enums import (
    AmbiguityKind,
    Confidence,
    EvidenceBasis,
    FactKind,
    Polarity,
    ProvenanceKind,
)
from flowlens.repository.redact import redact_attribute, redact_text

#: Strongest strength a NAME_HINT may carry.
NAME_HINT_MAX_STRENGTH = Confidence.LOW
#: Strongest strength any heuristic (INFERRED) evidence or rule-based inference may carry.
INFERRED_MAX_STRENGTH = Confidence.HIGH

Scalar = str | int | float | bool | None


def _set(obj: Any, name: str, value: Any) -> None:
    object.__setattr__(obj, name, value)


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


@dataclass(frozen=True)
class Locator:
    """Where inside an artifact a fact was read (proposal §7)."""

    block_kind: str | None = None
    labels: tuple[str, ...] = ()
    line_start: int | None = None
    line_end: int | None = None

    def __post_init__(self) -> None:
        _set(self, "labels", tuple(self.labels))

    def as_dict(self) -> dict[str, Any]:
        return {"block_kind": self.block_kind, "labels": list(self.labels), "line_start": self.line_start, "line_end": self.line_end}

    def render(self) -> str:
        parts = [p for p in (self.block_kind, *self.labels) if p]
        text = ".".join(parts)
        if self.line_start is not None:
            text += f":L{self.line_start}" + (f"-{self.line_end}" if self.line_end not in (None, self.line_start) else "")
        return text


def _sanitize_payload(payload: Mapping[str, Scalar] | Iterable[tuple[str, Scalar]]) -> tuple[tuple[str, Scalar], ...]:
    items = payload.items() if isinstance(payload, Mapping) else payload
    out = []
    for key, value in items:
        if not isinstance(value, Scalar):
            raise TypeError(f"fact payload values must be scalars, got {type(value).__name__} for {key!r}")
        out.append((key, redact_attribute(key, value)[0]))
    return tuple(sorted(out))


@dataclass(frozen=True)
class ObservedFact:
    """A direct, parser-level statement about one artifact. No judgement.

    `payload` is small, deterministic and redacted on construction: values of
    sensitive-named keys and secret-shaped values become ``<redacted>``.
    """

    artifact: str
    locator: Locator
    kind: FactKind
    payload: tuple[tuple[str, Scalar], ...] = ()
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "payload", _sanitize_payload(self.payload))
        _set(self, "id", ids.fact_id(self.artifact, self.locator.as_dict(), self.kind.value, [list(p) for p in self.payload]))

    def payload_dict(self) -> dict[str, Scalar]:
        return dict(self.payload)


@dataclass(frozen=True)
class Evidence:
    """A claim about a subject, with provenance and strength.

    `id` is content-addressed (kind, claim, subject, facts, polarity, basis),
    so it is deterministic and independent of construction order.
    """

    kind: ProvenanceKind
    claim: str
    subject: str
    facts: tuple[str, ...]
    strength: Confidence
    polarity: Polarity = Polarity.SUPPORTS
    basis: EvidenceBasis = EvidenceBasis.CONTENT
    detail: str = ""
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "facts", _sorted_unique(self.facts))
        _set(self, "detail", redact_text(self.detail))
        if not self.facts and self.kind is not ProvenanceKind.ASSERTED:
            raise ValueError(f"{self.kind.value} evidence must cite at least one observed fact ({self.claim})")
        if self.kind is ProvenanceKind.INFERRED and self.strength > INFERRED_MAX_STRENGTH:
            raise ValueError("INFERRED evidence can never be CERTAIN")
        if self.basis is EvidenceBasis.NAME_HINT:
            if self.kind is not ProvenanceKind.INFERRED:
                raise ValueError("a name hint is a heuristic: it must be INFERRED evidence")
            if self.strength > NAME_HINT_MAX_STRENGTH:
                raise ValueError(f"name hints are weak: strength must be <= {NAME_HINT_MAX_STRENGTH.value}")
        _set(self, "id", ids.evidence_id(self.kind.value, self.claim, self.subject, self.facts, self.polarity.value, self.basis.value))


def evidence_sources(evidence: Evidence, facts_by_id: Mapping[str, ObservedFact]) -> frozenset[tuple[str, str]]:
    """(artifact, locator) pairs an evidence item ultimately rests on."""
    return frozenset((facts_by_id[f].artifact, facts_by_id[f].locator.render()) for f in evidence.facts if f in facts_by_id)


def independent(a: Evidence, b: Evidence, facts_by_id: Mapping[str, ObservedFact]) -> bool:
    """True only if `a` and `b` may count as two *independent* signals for
    C-corroborate: different claims resting on disjoint source artifacts.

    Two readings of the same HCL construct (same artifact, same locator) - or
    any two items sharing a source artifact - are not independent. ASSERTED
    items (no facts) are never counted as corroboration here.
    """
    if a.id == b.id or a.claim == b.claim:
        return False
    sa, sb = evidence_sources(a, facts_by_id), evidence_sources(b, facts_by_id)
    if not sa or not sb:
        return False
    return {art for art, _ in sa}.isdisjoint(art for art, _ in sb)


@dataclass(frozen=True)
class Alternative:
    """Another conclusion the evidence also admits."""

    conclusion: str
    confidence: Confidence


@dataclass(frozen=True)
class Inference:
    """Answers "why do you believe this?" for one conclusion about one subject.

    `rule_id` names the versioned rule that produced it; ``None`` means the
    conclusion was ASSERTED by the user. Rule-based conclusions are never
    CERTAIN. Confidence belongs to *this* conclusion and is never promoted when
    the conclusion is consumed downstream (see ``DesiredResourceInstance``).
    """

    rule_id: str | None
    subject: str
    conclusion: str
    confidence: Confidence
    supporting: tuple[str, ...] = ()
    contrary: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    alternatives: tuple[Alternative, ...] = ()
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "supporting", _sorted_unique(self.supporting))
        _set(self, "contrary", _sorted_unique(self.contrary))
        _set(self, "missing", _sorted_unique(self.missing))
        _set(self, "alternatives", tuple(sorted(set(self.alternatives), key=lambda a: (-a.confidence.rank, a.conclusion))))
        if self.rule_id is not None and self.confidence > INFERRED_MAX_STRENGTH:
            raise ValueError(f"rule {self.rule_id}: inferred conclusions can never be CERTAIN")
        overlap = set(self.supporting) & set(self.contrary)
        if overlap:
            raise ValueError(f"evidence cannot both support and contradict a conclusion: {sorted(overlap)}")
        _set(self, "id", ids.inference_id(self.rule_id, self.subject))


@dataclass(frozen=True)
class Ambiguity:
    """A first-class state of knowledge, not a disposition: the subject stays
    in the model with its alternatives, the evidence behind them, and what
    would resolve it. Ambiguity never means delete/ignore/not-Terraform."""

    kind: AmbiguityKind
    subject: str
    alternatives: tuple[Alternative, ...]
    reasons: tuple[str, ...] = ()           # evidence ids
    resolution_hints: tuple[str, ...] = ()  # e.g. "backend block", "state artifact", "CI step"
    id: str = field(init=False)

    def __post_init__(self) -> None:
        _set(self, "alternatives", tuple(sorted(set(self.alternatives), key=lambda a: (-a.confidence.rank, a.conclusion))))
        _set(self, "reasons", _sorted_unique(self.reasons))
        _set(self, "resolution_hints", _sorted_unique(self.resolution_hints))
        if len(self.alternatives) < 2:
            raise ValueError("an ambiguity needs at least two alternatives")
        _set(self, "id", ids.ambiguity_id(self.kind, self.subject))
