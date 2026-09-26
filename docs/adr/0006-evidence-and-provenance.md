# 0006. Evidence and provenance: observed vs inferred, name hints, independence

Status: Accepted. Phase 1 implements the types, invariants and the independence predicate; no scoring.

## Context

A conclusion such as "`envs/prod` is a root" is only useful if a reader can see why it was
reached, what argues against it, and what would change it. Heuristics must be kept apart
from facts. Path names are especially tempting and especially misleading: `modules/` and
`prod/` are conventions chosen by humans, not Terraform semantics (§19, "content beats
names").

## Decision

- **ObservedFact** `(artifact, locator{block_kind, labels, lines}, kind, payload)` is a
  parser-level statement with no judgement. Its id is content-addressed (`fact:<sha256>`),
  and its payload holds scalars only and is redacted on construction (ADR 0009).
- **Evidence** `(kind, claim, subject, facts, strength, polarity, basis, detail)`:
  - `kind`: OBSERVED (read from an artifact), STRUCTURAL (derived from facts by
    Terraform's own rules, for example a call edge), INFERRED (a heuristic, at most HIGH),
    ASSERTED (provided by the user).
  - Every kind except ASSERTED must cite at least one fact, so every item can be traced to
    an artifact path and line.
  - `polarity`: SUPPORTS or CONTRADICTS.
  - The id is content-addressed over (kind, claim, subject, sorted facts, polarity, basis),
    so it does not depend on order.
- **Inference** `(rule_id | None, subject, conclusion, confidence, supporting, contrary,
  missing, alternatives)` answers "why do you believe this?". The same evidence may not
  both support and contradict a conclusion. `explain(model, id)` walks
  instance → context → configuration → inference → evidence → fact → `art:path#locator`
  and renders the §40 template: because / despite / missing / alternatives /
  would change if.
- **Name hints are weak.** `Evidence.basis` is `CONTENT` or `NAME_HINT`. NAME_HINT evidence
  must be INFERRED with strength ≤ LOW (constructor check). `RepositoryModel.validate()`
  flags any inference that is supported *only* by name hints and is above LOW, or that
  stands against contrary CONTENT evidence ≥ MEDIUM. A `modules/` segment is not proof of
  MODULE_SOURCE. `prod/` is not proof of environment=prod, and no RI entity has an
  `environment` field (ADR 0011). Path segments enter the model as `FactKind.PATH_SEGMENT`
  facts, so a hint is still traceable.
- **Corroboration means independence.** The future C-corroborate rule ("two MEDIUM →
  one step stronger, up to HIGH") may count only *independent* evidence.
  `evidence.independent(a, b, facts)` returns True only for different claims resting on
  disjoint source artifacts. Two readings of the same HCL construct (for example
  `has_backend` and `has_remote_state` from one `backend "s3"` block), or two items from
  the same file, are one signal. Phase 1 provides the predicate and keeps the provenance it
  needs (artifact and locator per fact, facts per evidence item). It does **not** implement
  any scoring or combination.

## Consequences

- Classification rules in Phase 2 are forced to go through evidence. A rule cannot
  conclude from a name alone above LOW without `validate()` reporting it.
- Evidence and fact ids are stable across machines and runs, so explanations can be
  compared between scans.
