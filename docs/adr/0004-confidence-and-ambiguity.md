# 0004. Ordinal confidence; ambiguity is not a drop; lifecycle stages

Status: Accepted. Phase 1 implements the representation and invariants; no classifier.

## Context

Messy repositories are allowed to produce uncertainty. They must never produce confident
but wrong output (§1). Today, a directory is either instantiated as a root or silently not
instantiated, and there is no way to express "we are not sure". Numeric scores such as 0.83
would look precise while being arbitrary, and they cannot be explained.

## Decision

**Confidence is ordinal only** (§10): `CERTAIN > HIGH > MEDIUM > LOW > UNKNOWN`
(`enums.Confidence`, with rich comparisons and `min_confidence`). There are no floats
anywhere.
- C-min: a derived conclusion is ≤ its weakest premise. `DesiredResourceInstance.derive`
  takes `min(context confidence, path confidence)`. Confidence can only stay the same or
  go down.
- Inferred conclusions are never CERTAIN: `Inference` with a `rule_id` is at most HIGH, and
  so is `Evidence(kind=INFERRED)`. Only OBSERVED/STRUCTURAL facts or ASSERTED claims
  (`rule_id=None` → `inf:ASSERTED:<subject>`) may be CERTAIN.
- **No promotion.** Confidence attaches to the inference it describes. When a conclusion is
  consumed downstream, it keeps its role and confidence:
  - `Classification` and `DeploymentContext`: PROBABLE_ROOT is MEDIUM or LOW by definition,
    and CONFIRMED_ROOT is ≥ HIGH. Anything else raises.
  - `DesiredResourceInstance`: it copies `context_role` from its context. An instance of a
    PROBABLE_ROOT context cannot exceed MEDIUM (constructor check).
    `RepositoryModel.validate()` flags an instance whose role differs from its context's
    role, or whose confidence exceeds it. It also flags a context whose confidence exceeds
    its root classification.
- C-corroborate, C-conflict, and C-partial are Phase-2 rules and are not implemented. The
  independence requirement for C-corroborate is fixed in ADR 0006.

**Ambiguity is a state of knowledge** (§11, §18):
- Roles: `CONFIRMED_ROOT | PROBABLE_ROOT | MODULE_SOURCE | DUAL_ROLE | AMBIGUOUS | UNKNOWN`.
  `Classification` enforces role/assessment consistency. For example, MODULE_SOURCE needs
  module_role=yes, and DUAL_ROLE needs both roles set to yes.
- `Ambiguity(kind, subject, alternatives ≥ 2, reasons, resolution_hints)` is first-class.
  An AMBIGUOUS configuration without an Ambiguity record fails `validate()`.
- **A1:** AMBIGUOUS/UNKNOWN never mean delete, ignore, or not-Terraform. The
  configuration, its files, facts, declarations, and diagnostics stay in the model.
- **A2:** understanding and instantiation are separate decisions. Only the
  `InstantiationRecord` can be DEFERRED/NOT_APPLICABLE/PARTIAL, and those statuses
  *require* a reason code (`InstantiationReason`) and an inference id. DEFERRED and
  NOT_APPLICABLE cannot carry contexts or instances.
- **A3:** `role_counts()` counts every configuration exactly once, with `UNCLASSIFIED` for
  configurations that stopped at DISCOVERED. Duplicate ids are rejected.
- `declaration_inventory()` keeps the full declaration inventory, including declarations
  in deferred or not-applicable configurations. It renders the proposal's summary, for
  example "2 configurations deferred (AMBIGUOUS_ROLE) — 4 resource declarations not
  instantiated: …".

**Lifecycle** (§12): `DISCOVERED → CLASSIFIED → INSTANTIATED → CORRELATED`. A
classification exists exactly when stage ≥ CLASSIFIED, and an instantiation record exists
exactly when stage ≥ INSTANTIATED. A newly discovered configuration has neither, so
discovery never implies instantiation.

## Consequences

- A future classifier cannot express a PROBABLE_ROOT at HIGH, a DUAL_ROLE without both
  roles, a deferral without a reason, or an ambiguity without alternatives. The types
  reject these outright.
- Deferred configurations do not appear in DIM (no phantom resources), but they appear in
  the inventory with reasons (no silent loss).
