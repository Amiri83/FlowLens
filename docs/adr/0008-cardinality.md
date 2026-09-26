# 0008. Cardinality is never invented

Status: Accepted. Phase 1 implements the type and invariant; no expression evaluation.

## Context

`count`, `for_each`, and module-level expansion make one HCL block stand for zero, one, or
many real resources. The current scanner correctly produces a single *template* node for
these (`terraform_template`, `terraform_expansion`; G8). The new model must keep that
honesty and must leave room for later evaluation without changing ids.

## Decision

- `ResourceDeclaration` (one block) and `DesiredResourceInstance` (one desired thing in one
  context) are distinct types. `MetaArguments` records `count`/`for_each` expressions as
  written (redacted, never evaluated), `dynamic` block names, and `depends_on`/`lifecycle`/
  `provider` presence.
- `Cardinality(kind, count, keys, expression)` with
  `kind ∈ {STATICALLY_RESOLVABLE, PARTIALLY_RESOLVABLE, RUNTIME_DEPENDENT, UNKNOWN}`:
  - Only STATICALLY_RESOLVABLE carries a count or keys, and every other kind rejects them.
  - A block without count/for_each is `Cardinality.single()`, because Terraform defines
    exactly one instance.
  - A block with count/for_each is UNKNOWN in the repository model.
  - `Cardinality.combine` (module path × declaration): UNKNOWN dominates, then
    RUNTIME_DEPENDENT, then PARTIALLY_RESOLVABLE. Only all-static paths get a count, the
    product. **UNKNOWN stays UNKNOWN**: `instance_count` is `None`, and it renders as
    "N = unknown", never 1.
- `dynamic` blocks shape attributes only and never change cardinality.
- A non-template `DesiredResourceInstance` must be exactly one instance. A template keeps
  the bare address as its id (`tf:<cfg>::<address>`). Resolved keys (`[key]`) are future
  additions and leave template ids unchanged.

## Consequences

- Counts can be reported as "known + unknown" instead of being coerced.
- Later evaluation (a literal `for_each` map, `count = 3`, var defaults bound to a context)
  only has to fill in `Cardinality`. The identity scheme does not change.
