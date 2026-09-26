# Architecture Decision Records

Decisions behind Repository Intelligence (RI). The approved design they record is
"FlowLens — Phase 1 Repository Intelligence Architecture, Revision 2" (referred to
below as *the proposal*, with its section numbers `§N`). Each ADR states what is
decided, what is implemented in Phase 1, and what is deferred.

| # | Title | Status |
|---|-------|--------|
| [0001](0001-repository-intelligence-domain-model.md) | Repository Intelligence is a separate domain model | Accepted |
| [0002](0002-desired-observed-correlated-separation.md) | Desired / Observed / Correlated separation and provider neutrality | Accepted |
| [0003](0003-repository-relative-identity.md) | Deterministic, repository-relative identity | Accepted |
| [0004](0004-confidence-and-ambiguity.md) | Ordinal confidence, ambiguity is not a drop, lifecycle stages | Accepted |
| [0005](0005-dual-role.md) | DUAL_ROLE is a first-class role with separate deployment contexts | Accepted |
| [0006](0006-evidence-and-provenance.md) | Evidence and provenance: observed vs inferred, name hints, independence | Accepted |
| [0007](0007-identity-migration.md) | Identity migration: version-gated legacy purge, atomic save | Accepted (not executed in Phase 1) |
| [0008](0008-cardinality.md) | Cardinality is never invented | Accepted |
| [0009](0009-repository-security-and-redaction.md) | Repository artifact security and redaction | Accepted |
| [0010](0010-configuration-module-source-instance-separation.md) | Configuration vs module source vs module instance | Accepted |
| [0011](0011-environment-vs-deployment-context.md) | Environment is not a deployment context | Accepted |

Phase 1 implements the representation only (`src/flowlens/repository/`). It does not
change the production scanner (`ingest/`, `discover/`, `linking/`, `reachability/`,
`compare/`, `storage/`, `api/`, `cli.py`), and it does not run the migration.

Note on naming: the proposal sketches the package as `flowlens.repo`. It is
implemented as `flowlens.repository`. This is a different package from
`flowlens.storage.repository` (the SQLite DAO), and the two are unrelated.
