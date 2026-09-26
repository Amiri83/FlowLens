# 0007. Identity migration: version-gated legacy purge, atomic save

Status: Accepted as a contract. **Not executed in Phase 1**: no database is read or modified.

## Context

Persistence is additive (G6). `cli._merge_and_save` loads the whole DB graph, merges the
new scan into it, then `save_graph(replace=True)`, which is `clear()` (commits) followed by
insert-all. Once Terraform ids change from `tf:<address>` to `tf:<cfg>::<address>`
(ADR 0003), an existing DB would hold both forms of the same resource. Because id equality
is the only merge path, the two can never merge silently. The risk is duplicates, not
corruption. Also, `clear()` commits before the inserts, so a crash between them leaves an
empty DB.

## Decision

The chosen option is §36(d), the smallest safe change:

1. Gate: a meta key `terraform_identity_scheme` in the existing `meta` table. A missing key
   means legacy scheme 1. The new value is `"2"`.
2. On a command that writes Terraform-derived nodes (`scan`, `ingest-tf`) or rewrites the
   whole graph (`build-graph`, `import-json --merge`), if the stored scheme is not `"2"`
   and legacy ids exist, remove exactly the nodes matching
   `node.id.startswith("tf:") and "::" not in node.id`, plus every edge touching them.
   Cloud-id nodes (`<type>:<cloud_id>`, including state-derived nodes merged with AWS) are
   **untouched**.
3. Purge, re-insert, and the scheme stamp run in **one SQLite transaction** with the save.
   `save_graph(replace=True)` becomes atomic at the same time.
4. Print one deterministic notice. Legacy nodes from other previously scanned paths are
   removed too, because they cannot be attributed, and a rescan restores them.
5. `import-json` of a legacy export is imported as-is with a warning, and the scheme is
   cleared, so the next Terraform scan migrates it.
6. `repository_model_version` (`CURRENT_REPOSITORY_MODEL_VERSION = 1`) is a separate
   axis. Bumping it only replaces a persisted model blob, never nodes.

Rejected: general stale-node pruning or scan-ownership tracking (a snapshot subsystem and
scope creep), a full DB rebuild (it would drop AWS observations whose ids did not change),
and a new prefix `tf2:` (it breaks `startswith("tf:")` consumers and leaves duplicates).

## Phase 1 scope

`flowlens.repository.migration` encodes the contract: `IDENTITY_SCHEME_META_KEY`,
`CURRENT_IDENTITY_SCHEME`, `is_legacy_terraform_node_id`, and `migration_required`. It
imports nothing and is not called by production code.
`test_migration_contract_legacy_predicate` asserts:
- `flowlens.ids.make_tf_only_node_id(...)` output is legacy;
- `ids.desired_instance_id(...)` output is not legacy;
- cloud-id nodes are not legacy.

## Consequences

- One-time cost for users. It is announced, and a rescan restores the removed nodes.
- Known edge case: a legacy id whose address contains a key with a literal `::` (for
  example `tf:module.w["a::b"].x`) is not matched by the exact predicate and would survive
  as a stale node. This is accepted as rare. The predicate stays exact and simple, as
  approved.
- Stale nodes *within* scheme 2 (for example a resource deleted from the repository)
  remain a documented known limitation, not a Phase-2 goal.
