# 0003. Deterministic, repository-relative identity

Status: Accepted. Phase 1 implements the id builders; the production scanner does not use them yet.

## Context

Legacy config-only node ids are `tf:<address>` (`flowlens.ids.make_tf_only_node_id`). They
carry no configuration qualifier, so identical addresses in two roots collide (G2, G4).
Any fix must not introduce machine dependence: the same repository checked out at
`/home/alice/project`, `/tmp/project`, or `/build/project` must produce the same ids.
Consumers such as `matcher._cloud_id_from_node_id` and `reachability/facts.node_label`
depend on the `tf:` prefix.

## Decision

- **Anchor.** The anchor is the nearest ancestor of the scan path that contains `.git`
  (a directory, or a file for worktrees), found by filesystem lookup only, without the git
  binary. If there is none, the anchor is the scan root, recorded as `kind=scan_root`.
  `RepositoryAnchor` stores the kind and `scan_root_rel`, **never an absolute path**. The
  absolute directory exists only in the transient `ids.AnchorResolution`, excluded from
  `repr`.
- **Paths.** Paths are anchor-relative POSIX, normalized with `posixpath.normpath`, with no
  trailing slash, `"."` for the anchor, case preserved, and `..` segments for directories
  outside the anchor (`outside_anchor=True`). Absolute paths raise `ValueError` wherever a
  path enters the model, and `RepositoryModel.validate()` scans all serialized strings for
  absolute paths.
- **Configuration identity is directory-level.** It is `cfg:<dir>`, and filenames never
  contribute. `main.tf` → `banana.tf` leaves every configuration and declaration id
  unchanged (test). `.tf` files are `SourceFileRef` provenance only. Only
  Terraform-defined filename semantics affect the *syntactic* `ArtifactKind`: override
  files, `.tf.json`, `terraform.tfvars`/`*.auto.tfvars`, and `.terraform.lock.hcl`.
- **Id forms** (§35): `art:`, `cfg:`, `modsrc:<kind>:`, `call:<cfg>::module.<name>`,
  `ctx:root:<cfg>`, `<ctx>::<module path>`, `decl:<cfg>::<mode>.<type>.<name>`,
  `tf:<root cfg>::<address>`, content-addressed `fact:`/`ev:`/`diag:` (sha256 over
  canonical JSON, truncated to 16 hex characters), `inf:<rule>:<subject>`, and
  `amb:<kind>:<subject>`.
- **Separator safety.** Inside ids, `%` → `%25` and `:` → `%3A` in paths, so the first
  `::` in a `tf:` id is always the configuration/address separator. Terraform keys such as
  `["a::b"]` can only appear after it. The `%` encoding goes slightly beyond the proposal,
  which only mentions `:`. It keeps the encoding injective.
- **Canonical form.** `ids.canonical_json` uses sorted keys, fixed separators, and no
  whitespace. Every model collection is sorted by id, and reference tuples are sorted and
  de-duplicated, so `RepositoryModel.to_json()` is byte-identical regardless of traversal
  or insertion order.
- **Forbidden in ids:** absolute paths, hostnames, usernames, timestamps, UUIDs, random
  values, iteration order, cloud account ids, and credentials (module-source ids use
  `redact.canonical_source_url`).
- The `tf:` prefix is preserved. Future qualified contexts (`@ws=…`, `@vars=…`, ADR 0011)
  append to the context and leave default-context ids valid. Qualifiers are not
  implemented in Phase 1.

## Consequences

- `flowlens scan .` and `flowlens scan apps/sentry` produce the same `cfg:apps/sentry`
  inside a git repository. Without `.git`, ids depend on the chosen scan root. This is a
  documented risk (§44) and is visible through `anchor.kind`.
- Tests: `test_same_repo_at_two_absolute_paths_gives_identical_ids`,
  `test_traversal_and_insertion_order_do_not_affect_ids`, and
  `test_filename_conventions_do_not_define_configuration_identity`.
- Switching production ids to `tf:<cfg>::<address>` is a node-identity change and requires
  the migration in ADR 0007. It is not done in Phase 1.
