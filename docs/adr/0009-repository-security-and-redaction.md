# 0009. Repository artifact security and redaction

Status: Accepted. Phase 1 implements minimal guard rails, not a secret scanner.

## Context

Repositories contain secrets in module source URLs (`https://user:token@host`,
`?access_token=`), backend blocks (`access_key`, `token`), tfvars, CI files, and
occasionally hard-coded literals. The RepositoryModel is meant to be persisted, exported
as JSON, and printed in explanations, so anything stored in it has to be safe to show.

## Decision

The RepositoryModel stores **structure, not secrets** (§38). Names and keys are kept, and
values that may be secret are replaced by `<redacted>`. Redaction happens **at
construction**, in `__post_init__`, so neither `repr()` nor `to_json()` can leak a value,
and bypassing a factory does not skip redaction:

- `redact.redact_url`, used for the display form (`ModuleSource.raw_source`): it masks
  userinfo (`https://***@host`) and secret query parameters (`access_token`, `token`,
  `sig`, `X-Amz-*`, SAS parameters, …). Non-secret parameters such as `ref` are kept.
- `redact.canonical_source_url`, used for the identity form (`ModuleSource.locator` and
  `modsrc:` ids for git/http/other): it drops userinfo and the whole query string.
- `redact.redact_attribute(name, value)`: if the name matches
  `password|secret|token|key|credential|private|cert|auth|signature|session`, the value is
  redacted. Otherwise `guard_value` applies. It is used for every `ObservedFact.payload`
  entry.
- `redact.guard_value` / `looks_secret` handle obvious secret *shapes* only: PEM headers,
  AWS access key ids, known token prefixes (GitHub, GitLab, Slack, Stripe, Google, `sk-`),
  JWTs, and long (≥ 32), mixed-case, digit-bearing, high-entropy (≥ 4.0 bits/char) strings
  without `.`/`:`. That last rule keeps Terraform references, ARNs, paths, and hex digests
  unflagged, as the tests check.
- `redact.redact_text`, used for free text (`Evidence.detail`, `Diagnostic.message`,
  `MetaArguments` expressions, `Cardinality.expression`): it redacts PEM blocks, URL
  credentials, `key=value` pairs with sensitive keys, and secret-shaped tokens.
- `redact.sanitize_backend_attributes`: attribute names are always kept. Values are kept
  only for an allowlist of identity-level keys (`bucket`, `key`, `region`, `encrypt`,
  `dynamodb_table`, `use_lockfile`, `workspace_key_prefix`, `organization`,
  `container_name`, `prefix`), and those values still go through the shape guard. Local
  backend `path` is deliberately excluded because it may be absolute.
- `VarFileArtifact` and `StateArtifact` hold identity and presence only. No values are
  read in Phase 1. `RawArtifact.sha256` gives provenance without storing content.
- No absolute paths, usernames, or hostnames of the scanning machine are stored
  (ADR 0003).

## Deferred

The existing `Node.desired_state` holds raw HCL bodies and state/plan attribute values.
Whether and how to redact it is a decision for the phase that projects DIM into nodes. It
is out of Phase-1 scope and is recorded here so it is not forgotten.

## Consequences

- Redaction is conservative. Some harmless values, such as a `kms_key_id` literal, are
  redacted because the name matches. This is the intended trade-off.
- The guard is not exhaustive. Hex-only secrets shorter than the entropy rule, for example,
  are not detected. The primary defense is that RI does not read values it does not need.
