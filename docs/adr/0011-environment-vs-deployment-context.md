# 0011. Environment is not a deployment context

Status: Accepted. Phase 1 implements `DeploymentContext` without any environment concept.

## Context

Two tempting shortcuts are both wrong:
- "One configuration = one environment." A single root is often applied several times
  with `-var-file=prod.tfvars`/`staging.tfvars` or with workspaces (§23).
- "The directory is called `prod/`, so the resources are prod." That is a name hint, not
  evidence (ADR 0006).

Both multiply or label resources without evidence that anything was ever applied that way.

## Decision

- `DeploymentContext` is **one independent apply unit**: a root configuration in its root
  role, `ctx:root:<cfg>`. It is separate from `TerraformConfiguration`. It records its root,
  its role and confidence (inherited, never promoted), and *candidate* context metadata:
  `workspace`, `var_files` (VarFileArtifact ids), `backend`, and `state`.
- Var files and workspaces are **candidates, not contexts**. Their existence does not mean
  they were applied, and they do not change the context id or multiply instances.
  `VarFileArtifact` records only Terraform's own filename semantics (`kind`, `autoloaded`)
  and never values.
- "Environment" is **not modeled** in RI. There is no `environment` field on any
  configuration, context, or instance (test-enforced). An environment label may later be an
  INFERRED hint (at most MEDIUM, §28) attached as evidence, never identity.
- Future qualified contexts (`ctx:root:<cfg>@ws=prod`, `@vars=env/prod.tfvars`) are created
  only from execution evidence, such as a CI step or state bound per workspace. They
  *append* a qualifier, so default-context ids stay valid. Qualifiers are not implemented
  in Phase 1.

## Consequences

- The number of environments stays UNKNOWN until evidence exists, which is honest and never
  inflates counts.
- Correlation can later use account/region/workspace as constraints without having baked
  them into identity.
