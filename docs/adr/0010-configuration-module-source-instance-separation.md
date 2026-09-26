# 0010. Configuration vs module source vs module call vs module instance

Status: Accepted. Phase 1 implements the four distinct types and ids.

## Context

The current scanner conflates "a directory of HCL", "reusable module code", "a `module`
block", and "the resources that a call produces in a particular root". That is the
mechanism behind both G1, where an unused module directory becomes a root, and G2, where
`module.nlb` in two roots is treated as one "duplicate".

## Decision

Four entities with four identities (§13, §15, §16, §35):

| Entity | Meaning | Id |
|--------|---------|----|
| `TerraformConfiguration` | one directory of Terraform files, whatever its role | `cfg:modules/nlb` |
| `ModuleSource` | where module code comes from; independent of how many times or by whom it is called | `modsrc:local:modules/nlb`, `modsrc:registry:<host>/<ns>/<name>/<provider>`, `modsrc:git:<url without credentials/query>` |
| `ModuleCall` | a `module "x" {}` block in a caller (a STRUCTURAL caller→source relationship, and itself a declaration) | `call:apps/sentry::module.nlb` |
| `ModuleInstance` | a call realized in one deployment context | `ctx:root:apps/sentry::module.nlb` |

- A local `ModuleSource` points to the configuration with the same path
  (`ModuleSource.configuration`). Registry and git sources have none, because their
  contents are not fetched.
- The registry version constraint and git `ref` are attributes, not identity.
- One source called by N calls in M contexts yields N×M module instances. This is correct
  and is not double counting.
- Resource addresses inside a context are Terraform-native and context-relative
  (`module.nlb.aws_lb.this`). The context supplies the qualifier:
  `tf:apps/sentry::module.nlb.aws_lb.this` and
  `tf:apps/observability::module.nlb.aws_lb.this` never collide (the UNDERCOUNT fix).
- `ResourceDeclaration` ids are per configuration (`decl:modules/nlb::managed.aws_lb.this`).
  The declaration is shared by every instance that realizes it.

## Consequences

- Classification (a property of a configuration) and instantiation (a property of a
  context) can be decided and explained separately.
- `test_same_source_called_twice_gives_distinct_module_instances`,
  `test_module_source_ids_by_kind`, and
  `test_root_deployment_identity_differs_from_module_instance_identity` pin the shapes.
