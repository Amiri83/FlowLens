# 0005. DUAL_ROLE is a first-class role with separate deployment contexts

Status: Accepted. Phase 1 implements the representation; detection is Phase 2 (rules ROLE-C1/C2).

## Context

In Terraform, any directory can be `terraform apply`'d and any directory can be `source`d.
The current scanner assumes "called, therefore not a root" (G3). So a configuration that
is deployed on its own *and* used as a module (for example `shared-network`, §47) only
ever appears as a module instance, and its own root deployment is invisible.

## Decision

- DUAL_ROLE means that a configuration is called by at least one instantiated configuration
  (STRUCTURAL, CERTAIN) **and** has corroborated root evidence ≥ MEDIUM (§17). Being called
  is evidence *for* the module role and is never evidence *against* the root role.
- `Classification` carries two independent `RoleAssessment`s, `root_role` and
  `module_role`, each with status (`yes|no|candidate|unknown`), confidence, supporting and
  contrary evidence ids, and missing evidence kinds. `role=DUAL_ROLE` requires both to be
  `yes`, and the constructor rejects anything else.
- The two roles are **separate deployment contexts** that share one declaration:
  - `ctx:root:shared-network` (basis `dual_role_root`) →
    `tf:shared-network::aws_vpc.main`
  - `ctx:root:application` → module instance `ctx:root:application::module.network` →
    `tf:application::module.network.aws_vpc.main`
  - both reference `decl:shared-network::managed.aws_vpc.main`.
  Their ids differ by construction, so they cannot collide.
- `InstantiationRecord(status=RESOLVED_BOTH, contexts=(root ctx,), instances=(module
  instances,))` records both roles.
- Weak variant (only one medium root signal): MODULE_SOURCE with `root_role=candidate
  (LOW)`. Root instantiation is deferred with reason `ROOT_ROLE_WEAK`, while the module
  instances resolve. There is no phantom second deployment.
- There is no deduplication in DIM. Counts are per context and grouped by declaration
  ("1 declaration → 2 desired instances in 2 contexts"). If both instances bind to the
  same cloud id in the future, that is a CONFLICT correlation verdict, never a silent merge.

## Consequences

- `test_dual_role_is_representable`,
  `test_root_deployment_identity_differs_from_module_instance_identity`, and
  `test_dual_role_inventory_counts_one_declaration_two_instances` prove the shape.
  `explain()` renders both role assessments with their evidence.
- Totals will change when Phase 2 activates this: previously invisible root deployments
  appear. Reports must say why ("deployed as root AND instantiated by …").
