# 0002. Desired / Observed / Correlated separation and provider neutrality

Status: Accepted. Phase 1 establishes the DIM boundary types only.

## Context

The graph mixes three different questions today. Terraform nodes (what the repository
intends), AWS nodes (what a credential can see), and their merge (`Graph.add_node` on
equal ids; G7) live in one structure. `compare/matcher.py` treats a name match like an ARN
match (G10), and `compare/diff.py` labels every unmatched AWS resource `AWS_ONLY`. As a
result, "AWS sees 50 Lambdas, Terraform declares 4" reads as 46 problems, when most of
those resources are simply unrelated or have unknown ownership (§33, §34, §48).

## Decision

There are three bounded models (§3–§5):

- **Desired Infrastructure Model (DIM):** a projection of the RepositoryModel,
  DeploymentContexts × instantiated ModuleInstances × ResourceDeclarations, which gives
  `DesiredResourceInstance`s. It is derived only from the repository (and, in the future,
  from state or plan bound to a context), never from the cloud. It contains only instances
  of *instantiated* contexts.
- **Observed Cloud Model (OCM):** what an observer reports (AWS today, through
  `discover/aws.py`, unchanged). Observation implies nothing about ownership.
- **Correlated Infrastructure Model (CIM):** future `Correlation` records that link DIM
  and OCM ids with a verdict, a strength, and evidence. They link ids and never rewrite
  them. UNKNOWN is a first-class verdict.

Id equality stays the **only** storage-level merge. No new name-based or tag-based merge
keys are allowed.

Provider neutrality (ADR-010 in the proposal's list, merged here): RI is written in
Terraform concepts only. `ResourceDeclaration.provider_type` is the raw Terraform type.
AWS normalization (`flowlens.ids.normalize_terraform_type`, NLB/ALB) happens only in the
future DIM→Node projection. No RI class has an AWS-specific field. `flowlens.repository`
never imports `discover`, `aws`, `linking`, `reachability`, `models`, `graph`, `storage`,
`compare`, `ingest`, `api`, `cli`, top-level `flowlens.ids`, or boto.

## Phase 1 scope

- `DeploymentContext` and `DesiredResourceInstance` exist as boundary types.
  `DesiredResourceInstance.derive(context, declaration, module_instance)` is the single,
  explicit RI→DIM step. `RepositoryModel.desired_instances()` returns only instances whose
  context the root's `InstantiationRecord` lists, and `validate()` flags any other.
- The current scanner is **not** connected to DIM, and the production graph is unchanged.
- The package boundary is test-enforced by AST import checks, a subprocess check that
  `import flowlens.repository` loads no other FlowLens layer, and a field-name check for
  `aws|arn|account|region|vpc`.

## Consequences

- Adding Azure, GCP, or Kubernetes observers needs no RI change, because DIM ids
  (`tf:<cfg>::<address>`) are provider-agnostic.
- Drift, "unrelated", and "unknown ownership" can be distinguished later, because the
  models are not collapsed in advance.
- Until the CIM exists, `compare` keeps its current behavior (out of scope).
