# 0001. Repository Intelligence is a separate domain model

Status: Accepted (Phase 1: implemented as representation only)

## Context

The static Terraform scan (`ingest/terraform.py::parse_config_dir`) turns HCL straight
into graph `Node`s. All of its decisions (which directory is a root, which module is
instantiated where, whether two blocks are "duplicates") are implicit side effects of
building nodes, and none of them are recorded. The proposal's code grounding (§0) traces
real defects to this:

- G1 OVERCOUNT: every uncalled directory becomes a root, so unused module directories
  produce phantom resources.
- G2 UNDERCOUNT: `blocks` is keyed by bare address across roots, so `module.nlb` in two
  roots collapses into one.
- G3: "called, therefore not a root" hides DUAL_ROLE configurations.

None of this can be explained afterwards, because only the resulting nodes survive.

## Decision

We add a Repository Intelligence (RI) domain model (`flowlens.repository`) that records
*what a repository configures* before anything becomes a node (proposal §1, §2, and
Option B). RI entities, such as `TerraformConfiguration`, `ModuleSource`, `ModuleCall`,
`ModuleInstance`, `DeploymentContext`, `ResourceDeclaration`, `BackendEvidence`,
`StateArtifact`, and `VarFileArtifact`, are frozen dataclasses. They are **not**
`Node`/`Edge`. Only `DesiredResourceInstance` will be projected into graph nodes, in a
later phase.

The processing stages are formal, and each stage consumes only the outputs of earlier ones:
raw artifacts → observed facts → structural evidence → inferences → RepositoryModel →
Desired Infrastructure Model.

## Phase 1 scope

Implemented:
- `enums.py`, `model.py`, `evidence.py`, `ids.py`, `redact.py`, `explain.py`, and
  `migration.py` (contract only).
- `RepositoryModel` with sorted, duplicate-checked collections, `validate()` (referential
  integrity and invariants), `declaration_inventory()`, `desired_instances()`,
  canonical `to_json()`, and `explain()`.

Deliberately omitted because they have no Phase-1 purpose: `Pipeline` (CI is Phase 3+),
`BindingHint` and `InputBinding` (correlation and dataflow come later), Variable/Local/Output
entities (§26), the `StateArtifact.summary`, and `VarFileArtifact.variable_names`, which
need content parsing. Collection, classification, and instantiation code (§41
`anchor/artifacts/facts/structure/classify/instantiate`) is Phase 2. The only exception is
`ids.resolve_anchor`, which identity needs.

## Consequences

- Every future classification or deferral has a place to live, together with its reasons.
  Nothing has to be dropped to keep the graph simple.
- There are now two representations of Terraform: RI and the graph. They are connected
  only through an explicit projection (`DesiredResourceInstance.derive`, and in the future
  a DIM→Node projection), never by sharing classes.
- Production code does not import `flowlens.repository` in Phase 1. This is enforced by
  `test_production_code_does_not_depend_on_repository_package_yet`.
