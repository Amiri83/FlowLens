"""Phase 1 Repository Intelligence: domain model, identity, evidence,
confidence, redaction and package boundaries. No classifier is exercised -
models are built by hand (tests/repository_fixtures.py)."""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import os
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

from flowlens import ids as legacy_ids
from flowlens.repository import (
    CURRENT_REPOSITORY_MODEL_VERSION,
    Alternative,
    Ambiguity,
    AmbiguityKind,
    AnchorKind,
    ArtifactKind,
    BackendEvidence,
    BackendKind,
    Cardinality,
    CardinalityKind,
    Classification,
    Confidence,
    ConfigurationLifecycle,
    ConfigurationRole,
    DeclarationMode,
    DeploymentContext,
    DesiredResourceInstance,
    Diagnostic,
    Evidence,
    EvidenceBasis,
    FactKind,
    Inference,
    InstantiationReason,
    InstantiationRecord,
    InstantiationStatus,
    LifecycleStage,
    Locator,
    MetaArguments,
    ModuleInstance,
    ModuleSource,
    ModuleSourceKind,
    ObservedFact,
    ProvenanceKind,
    RawArtifact,
    RepositoryAnchor,
    RepositoryModel,
    ResourceDeclaration,
    RoleAssessment,
    RoleStatus,
    Severity,
    SourceFileRef,
    TerraformConfiguration,
    VarFileArtifact,
    VarFileKind,
    explain,
    independent,
    migration,
    min_confidence,
    redact,
    schema_version,
)
from flowlens.repository import ids as ri_ids
from repository_fixtures import Builder, declare, dual_role_model, messy_model, name_hint_evidence

C = Confidence
REPO_PKG = Path(__file__).resolve().parent.parent / "src" / "flowlens" / "repository"


# --------------------------------------------------------------------------- 1-5 roles are representable


def test_schema_version():
    assert schema_version == CURRENT_REPOSITORY_MODEL_VERSION == 1
    assert dual_role_model().schema_version == 1


def test_confirmed_root_is_representable():
    m = dual_role_model()
    app = m.get("cfg:application")
    assert app.role is ConfigurationRole.CONFIRMED_ROOT
    assert app.classification.confidence is C.HIGH
    assert app.lifecycle.instantiation.contexts == ("ctx:root:application",)
    assert m.validate() == ()


def test_probable_root_is_representable():
    m = messy_model()
    potato = m.get("cfg:potato")
    assert potato.role is ConfigurationRole.PROBABLE_ROOT
    assert potato.classification.confidence is C.MEDIUM
    assert m.get("ctx:root:potato").role is ConfigurationRole.PROBABLE_ROOT
    assert m.validate() == ()


def test_probable_root_cannot_claim_high_confidence():
    ra = RoleAssessment(RoleStatus.YES, C.HIGH)
    with pytest.raises(ValueError, match="PROBABLE_ROOT"):
        Classification(ConfigurationRole.PROBABLE_ROOT, C.HIGH, ra, RoleAssessment.unknown(), "inf:x:cfg:a")
    with pytest.raises(ValueError, match="PROBABLE_ROOT"):
        DeploymentContext("a", ConfigurationRole.PROBABLE_ROOT, C.HIGH)


def test_ambiguous_and_unknown_configurations_are_preserved_not_dropped():
    m = messy_model()
    ambiguous = [c for c in m.configurations if c.role is ConfigurationRole.AMBIGUOUS]
    assert [c.path for c in ambiguous] == ["stuff/a", "stuff/b"]
    for c in ambiguous:
        assert c.lifecycle.instantiation.status is InstantiationStatus.DEFERRED
        assert c.lifecycle.instantiation.reason is InstantiationReason.AMBIGUOUS_ROLE
        assert c.files  # provenance kept
        amb = m.get(f"amb:ROLE:{c.id}")
        assert len(amb.alternatives) == 2 and amb.reasons and amb.resolution_hints
    unknown = m.get("cfg:random")
    assert unknown.role is ConfigurationRole.UNKNOWN
    assert unknown.lifecycle.instantiation.reason is InstantiationReason.PARSE_FAILED
    assert any(d.subject == "cfg:random" for d in m.diagnostics)
    # A3 conservation: every discovered configuration is counted exactly once.
    counts = m.role_counts()
    assert sum(counts.values()) == len(m.configurations) == 5
    assert counts == {"AMBIGUOUS": 2, "PROBABLE_ROOT": 1, "UNCLASSIFIED": 1, "UNKNOWN": 1}


def test_ambiguous_without_ambiguity_record_is_flagged():
    m = messy_model()
    stripped = dataclasses.replace(m, ambiguities=tuple(a for a in m.ambiguities if a.subject != "cfg:stuff/a"))
    assert any("cfg:stuff/a: AMBIGUOUS configuration has no Ambiguity record" in v for v in stripped.validate())


def test_ambiguity_needs_alternatives():
    with pytest.raises(ValueError, match="two alternatives"):
        Ambiguity(AmbiguityKind.ROLE, "cfg:x", (Alternative("role=PROBABLE_ROOT", C.MEDIUM),))


def test_ambiguous_config_retains_its_declarations():
    m = messy_model()
    decls = [d for d in m.resource_declarations if d.configuration == "cfg:stuff/a"]
    assert [d.id for d in decls] == [f"decl:stuff/a::managed.aws_lambda_function.fn{i}" for i in range(3)]
    assert not any(i.declaration in {d.id for d in decls} for i in m.resource_instances)


def test_dual_role_is_representable():
    m = dual_role_model()
    sn = m.get("cfg:shared-network")
    assert sn.role is ConfigurationRole.DUAL_ROLE
    assert sn.classification.root_role.status is RoleStatus.YES
    assert sn.classification.module_role.status is RoleStatus.YES
    assert sn.lifecycle.instantiation.status is InstantiationStatus.RESOLVED_BOTH
    assert sn.lifecycle.instantiation.contexts == ("ctx:root:shared-network",)
    assert sn.lifecycle.instantiation.instances == ("ctx:root:application::module.network",)
    assert m.get("ctx:root:shared-network").basis == "dual_role_root"
    with pytest.raises(ValueError, match="DUAL_ROLE requires"):
        Classification(ConfigurationRole.DUAL_ROLE, C.HIGH, RoleAssessment(RoleStatus.CANDIDATE, C.LOW),
                       RoleAssessment(RoleStatus.YES, C.CERTAIN), "inf:x:cfg:a")


# --------------------------------------------------------------------------- 6 identity separation


def test_root_deployment_identity_differs_from_module_instance_identity():
    m = dual_role_model()
    by_id = {i.id: i for i in m.resource_instances}
    root = by_id["tf:shared-network::aws_vpc.main"]
    inst = by_id["tf:application::module.network.aws_vpc.main"]
    assert root.declaration == inst.declaration == "decl:shared-network::managed.aws_vpc.main"
    assert root.context == "ctx:root:shared-network" and inst.context == "ctx:root:application"
    assert root.address == "aws_vpc.main" and inst.address == "module.network.aws_vpc.main"
    # source, call and instance are three distinct identities
    assert m.get("modsrc:local:shared-network").configuration == "cfg:shared-network"
    assert m.get("call:application::module.network").caller == "cfg:application"
    assert m.get("ctx:root:application::module.network").source == "modsrc:local:shared-network"
    assert "tf:application::aws_lambda_function.app" in by_id


def test_same_source_called_twice_gives_distinct_module_instances():
    a = ModuleInstance("ctx:root:apps/sentry", "module.nlb", "call:apps/sentry::module.nlb", "modsrc:local:modules/nlb")
    b = ModuleInstance("ctx:root:apps/observability", "module.nlb", "call:apps/observability::module.nlb", "modsrc:local:modules/nlb")
    assert a.id != b.id and a.source == b.source
    assert ri_ids.desired_instance_id(a.context, "module.nlb.aws_lb.this") == "tf:apps/sentry::module.nlb.aws_lb.this"


def test_module_source_ids_by_kind():
    assert ModuleSource(ModuleSourceKind.LOCAL, "modules/./nlb/").id == "modsrc:local:modules/nlb"
    reg = ModuleSource(ModuleSourceKind.REGISTRY, "terraform-aws-modules/vpc/aws", version_constraint="~> 5.0")
    assert reg.id == "modsrc:registry:registry.terraform.io/terraform-aws-modules/vpc/aws"
    assert reg.configuration is None and reg.version_constraint == "~> 5.0"


def test_ids_percent_encode_colon_so_first_double_colon_is_the_separator():
    ctx = ri_ids.context_id("weird:dir")
    node = ri_ids.desired_instance_id(ctx, 'module.w["a::b"].aws_s3_bucket.x')
    assert node == 'tf:weird%3Adir::module.w["a::b"].aws_s3_bucket.x'
    assert ri_ids.split_desired_instance_id(node) == ("weird%3Adir", 'module.w["a::b"].aws_s3_bucket.x')


def test_absolute_paths_are_rejected():
    for bad in ("/home/alice/project", "C:\\repo", "\\\\server\\share"):
        with pytest.raises(ValueError, match="absolute path"):
            TerraformConfiguration(bad)


# --------------------------------------------------------------------------- 7-9 deterministic repository-relative identity

_RES_RE = re.compile(r'^(resource|data)\s+"([^"]+)"\s+"([^"]+)"', re.M)


def _write_repo(root: Path, main_name: str = "main.tf") -> None:
    (root / ".git").mkdir(parents=True)
    files = {
        f"apps/sentry/{main_name}": 'module "nlb" {\n  source = "../../modules/nlb"\n}\n',
        "modules/nlb/lb.tf": 'resource "aws_lb" "this" {\n  load_balancer_type = "network"\n}\n',
        f"envs/prod/{main_name}": 'resource "aws_vpc" "main" {}\ndata "aws_region" "current" {}\n',
        "envs/prod/terraform.tfvars": 'cidr = "10.0.0.0/16"\n',
        "envs/prod/.terraform.lock.hcl": "# lock\n",
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _model_from_tree(scan_path: Path, shuffle_seed: int | None = None) -> RepositoryModel:
    """Test-only collector: files -> artifacts, directories -> configurations,
    blocks -> declarations. It is NOT the Phase 2 discovery; it exists to prove
    that identity is anchor-relative and order-independent."""
    anchor = ri_ids.resolve_anchor(scan_path)
    paths = [Path(d) / f for d, _, fs in os.walk(scan_path) if ".git" not in Path(d).parts for f in fs]
    if shuffle_seed is None:
        paths.sort()
    else:
        random.Random(shuffle_seed).shuffle(paths)
    b = Builder(anchor=RepositoryAnchor.from_resolution(anchor))
    dirs: dict[str, list[str]] = {}
    for p in paths:
        rel = anchor.relative(p)
        b.add("artifacts", RawArtifact(rel, sha256=hashlib.sha256(p.read_bytes()).hexdigest(), size=p.stat().st_size))
        if rel.endswith(".tf"):
            cfg = rel.rsplit("/", 1)[0]
            dirs.setdefault(cfg, []).append(rel)
            for mode, tf_type, name in _RES_RE.findall(p.read_text()):
                m = DeclarationMode.DATA if mode == "data" else DeclarationMode.MANAGED
                b.add("resource_declarations", ResourceDeclaration(cfg, m, tf_type, name))
    for cfg, files in dirs.items():
        b.add("configurations", TerraformConfiguration(cfg, files=tuple(SourceFileRef(ri_ids.artifact_id(f)) for f in files)))
    return b.model()


def test_same_repo_at_two_absolute_paths_gives_identical_ids(tmp_path):
    alice = tmp_path / "home" / "alice" / "project"
    build = tmp_path / "build" / "ci-4711" / "project"
    _write_repo(alice)
    _write_repo(build)
    ma, mb = _model_from_tree(alice), _model_from_tree(build)
    assert ma.to_json() == mb.to_json()
    assert {c.id for c in ma.configurations} == {"cfg:apps/sentry", "cfg:envs/prod", "cfg:modules/nlb"}
    assert "decl:envs/prod::data.aws_region.current" in {d.id for d in ma.resource_declarations}
    assert ma.anchor == RepositoryAnchor(AnchorKind.GIT_TOPLEVEL, ".")
    for s in (str(alice), str(build), str(tmp_path)):
        assert s not in ma.to_json() and s not in repr(ma)
    assert ma.validate() == ()


def test_scanning_a_subdirectory_keeps_anchor_relative_ids(tmp_path):
    repo = tmp_path / "project"
    _write_repo(repo)
    sub = _model_from_tree(repo / "envs" / "prod")
    assert sub.anchor.scan_root_rel == "envs/prod"
    assert [c.id for c in sub.configurations] == ["cfg:envs/prod"]


def test_without_git_the_scan_root_is_the_anchor(tmp_path):
    (tmp_path / "x").mkdir()
    res = ri_ids.resolve_anchor(tmp_path / "x")
    if res.kind is AnchorKind.SCAN_ROOT:  # tmp dirs are not inside a git checkout
        assert res.scan_root_rel == "." and res.relative(tmp_path / "x" / "a" / "main.tf") == "a/main.tf"
    assert str(tmp_path) not in repr(res)


def test_traversal_and_insertion_order_do_not_affect_ids(tmp_path):
    repo = tmp_path / "project"
    _write_repo(repo)
    reference = _model_from_tree(repo).to_json()
    for seed in range(5):
        assert _model_from_tree(repo, shuffle_seed=seed).to_json() == reference
    m = dual_role_model()
    shuffled = {}
    for f in dataclasses.fields(m):
        value = getattr(m, f.name)
        if isinstance(value, tuple):
            value = list(reversed(value))
        shuffled[f.name] = tuple(value) if isinstance(value, list) else value
    assert RepositoryModel(**shuffled).to_json() == m.to_json()


def test_evidence_id_independent_of_fact_order():
    a = Evidence(ProvenanceKind.OBSERVED, "c", "cfg:x", ("fact:2", "fact:1"), C.CERTAIN)
    b = Evidence(ProvenanceKind.OBSERVED, "c", "cfg:x", ("fact:1", "fact:2", "fact:1"), C.CERTAIN)
    assert a.id == b.id and a.facts == ("fact:1", "fact:2")


def test_duplicate_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate id"):
        RepositoryModel(RepositoryAnchor(AnchorKind.SCAN_ROOT), configurations=(TerraformConfiguration("a"), TerraformConfiguration("a/")))


def test_filename_conventions_do_not_define_configuration_identity(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    _write_repo(one, "main.tf")
    _write_repo(two, "banana.tf")
    m1, m2 = _model_from_tree(one), _model_from_tree(two)
    assert [c.id for c in m1.configurations] == [c.id for c in m2.configurations]
    assert [d.id for d in m1.resource_declarations] == [d.id for d in m2.resource_declarations]
    # only provenance differs
    assert m1.get("cfg:envs/prod").files != m2.get("cfg:envs/prod").files


def test_artifact_kinds_follow_terraform_filename_rules_only():
    k = ri_ids.artifact_kind_for
    assert k("a/main.tf") is k("a/banana.tf") is k("a/prod.tf") is ArtifactKind.TF_HCL
    assert k("a/override.tf") is k("a/x_override.tf") is ArtifactKind.TF_OVERRIDE
    assert k("a/x.tf.json") is ArtifactKind.TF_JSON
    assert k("a/terraform.tfvars") is k("a/prod.tfvars") is ArtifactKind.TFVARS
    assert k("a/x.auto.tfvars") is ArtifactKind.AUTO_TFVARS
    assert k("a/.terraform.lock.hcl") is ArtifactKind.LOCKFILE
    assert k(".github/workflows/deploy.yml") is ArtifactKind.CI_CONFIG
    assert k("a/.terraform", is_dir=True) is ArtifactKind.DOT_TERRAFORM_DIR
    assert k("modules/README.md") is ArtifactKind.OTHER


# --------------------------------------------------------------------------- 10-12 evidence, confidence, explainability


def test_evidence_distinguishes_observed_structural_inferred_asserted():
    m = dual_role_model()
    kinds = {e.claim: e.kind for e in m.evidence}
    assert kinds["cfg.has_backend"] is ProvenanceKind.OBSERVED
    assert kinds["cfg.called_by"] is ProvenanceKind.STRUCTURAL
    with pytest.raises(ValueError, match="must cite at least one observed fact"):
        Evidence(ProvenanceKind.INFERRED, "cfg.looks_like_root", "cfg:x", (), C.MEDIUM)
    with pytest.raises(ValueError, match="never be CERTAIN"):
        Evidence(ProvenanceKind.INFERRED, "cfg.looks_like_root", "cfg:x", ("fact:1",), C.CERTAIN)
    asserted = Evidence(ProvenanceKind.ASSERTED, "cfg.user_root", "cfg:x", (), C.CERTAIN, detail="--root x")
    assert asserted.kind is ProvenanceKind.ASSERTED and asserted.strength is C.CERTAIN


def test_confidence_is_ordinal_and_min_is_weakest_link():
    assert C.CERTAIN > C.HIGH > C.MEDIUM > C.LOW > C.UNKNOWN
    assert sorted([C.LOW, C.CERTAIN, C.UNKNOWN, C.MEDIUM]) == [C.UNKNOWN, C.LOW, C.MEDIUM, C.CERTAIN]
    assert min_confidence(C.HIGH, C.MEDIUM, C.CERTAIN) is C.MEDIUM
    assert not any(isinstance(c.value, float) for c in C)


def test_confidence_is_preserved_on_inference():
    m = messy_model()
    inf = m.get("inf:ROLE-U2:cfg:potato")
    assert inf.confidence is C.MEDIUM
    assert m.get("cfg:potato").classification.inference == inf.id
    with pytest.raises(ValueError, match="never be CERTAIN"):
        Inference("ROLE-U1", "cfg:x", "role=CONFIRMED_ROOT", C.CERTAIN)
    assert Inference(None, "cfg:x", "role=CONFIRMED_ROOT", C.CERTAIN).id == "inf:ASSERTED:cfg:x"


def test_evidence_provenance_supports_explainability():
    m = dual_role_model()
    text = explain(m, "tf:shared-network::aws_vpc.main")
    assert "context_role DUAL_ROLE, confidence HIGH" in text
    assert "cfg:shared-network: stage INSTANTIATED, role DUAL_ROLE (HIGH)" in text
    assert "root_role: yes (HIGH); missing: ci_execution" in text
    assert "module_role: yes (CERTAIN)" in text
    assert "role=DUAL_ROLE (HIGH) [rule ROLE-C1]" in text
    assert ('[OBSERVED] cfg.has_backend (CERTAIN): shared-network/main.tf declares backend "s3" '
            "@ art:shared-network/main.tf#terraform.backend.s3:L1-4") in text
    assert "[STRUCTURAL] cfg.called_by (CERTAIN): called by application as module.network" in text

    amb = explain(messy_model(), "cfg:stuff/a")
    assert "despite:" in amb and "cfg.required_var_unsatisfied" in amb
    assert "alternatives: role=MODULE_SOURCE(unused) (MEDIUM), role=PROBABLE_ROOT (MEDIUM)" in amb
    assert "would change if:" in amb and "backend block" in amb
    assert explain(m, "cfg:nope") == "cfg:nope: nothing known"


def test_corroboration_requires_independent_sources():
    b = Builder()
    f_backend = b.fact("envs/prod/main.tf", FactKind.BACKEND_BLOCK, "terraform", ("backend", "s3"), (1, 4))
    f_provider = b.fact("envs/prod/main.tf", FactKind.PROVIDER_CONFIG, "provider", ("aws",), (6, 8))
    f_tfvars = b.fact("envs/prod/terraform.tfvars", FactKind.ARTIFACT_PRESENT)
    e1 = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_backend", "cfg:envs/prod", [f_backend], C.CERTAIN)
    e1_again = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_remote_state", "cfg:envs/prod", [f_backend], C.MEDIUM)
    e_provider = b.evidence(ProvenanceKind.OBSERVED, "cfg.provider_configured", "cfg:envs/prod", [f_provider], C.MEDIUM)
    e_tfvars = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_autoloaded_tfvars", "cfg:envs/prod", [f_tfvars], C.MEDIUM)
    facts = {f.id: f for f in b.parts["facts"]}
    # two claims read from the very same HCL construct are one signal
    assert not independent(e1, e1_again, facts)
    # same artifact, different constructs: still not independent
    assert not independent(e1_again, e_provider, facts)
    # different artifacts, different claims: independent
    assert independent(e_provider, e_tfvars, facts)
    assert independent(e1, e_tfvars, facts)
    # provenance needed for that decision is on the model
    assert facts[f_backend.id].artifact == "art:envs/prod/main.tf" and facts[f_backend.id].locator.line_start == 1


def test_path_names_are_weak_hints_only():
    b = Builder()
    with pytest.raises(ValueError, match="name hints are weak"):
        name_hint_evidence(Builder(), "modules/network", "modules", strength=C.MEDIUM)
    with pytest.raises(ValueError, match="must be INFERRED"):
        Evidence(ProvenanceKind.OBSERVED, "cfg.path_hint_env", "cfg:envs/prod", ("fact:1",), C.LOW, basis=EvidenceBasis.NAME_HINT)

    # a conclusion resting only on a name hint, against content evidence, is flagged
    hint = name_hint_evidence(b, "modules/network", "modules")
    f_backend = b.fact("modules/network/main.tf", FactKind.BACKEND_BLOCK, "terraform", ("backend", "s3"), (1, 3))
    backend = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_backend", "cfg:modules/network", [f_backend], C.CERTAIN)
    b.inference("ROLE-X", "cfg:modules/network", "role=MODULE_SOURCE", C.MEDIUM, [hint], [backend])
    violations = b.model().validate()
    assert any("cannot exceed LOW" in v for v in violations)
    assert any("name hints cannot override contrary content evidence" in v for v in violations)

    # `prod/` is not an environment: nothing in the model has an environment field
    for cls in (TerraformConfiguration, DeploymentContext, DesiredResourceInstance):
        assert "environment" not in {f.name for f in dataclasses.fields(cls)}


# --------------------------------------------------------------------------- 13 no promotion across the DIM boundary


def test_probable_root_instance_preserves_role_and_medium_confidence():
    m = messy_model()
    inst = m.get("tf:potato::aws_lambda_function.handler")
    assert inst.context_role is ConfigurationRole.PROBABLE_ROOT
    assert inst.confidence is C.MEDIUM
    # cannot be promoted in place
    with pytest.raises(ValueError, match="PROBABLE_ROOT"):
        dataclasses.replace(inst, confidence=C.HIGH)
    # a relabelled role or a confidence above the context is caught by the model
    relabelled = dataclasses.replace(inst, context_role=ConfigurationRole.CONFIRMED_ROOT)
    bad = dataclasses.replace(m, resource_instances=tuple(relabelled if i.id == inst.id else i for i in m.resource_instances))
    assert any("no promotion" in v for v in bad.validate())
    low_ctx = DeploymentContext("legacy", ConfigurationRole.PROBABLE_ROOT, C.LOW)
    decl = ResourceDeclaration("legacy", DeclarationMode.MANAGED, "aws_vpc", "main")
    assert DesiredResourceInstance.derive(low_ctx, decl).confidence is C.LOW
    # C-min: path confidence can lower, never raise
    assert DesiredResourceInstance.derive(m.get("ctx:root:potato"), decl, path_confidence=C.HIGH).confidence is C.MEDIUM
    assert DesiredResourceInstance.derive(m.get("ctx:root:potato"), decl, path_confidence=C.LOW).confidence is C.LOW


def test_desired_instances_only_from_instantiated_contexts():
    m = messy_model()
    assert {i.context for i in m.desired_instances()} == {"ctx:root:potato"}
    # a context whose root is not instantiated cannot feed DIM
    b_ctx = DeploymentContext("orphan", ConfigurationRole.PROBABLE_ROOT, C.LOW)
    decl = ResourceDeclaration("orphan", DeclarationMode.MANAGED, "aws_vpc", "main")
    bad = dataclasses.replace(
        m,
        configurations=(*m.configurations, TerraformConfiguration("orphan")),
        deployment_contexts=(*m.deployment_contexts, b_ctx),
        resource_declarations=(*m.resource_declarations, decl),
        resource_instances=(*m.resource_instances, DesiredResourceInstance.derive(b_ctx, decl)),
    )
    assert "tf:orphan::aws_vpc.main" not in {i.id for i in bad.desired_instances()}
    assert any("not instantiated" in v for v in bad.validate())


def test_deferred_and_not_applicable_need_reasons_and_carry_nothing():
    with pytest.raises(ValueError, match="requires a reason"):
        InstantiationRecord(InstantiationStatus.DEFERRED)
    with pytest.raises(ValueError, match="cannot carry"):
        InstantiationRecord(InstantiationStatus.NOT_APPLICABLE, InstantiationReason.UNUSED_MODULE_SOURCE, "inf:x:y",
                            contexts=("ctx:root:a",))


def test_lifecycle_discovery_never_implies_instantiation():
    discovered = TerraformConfiguration("modules/x")
    assert discovered.lifecycle.stage is LifecycleStage.DISCOVERED
    assert discovered.classification is None and discovered.lifecycle.instantiation is None
    with pytest.raises(ValueError, match="instantiation record"):
        ConfigurationLifecycle(LifecycleStage.INSTANTIATED)
    with pytest.raises(ValueError, match="classification exists exactly"):
        TerraformConfiguration("a", lifecycle=ConfigurationLifecycle(LifecycleStage.CLASSIFIED))
    assert [s.value for s in LifecycleStage] == ["DISCOVERED", "CLASSIFIED", "INSTANTIATED", "CORRELATED"]


# --------------------------------------------------------------------------- 14 cardinality


def test_unknown_cardinality_stays_unknown():
    decl = ResourceDeclaration("a", DeclarationMode.MANAGED, "aws_lambda_function", "w", MetaArguments(for_each="var.services"))
    assert decl.cardinality.kind is CardinalityKind.UNKNOWN
    assert decl.cardinality.instance_count is None
    assert decl.cardinality.render() == "N = unknown"
    assert decl.cardinality.expression == "for_each = var.services"
    single = Cardinality.single()
    assert Cardinality.combine(single, decl.cardinality).kind is CardinalityKind.UNKNOWN
    assert Cardinality.combine(decl.cardinality, Cardinality(CardinalityKind.STATICALLY_RESOLVABLE, count=3)).instance_count is None
    assert Cardinality.combine(Cardinality(CardinalityKind.STATICALLY_RESOLVABLE, keys=("a", "b")),
                               Cardinality(CardinalityKind.STATICALLY_RESOLVABLE, count=3)).instance_count == 6
    with pytest.raises(ValueError, match="cannot carry a count"):
        Cardinality(CardinalityKind.UNKNOWN, count=1)

    ctx = DeploymentContext("a", ConfigurationRole.CONFIRMED_ROOT, C.HIGH)
    inst = DesiredResourceInstance.derive(ctx, decl)
    assert inst.template and inst.cardinality.kind is CardinalityKind.UNKNOWN and inst.id == "tf:a::aws_lambda_function.w"
    with pytest.raises(ValueError, match="exactly one instance"):
        dataclasses.replace(inst, template=False)

    mi = ModuleInstance("ctx:root:a", "module.w", "call:a::module.w", "modsrc:local:m", expanded_by=("module.w",))
    plain = ResourceDeclaration("m", DeclarationMode.MANAGED, "aws_sqs_queue", "q")
    via = DesiredResourceInstance.derive(ctx, plain, mi)
    assert via.template and via.cardinality.kind is CardinalityKind.UNKNOWN and via.address == "module.w.aws_sqs_queue.q"


def test_dynamic_blocks_do_not_change_cardinality():
    decl = ResourceDeclaration("a", DeclarationMode.MANAGED, "aws_security_group", "sg", MetaArguments(dynamic_blocks=("ingress",)))
    assert decl.cardinality.is_single and not decl.meta.expands


# --------------------------------------------------------------------------- 15 package boundary


_FORBIDDEN = ("flowlens.discover", "flowlens.aws", "flowlens.linking", "flowlens.reachability", "flowlens.models",
              "flowlens.graph", "flowlens.storage", "flowlens.compare", "flowlens.ingest", "flowlens.api", "flowlens.cli",
              "boto3", "botocore")


def _imports(path: Path) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def test_repository_package_has_no_provider_or_pipeline_imports():
    files = sorted(REPO_PKG.glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "model.py", "evidence.py", "ids.py", "redact.py", "enums.py"}
    for f in files:
        for mod in _imports(f):
            assert not mod.startswith(_FORBIDDEN), f"{f.name} imports {mod}"
            # only its own modules; notably not the AWS-normalizing top-level flowlens.ids
            if mod.split(".")[0] == "flowlens":
                assert mod.startswith("flowlens.repository"), f"{f.name} imports {mod}"


def test_importing_repository_package_loads_no_other_flowlens_layers():
    code = (
        "import sys, flowlens.repository\n"
        "bad = sorted(m for m in sys.modules if m.startswith('flowlens.') and not m.startswith('flowlens.repository'))\n"
        "bad += sorted(m for m in sys.modules if m.split('.')[0] in ('boto3', 'botocore'))\n"
        "print(bad); sys.exit(1 if bad else 0)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_production_code_does_not_depend_on_repository_package_yet():
    src = REPO_PKG.parent
    for f in src.rglob("*.py"):
        if REPO_PKG in f.parents:
            continue
        assert not any(m.startswith("flowlens.repository") for m in _imports(f)), f"{f} is wired to RI in Phase 1"


def test_domain_models_have_no_aws_specific_fields():
    import flowlens.repository.evidence as ev_mod
    import flowlens.repository.model as model_mod

    for mod in (model_mod, ev_mod):
        for obj in vars(mod).values():
            if isinstance(obj, type) and dataclasses.is_dataclass(obj) and obj.__module__ == mod.__name__:
                for f in dataclasses.fields(obj):
                    assert not re.search(r"(^|_)(aws|arn|account|region|vpc)(_|$)", f.name), f"{obj.__name__}.{f.name}"


# --------------------------------------------------------------------------- 16 redaction

_GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def test_sensitive_values_do_not_leak_through_repr_or_json():
    b = Builder()
    fact = b.fact("envs/prod/main.tf", FactKind.LITERAL_ATTRIBUTE, "provider", ("github",), (1, 2),
                  token=_GH, function_name="payments-api", note=_AWS_KEY, password="hunter2")
    assert fact.payload_dict() == {"function_name": "payments-api", "note": "<redacted>", "password": "<redacted>", "token": "<redacted>"}
    ev = b.evidence(ProvenanceKind.OBSERVED, "cfg.literal", "cfg:envs/prod", [fact], C.CERTAIN,
                    detail=f"token={_GH} source https://bob:s3cr3tpw@git.example.com/r.git?ref=v1&access_token=zz9 "
                           "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")
    diag = b.add("diagnostics", Diagnostic("RI-X", Severity.INFO, "cfg:envs/prod", f"saw {_AWS_KEY} in a literal"))
    src = b.add("module_sources", ModuleSource(ModuleSourceKind.GIT, "git::https://bob:s3cr3tpw@git.example.com/r.git//mod?ref=v1&token=zz9",
                                               raw_source="git::https://bob:s3cr3tpw@git.example.com/r.git//mod?ref=v1&token=zz9"))
    backend = b.add("configurations", TerraformConfiguration("envs/prod"))
    be = b.add("backend_evidence", BackendEvidence("envs/prod", BackendKind.BACKEND, "s3",
                                                   {"bucket": "tf-state", "key": "prod.tfstate", "access_key": _AWS_KEY,
                                                    "secret_key": "abc", "token": "zz9", "encrypt": True}))
    meta = MetaArguments(for_each=f'{{ k = "{_GH}" }}')
    model = b.model()
    blob = model.to_json() + repr(model) + repr(ev) + repr(fact) + repr(diag) + repr(src) + repr(be) + repr(meta) + repr(backend)
    for secret in (_GH, _AWS_KEY, "hunter2", "s3cr3tpw", "zz9", "MIIabc", "bob:"):
        assert secret not in blob, secret
    assert src.id == "modsrc:git:git::https://git.example.com/r.git//mod"
    assert src.raw_source == "git::https://***@git.example.com/r.git//mod?ref=v1&token=***"
    assert dict(be.attributes) == {"access_key": "<redacted>", "bucket": "tf-state", "encrypt": "true", "key": "prod.tfstate",
                                   "secret_key": "<redacted>", "token": "<redacted>"}
    assert be.keys_present == ("access_key", "bucket", "encrypt", "key", "secret_key", "token")


def test_redaction_helpers():
    assert redact.redact_url("https://user:tok@host/x") == "https://***@host/x"
    assert redact.redact_url("https://host/x?access_token=abc&ref=v2") == "https://host/x?access_token=***&ref=v2"
    assert redact.redact_url("git@github.com:org/repo.git") == "git@github.com:org/repo.git"
    assert redact.looks_secret("-----BEGIN OPENSSH PRIVATE KEY-----") == "PEM block"
    assert redact.looks_secret(_AWS_KEY)
    assert redact.looks_secret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc")
    assert redact.looks_secret("Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1O")
    for benign in ("aws_lambda_function.this.arn", "var.services", "modules/network", "arn:aws:lambda:eu-west-1:111122223333:function:x",
                   "data.aws_iam_policy_document.lambda_assume_role.json",
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                   "payments-api", "10.0.0.0/16"):
        assert redact.looks_secret(benign) is None, benign
    assert redact.redact_attribute("db_password", "x") == ("<redacted>", "sensitive attribute name")
    assert redact.guard_value("plain") == ("plain", None)


# --------------------------------------------------------------------------- 17 inventory survives deferral


def test_full_declaration_inventory_survives_deferred_instantiation():
    inv = messy_model().declaration_inventory()
    assert inv.total_declarations == 6  # potato 2 + stuff/a 3 + stuff/b 1
    assert len(inv.not_instantiated_declarations) == 4
    deferred = inv.configurations_with_status(InstantiationStatus.DEFERRED)
    ambiguous = [e for e in deferred if e.reason is InstantiationReason.AMBIGUOUS_ROLE]
    assert len(ambiguous) == 2 and sum(len(e.not_instantiated) for e in ambiguous) == 4
    assert ("2 configurations deferred (AMBIGUOUS_ROLE) — 4 resource declarations not instantiated: "
            "stuff/a (3 aws_lambda_function), stuff/b (1 aws_lambda_function)") in inv.summary()
    # discovered-only configurations are still listed
    assert any(e.path == "modules/lambda-tpl" and e.stage is LifecycleStage.DISCOVERED for e in inv.entries)


def test_dual_role_inventory_counts_one_declaration_two_instances():
    m = dual_role_model()
    inv = m.declaration_inventory()
    assert inv.not_instantiated_declarations == ()
    vpc = [i for i in m.resource_instances if i.declaration == "decl:shared-network::managed.aws_vpc.main"]
    assert len(vpc) == 2 and len({i.context for i in vpc}) == 2


# --------------------------------------------------------------------------- environment vs deployment context


def test_var_files_are_candidates_and_do_not_change_context_identity():
    plain = DeploymentContext("envs/app", ConfigurationRole.CONFIRMED_ROOT, C.HIGH)
    with_vars = DeploymentContext("envs/app", ConfigurationRole.CONFIRMED_ROOT, C.HIGH,
                                  var_files=("varfile:envs/app/prod.tfvars", "varfile:envs/app/staging.tfvars"))
    assert plain.id == with_vars.id == "ctx:root:envs/app"
    prod = VarFileArtifact("envs/app/prod.tfvars")
    assert prod.kind is VarFileKind.NAMED_TFVARS and not prod.autoloaded and prod.configuration == "cfg:envs/app"
    assert VarFileArtifact("envs/app/terraform.tfvars").autoloaded
    assert VarFileArtifact("envs/app/x.auto.tfvars.json").autoloaded


def test_raw_artifact_and_fact_are_syntactic():
    art = RawArtifact("envs/prod/terraform.tfvars", sha256="0" * 64)
    assert art.id == "art:envs/prod/terraform.tfvars" and art.kind is ArtifactKind.TFVARS
    f = ObservedFact(art.id, Locator(), FactKind.ARTIFACT_PRESENT)
    assert f.id.startswith("fact:") and f.id == ObservedFact(art.id, Locator(), FactKind.ARTIFACT_PRESENT).id
    assert "role" not in {x.name for x in dataclasses.fields(ObservedFact)}


# --------------------------------------------------------------------------- migration contract (documented, not executed)


def test_migration_contract_legacy_predicate():
    legacy = legacy_ids.make_tf_only_node_id("module.nlb.aws_lb.this")
    assert migration.is_legacy_terraform_node_id(legacy)
    assert migration.is_legacy_terraform_node_id("tf:aws_vpc.main")
    new = ri_ids.desired_instance_id(ri_ids.context_id("apps/sentry"), "module.nlb.aws_lb.this")
    assert not migration.is_legacy_terraform_node_id(new)
    # cloud-id nodes (incl. state-derived nodes merged with AWS) are untouched
    for cloud in (legacy_ids.make_node_id("vpc", "vpc-0abc"), "nlb:arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/net/x/y",
                  "lambda:payments-api"):
        assert not migration.is_legacy_terraform_node_id(cloud)
    assert migration.IDENTITY_SCHEME_META_KEY == "terraform_identity_scheme" and migration.CURRENT_IDENTITY_SCHEME == "2"
    assert migration.migration_required(None, [legacy, "vpc:vpc-1"])
    assert not migration.migration_required("2", [legacy])
    assert not migration.migration_required(None, ["vpc:vpc-1", new])
    # separate version axes
    assert CURRENT_REPOSITORY_MODEL_VERSION == 1


def test_migration_module_is_contract_only():
    assert _imports(REPO_PKG / "migration.py") <= {"__future__"}


def test_model_json_has_no_absolute_paths_and_validate_catches_them():
    m = dual_role_model()
    assert m.validate() == ()
    sneaky = dataclasses.replace(m, diagnostics=(Diagnostic("RI-X", Severity.INFO, "/home/alice/project", "x"),))
    assert any("absolute path" in v for v in sneaky.validate())


def test_redacted_evidence_detail_still_explains():
    b = Builder()
    f = b.fact("a/main.tf", FactKind.BACKEND_BLOCK, "terraform", ("backend", "remote"), (1, 5))
    e = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_backend", "cfg:a", [f], C.CERTAIN, detail=f"remote backend token {_GH}")
    b.inference("ROLE-U1", "cfg:a", "role=CONFIRMED_ROOT", C.HIGH, [e])
    text = explain(b.model(), "cfg:a")
    assert "remote backend token <redacted>" in text and _GH not in text


def test_declaration_and_module_call_ids():
    d = declare(Builder(), "modules/nlb", "aws_lb", "this", "main.tf")
    assert d.id == "decl:modules/nlb::managed.aws_lb.this" and d.address == "aws_lb.this"
    data = ResourceDeclaration("envs/prod", DeclarationMode.DATA, "aws_region", "current")
    assert data.id == "decl:envs/prod::data.aws_region.current" and data.address == "data.aws_region.current"
    assert d.provider_type == "aws_lb"  # raw Terraform type; never normalized in RI
