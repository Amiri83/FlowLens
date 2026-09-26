"""Phase 2: Terraform structural repository reconnaissance (path -> RepositoryModel).

Fixtures A-H live in tests/fixtures/recon/ (see tests/recon_fixtures.py).
Classification must follow the approved rule table (proposal §19): the
assertions name exact roles, confidences, rule ids, evidence claims and ids.
"""
from __future__ import annotations

import os
import socket

import pytest

from flowlens.repository import (
    AmbiguityKind,
    ArtifactKind,
    CardinalityKind,
    ConfigurationRole,
    DeploymentContext,
    Evidence,
    EvidenceBasis,
    FactKind,
    LifecycleStage,
    ModuleSourceKind,
    ObservedFact,
    ParseStatus,
    ProvenanceKind,
    ReadStatus,
    build_repository_model,
    explain,
    independent,
    summarize,
)
from flowlens.repository import __main__ as recon_cli
from flowlens.repository.hcl import block_facts, parse_terraform
from recon_fixtures import (
    FIXTURE_NAMES,
    C,
    R,
    S,
    Why,
    build_fixture,
    cfg,
    desired_ids,
    materialize,
    outcome,
    rule,
    signals,
    write_tree,
)

# --------------------------------------------------------------------------- every fixture


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_every_fixture_builds_a_valid_conserving_model(name, tmp_path):
    model = build_fixture(name, tmp_path)
    model.assert_valid()
    # A3 conservation: every discovered configuration is classified exactly once.
    assert sum(model.role_counts().values()) == len(model.configurations)
    assert "UNCLASSIFIED" not in model.role_counts()
    for c in model.configurations:
        assert c.lifecycle.stage is LifecycleStage.INSTANTIATED
        assert c.lifecycle.instantiation is not None
        inf = model.get(c.classification.inference)
        assert inf is not None and inf.subject == c.id and inf.rule_id.startswith("ROLE-")


# --------------------------------------------------------------------------- discovery & grouping


def test_discovery_is_recursive_and_skips_dot_terraform_internals(tmp_path):
    model = build_fixture("f_messy", tmp_path)
    assert [c.path for c in model.configurations] == [
        "infra/live", "lib/app-stack", "lib/app-stack/db", "lib/cycle-a", "lib/cycle-b", "old/unused-tf", "scratch",
    ]
    arts = {a.id: a for a in model.artifacts}
    dot = arts["art:infra/live/.terraform"]
    assert dot.kind is ArtifactKind.DOT_TERRAFORM_DIR and dot.read_status is ReadStatus.SKIPPED_BY_POLICY
    # the downloaded module copy inside .terraform/ is never scanned
    assert not any(a.startswith("art:infra/live/.terraform/") for a in arts)
    assert not any("downloaded_copy_never_scanned" in d.id for d in model.resource_declarations)
    # Terragrunt and override files are recorded (syntactic kinds), not interpreted as declarations
    assert arts["art:infra/live/terragrunt.hcl"].kind is ArtifactKind.TERRAGRUNT_HCL
    assert arts["art:infra/live/override.tf"].kind is ArtifactKind.TF_OVERRIDE
    assert [c.id for c in model.module_calls if c.caller_path == "infra/live"] == [
        "call:infra/live::module.app", "call:infra/live::module.missing",
    ]
    assert all(a.sha256 for a in model.artifacts if a.kind in (ArtifactKind.TF_HCL, ArtifactKind.TF_OVERRIDE))


def test_directory_level_grouping_with_arbitrary_filenames(tmp_path):
    model = build_fixture("b_arbitrary", tmp_path)
    potato, banana = cfg(model, "potato"), cfg(model, "banana")
    assert [f.artifact for f in potato.files] == ["art:potato/stuff.tf", "art:potato/zzz.tf"]
    assert [f.artifact for f in banana.files] == ["art:banana/knobs.tf.json", "art:banana/lambda.tf"]
    # filenames are provenance only: identity is the directory
    assert potato.id == "cfg:potato" and banana.id == "cfg:banana"
    # the backend in zzz.tf and the provider in stuff.tf belong to one configuration
    assert potato.block_summary.get("terraform") == 1 and potato.block_summary.get("provider") == 1
    # .tf.json variables are merged with the .tf file of the same directory
    assert banana.block_summary.get("variable") == 2 and banana.block_summary.get("resource") == 2


def test_arbitrary_directory_names_classify_like_conventional_ones(tmp_path):
    """Fixture B is fixture A's content under arbitrary names: identical outcomes."""
    a, b = build_fixture("a_clean", tmp_path), build_fixture("b_arbitrary", tmp_path)
    assert outcome(a, "root") == outcome(b, "potato") == (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1", S.RESOLVED_ROOT, None)
    assert outcome(a, "modules/network") == outcome(b, "banana") == (R.MODULE_SOURCE, C.HIGH, "ROLE-C3", S.RESOLVED_INSTANCES, None)
    strip = lambda ids_, root: {i.split("::", 1)[1] for i in ids_ if i.startswith(f"tf:{root}::")}  # noqa: E731
    assert strip(desired_ids(a), "root") == strip(desired_ids(b), "potato") == {
        "aws_lambda_function.api", "module.network.aws_vpc.main", "module.network.aws_subnet.private",
    }


def test_weak_path_hints_never_decide(tmp_path):
    a, b = build_fixture("a_clean", tmp_path), build_fixture("b_arbitrary", tmp_path)
    # the only difference the `modules/` name makes is one LOW, INFERRED, NAME_HINT evidence item
    sa, sb = signals(a, "modules/network"), signals(b, "banana")
    assert sa.pop("M-HINT") is C.LOW and sa == sb
    hint = next(e for e in a.evidence if e.claim == "M-HINT")
    assert hint.basis is EvidenceBasis.NAME_HINT and hint.kind is ProvenanceKind.INFERRED

    # identical content under a module-ish and an arbitrary name -> identical classification
    provider_only = 'provider "aws" {\n  region = "us-east-1"\n}\n\nresource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'
    reqvar_only = 'variable "name" {}\n\nresource "aws_sqs_queue" "q" {\n  name = var.name\n}\n'
    model = build_repository_model(write_tree(tmp_path / "hints", {
        "modules/app/main.tf": provider_only, "potato/main.tf": provider_only,
        "modules/lib/main.tf": reqvar_only, "envs/prod/main.tf": reqvar_only,
    }))
    assert outcome(model, "modules/app") == outcome(model, "potato") == (R.PROBABLE_ROOT, C.MEDIUM, "ROLE-U2", S.RESOLVED_ROOT, None)
    assert outcome(model, "modules/lib") == outcome(model, "envs/prod") == (
        R.MODULE_SOURCE, C.MEDIUM, "ROLE-U4", S.NOT_APPLICABLE, Why.UNUSED_MODULE_SOURCE)
    assert "M-HINT" in signals(model, "modules/app") and "M-HINT" not in signals(model, "potato")
    # `prod` in a path is not environment evidence: envs/prod gets no context
    assert "ctx:root:envs/prod" not in {c.id for c in model.deployment_contexts}
    model.assert_valid()


# --------------------------------------------------------------------------- module sources


def test_local_module_resolution_is_relative_to_the_caller(tmp_path):
    model = build_fixture("a_clean", tmp_path)
    (call,) = model.module_calls
    assert call.id == "call:root::module.network"
    assert call.source == "modsrc:local:modules/network"
    assert call.inputs == ("cidr",)  # input names only
    src = model.get(call.source)
    assert src.kind is ModuleSourceKind.LOCAL and src.configuration == "cfg:modules/network" and src.resolved
    ev = model.get(call.evidence)
    assert ev.kind is ProvenanceKind.STRUCTURAL and ev.claim == "call.resolves_to" and ev.strength is C.CERTAIN
    assert "resolves to modules/network" in ev.detail


def test_unresolvable_local_source_stays_a_declaration(tmp_path):
    model = build_fixture("f_messy", tmp_path)
    call = model.get("call:infra/live::module.missing")
    src = model.get(call.source)
    assert src.id == "modsrc:local:lib/does-not-exist" and not src.resolved and src.configuration is None
    assert model.get("ctx:root:infra/live::module.missing") is None
    codes = {(d.code, d.subject) for d in model.diagnostics}
    assert ("RI-SOURCE-UNREADABLE", "call:infra/live::module.missing") in codes
    assert ("RI-INSTANCE-DEFERRED", "call:infra/live::module.missing") in codes


def test_nested_local_modules(tmp_path):
    model = build_fixture("f_messy", tmp_path)
    assert outcome(model, "lib/app-stack/db") == (R.MODULE_SOURCE, C.HIGH, "ROLE-C3", S.RESOLVED_INSTANCES, None)
    mi = model.get("ctx:root:infra/live::module.app.module.db")
    assert mi.call == "call:lib/app-stack::module.db" and mi.source_configuration == "cfg:lib/app-stack/db"
    assert cfg(model, "lib/app-stack/db").lifecycle.instantiation.instances == ("ctx:root:infra/live::module.app.module.db",)
    assert "tf:infra/live::module.app.module.db.aws_db_instance.main" in desired_ids(model)


def test_shared_module_across_roots_yields_distinct_instances(tmp_path):
    model = build_fixture("c_multi_root", tmp_path)
    assert outcome(model, "app-a") == outcome(model, "app-b") == (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1", S.RESOLVED_ROOT, None)
    assert outcome(model, "shared") == (R.MODULE_SOURCE, C.HIGH, "ROLE-C3", S.RESOLVED_INSTANCES, None)
    assert [s.id for s in model.module_sources if s.kind is ModuleSourceKind.LOCAL] == ["modsrc:local:shared"]
    assert cfg(model, "shared").lifecycle.instantiation.instances == ("ctx:root:app-a::module.svc", "ctx:root:app-b::module.svc")
    assert desired_ids(model) == {
        "tf:app-a::aws_s3_bucket.logs", "tf:app-a::module.svc.aws_lb.this",
        "tf:app-b::aws_s3_bucket.logs", "tf:app-b::module.svc.aws_lb.this",
    }
    # both module.svc instances share one declaration; no duplicate diagnostics
    decls = {i.declaration for i in model.desired_instances() if "module.svc" in i.id}
    assert decls == {"decl:shared::managed.aws_lb.this"}
    assert not any("DUPLICATE" in d.code for d in model.diagnostics)


def test_remote_sources_are_recorded_not_fetched_and_redacted(tmp_path, monkeypatch):
    dest = materialize("c_multi_root", tmp_path / "c")

    def no_network(*_a, **_k):
        raise AssertionError("reconnaissance must never touch the network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    model = build_repository_model(dest)

    reg = model.get("modsrc:registry:registry.terraform.io/terraform-aws-modules/vpc/aws")
    assert reg.kind is ModuleSourceKind.REGISTRY and reg.configuration is None and reg.version_constraint == "~> 5.0"
    git = model.get("modsrc:git:git::https://git.example.com/org/tf-modules.git//lb")
    assert git.kind is ModuleSourceKind.GIT and git.ref == "v1.2.0" and git.configuration is None
    assert git.raw_source == "git::https://***@git.example.com/org/tf-modules.git//lb?ref=v1.2.0"
    # instances exist, contents UNKNOWN: no source configuration, no desired resources beneath them
    for mp in ("module.vpc", "module.private_lib"):
        assert model.get(f"ctx:root:app-a::{mp}").source_configuration is None
        assert not any(i.startswith(f"tf:app-a::{mp}.") for i in desired_ids(model))
    fetched = {d.subject for d in model.diagnostics if d.code == "RI-SOURCE-NOT-FETCHED"}
    assert fetched == {"call:app-a::module.vpc", "call:app-a::module.private_lib"}
    dump = model.to_json()
    assert "s3cr3t" not in dump and "deploy:" not in dump


# --------------------------------------------------------------------------- cycles


def test_cycle_only_configurations_are_ambiguous_and_never_recurse(tmp_path):
    model = build_fixture("f_messy", tmp_path)
    for path in ("lib/cycle-a", "lib/cycle-b"):
        assert outcome(model, path) == (R.AMBIGUOUS, C.LOW, "ROLE-X1", S.DEFERRED, Why.CYCLE_ONLY)
    amb = {a.subject: a for a in model.ambiguities}
    assert amb["cfg:lib/cycle-a"].kind is AmbiguityKind.CYCLE_ONLY
    cycle = [d for d in model.diagnostics if d.code == "RI-MODULE-CYCLE"]
    assert len(cycle) == 1 and cycle[0].message == "local module cycle: lib/cycle-a -> lib/cycle-b -> lib/cycle-a"
    assert not any("cycle" in i for i in desired_ids(model))
    # declarations are kept
    assert {"decl:lib/cycle-a::managed.aws_sqs_queue.a", "decl:lib/cycle-b::managed.aws_sqs_queue.b"} <= {
        d.id for d in model.resource_declarations}


def test_cycle_entered_from_an_instantiated_root_is_cut_once(tmp_path):
    model = build_repository_model(write_tree(tmp_path / "r", {
        "live/main.tf": 'terraform {\n  backend "s3" {}\n}\n\nmodule "x" {\n  source = "../c1"\n}\n',
        "c1/main.tf": 'module "y" {\n  source = "../c2"\n}\n\nresource "aws_sqs_queue" "one" {\n  name = "1"\n}\n',
        "c2/main.tf": 'module "z" {\n  source = "../c1"\n}\n\nresource "aws_sqs_queue" "two" {\n  name = "2"\n}\n',
    }))
    model.assert_valid()
    assert rule(model, "c1") == rule(model, "c2") == "ROLE-C3"
    assert {m.id for m in model.module_instances} == {"ctx:root:live::module.x", "ctx:root:live::module.x.module.y"}
    assert desired_ids(model) == {"tf:live::module.x.aws_sqs_queue.one", "tf:live::module.x.module.y.aws_sqs_queue.two"}
    assert [d.subject for d in model.diagnostics if d.code == "RI-MODULE-CYCLE-CUT"] == ["call:c2::module.z"]


# --------------------------------------------------------------------------- partial failure


def test_malformed_file_is_skipped_and_neighbours_are_kept(tmp_path):
    model = build_fixture("f_messy", tmp_path)
    scratch = cfg(model, "scratch")
    assert scratch.parse_status is ParseStatus.PARTIAL
    assert {(f.artifact, f.parse_status) for f in scratch.files} == {
        ("art:scratch/good.tf", ParseStatus.COMPLETE), ("art:scratch/notes.tf", ParseStatus.FAILED)}
    # the valid neighbour still yields its declaration and variable facts
    assert "decl:scratch::managed.aws_s3_bucket.scratch" in {d.id for d in model.resource_declarations}
    # ROLE-U4 under C-partial: the unparsed file might hold a backend, so not "unused module" but AMBIGUOUS
    assert outcome(model, "scratch") == (R.AMBIGUOUS, C.MEDIUM, "ROLE-U4", S.DEFERRED, Why.AMBIGUOUS_ROLE)
    err = next(f for f in model.facts if f.kind is FactKind.PARSE_ERROR and f.artifact == "art:scratch/notes.tf")
    assert err.locator.line_start == 2
    diag = next(d for d in model.diagnostics if d.code == "RI-PARSE-FAILED" and d.subject == "cfg:scratch")
    assert diag.message.startswith("scratch/notes.tf (line 2): failed to parse, skipped")
    # the rest of the repository is unaffected
    assert outcome(model, "infra/live")[:3] == (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1")


def test_configuration_whose_files_all_fail_is_unknown_not_dropped(tmp_path):
    model = build_fixture("e_ambiguous", tmp_path)
    broken = cfg(model, "broken")
    assert broken.parse_status is ParseStatus.FAILED
    assert outcome(model, "broken") == (R.UNKNOWN, C.UNKNOWN, "ROLE-P1", S.DEFERRED, Why.PARSE_FAILED)
    assert {d.code for d in model.diagnostics if d.subject == "cfg:broken"} == {
        "RI-PARSE-FAILED", "RI-UNKNOWN-CLASSIFICATION", "RI-INSTANTIATION-DEFERRED"}


# --------------------------------------------------------------------------- the rule table, role by role


@pytest.mark.parametrize(("fixture", "path", "expected"), [
    ("a_clean", "root", (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1", S.RESOLVED_ROOT, None)),
    ("b_arbitrary", "random-stuff", (R.PROBABLE_ROOT, C.MEDIUM, "ROLE-U2", S.RESOLVED_ROOT, None)),
    ("e_ambiguous", "lonely", (R.PROBABLE_ROOT, C.LOW, "ROLE-U5", S.RESOLVED_ROOT, None)),
    ("e_ambiguous", "stuff/unused", (R.AMBIGUOUS, C.MEDIUM, "ROLE-U3", S.DEFERRED, Why.AMBIGUOUS_ROLE)),
    ("g_overcount", "old-stuff", (R.MODULE_SOURCE, C.MEDIUM, "ROLE-U4", S.NOT_APPLICABLE, Why.UNUSED_MODULE_SOURCE)),
    ("g_overcount", "modules/helper", (R.AMBIGUOUS, C.LOW, "ROLE-X2", S.DEFERRED, Why.CALLER_DEFERRED)),
    ("f_messy", "lib/cycle-a", (R.AMBIGUOUS, C.LOW, "ROLE-X1", S.DEFERRED, Why.CYCLE_ONLY)),
    ("a_clean", "modules/network", (R.MODULE_SOURCE, C.HIGH, "ROLE-C3", S.RESOLVED_INSTANCES, None)),
    ("d_dual_role", "shared-network", (R.DUAL_ROLE, C.HIGH, "ROLE-C1", S.RESOLVED_BOTH, None)),
    ("d_dual_role", "shared-queue", (R.MODULE_SOURCE, C.HIGH, "ROLE-C2", S.RESOLVED_INSTANCES, Why.ROOT_ROLE_WEAK)),
    ("d_dual_role", "shared-dns", (R.MODULE_SOURCE, C.HIGH, "ROLE-C3", S.RESOLVED_INSTANCES, Why.ROOT_ROLE_WEAK)),
    ("e_ambiguous", "broken", (R.UNKNOWN, C.UNKNOWN, "ROLE-P1", S.DEFERRED, Why.PARSE_FAILED)),
])
def test_rule_table_outcomes(fixture, path, expected, tmp_path):
    assert outcome(build_fixture(fixture, tmp_path), path) == expected


def test_signal_strengths_follow_the_approved_table(tmp_path):
    a = build_fixture("a_clean", tmp_path)
    assert signals(a, "root") == {
        "R-BACKEND": C.HIGH, "R-TFVARS": C.MEDIUM, "R-LOCK": C.MEDIUM, "R-PROVIDER": C.MEDIUM,
        "R-UNCALLED": C.LOW, "R-DEFAULTS": C.LOW,
    }
    assert signals(a, "modules/network") == {"M-CALLED": C.CERTAIN, "M-REQVAR": C.MEDIUM, "M-NOPROV": C.LOW, "M-HINT": C.LOW}
    d = build_fixture("d_dual_role", tmp_path)
    # R-PROVIDER is medium when uncalled (above) but weak when called
    assert signals(d, "shared-dns") == {"M-CALLED": C.CERTAIN, "R-PROVIDER": C.LOW}
    f = build_fixture("f_messy", tmp_path)
    assert signals(f, "infra/live")["R-DOTTF"] is C.MEDIUM
    g = build_fixture("g_overcount", tmp_path)
    assert signals(g, "modules/helper")["M-DEFERRED-CALLER"] is C.LOW
    s = build_repository_model(write_tree(tmp_path / "st", {"x/main.tf": 'resource "aws_sqs_queue" "q" {}\n',
                                                              "x/terraform.tfstate": "{}"}))
    assert signals(s, "x")["R-STATE"] is C.HIGH and outcome(s, "x")[:3] == (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1")
    # R-CI is Phase 3: never emitted, and its absence is not negative evidence
    assert not any(e.claim == "R-CI" for m in (a, d, f, g, s) for e in m.evidence)


def test_independent_corroboration(tmp_path):
    tf_provider = 'provider "aws" {\n  region = "us-east-1"\n}\n\nresource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'
    model = build_repository_model(write_tree(tmp_path / "corr", {
        # provider (.tf) + terraform.tfvars: two independent medium signals -> strong root
        "two/main.tf": tf_provider, "two/terraform.tfvars": 'x = "1"\n',
        # two provider blocks in two files: one signal kind (R-PROVIDER), not corroboration
        "same/a.tf": tf_provider, "same/b.tf": 'provider "google" {\n  project = "p"\n}\n',
        # two autoloaded var files: still one R-TFVARS signal
        "vars/main.tf": 'resource "aws_sqs_queue" "q" {}\n', "vars/terraform.tfvars": 'x = "1"\n', "vars/a.auto.tfvars": 'y = "2"\n',
        # lock file + .terraform/: different artifacts, different claims -> independent
        "init/main.tf": 'resource "aws_sqs_queue" "q" {}\n', "init/.terraform.lock.hcl": "", "init/.terraform/": "",
    }))
    assert outcome(model, "two")[:3] == (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1")
    assert outcome(model, "same")[:3] == (R.PROBABLE_ROOT, C.MEDIUM, "ROLE-U2")
    assert outcome(model, "vars")[:3] == (R.PROBABLE_ROOT, C.MEDIUM, "ROLE-U2")
    assert outcome(model, "init")[:3] == (R.CONFIRMED_ROOT, C.HIGH, "ROLE-U1")

    facts = {f.id: f for f in model.facts}
    by = lambda path, claim: next(e for e in model.evidence if e.subject == f"cfg:{path}" and e.claim == claim)  # noqa: E731
    prov_same = by("same", "R-PROVIDER")
    assert {facts[f].artifact for f in prov_same.facts} == {"art:same/a.tf", "art:same/b.tf"}
    assert independent(by("two", "R-PROVIDER"), by("two", "R-TFVARS"), facts)
    assert independent(by("init", "R-LOCK"), by("init", "R-DOTTF"), facts)
    assert not independent(prov_same, prov_same, facts)
    # two readings of the same HCL construct are never independent, whatever their claims
    fact = facts[next(iter(by("two", "R-PROVIDER").facts))]
    e1 = Evidence(ProvenanceKind.OBSERVED, "claim.one", "cfg:two", (fact.id,), C.MEDIUM)
    e2 = Evidence(ProvenanceKind.OBSERVED, "claim.two", "cfg:two", (fact.id,), C.MEDIUM)
    assert not independent(e1, e2, facts)


def test_probable_root_is_never_promoted(tmp_path):
    model = build_repository_model(write_tree(tmp_path / "p", {
        # ROLE-U2 (one medium signal) calling a module
        "svc/main.tf": 'provider "aws" {\n  region = "us-east-1"\n}\n\nmodule "m" {\n  source = "../lib"\n}\n'
                       'resource "aws_sqs_queue" "q" {}\n',
        # ROLE-U5 (nothing >= medium) calling the same module
        "bare/main.tf": 'module "m" {\n  source = "../lib"\n}\n',
        "lib/main.tf": 'resource "aws_sns_topic" "t" {}\n',
    }))
    model.assert_valid()
    assert outcome(model, "svc")[:3] == (R.PROBABLE_ROOT, C.MEDIUM, "ROLE-U2")
    assert outcome(model, "bare")[:3] == (R.PROBABLE_ROOT, C.LOW, "ROLE-U5")
    # C3: a caller below MEDIUM -> the module role takes the minimum
    assert outcome(model, "lib")[:3] == (R.MODULE_SOURCE, C.LOW, "ROLE-C3")
    by_id = {i.id: i for i in model.desired_instances()}
    assert {(i, by_id[i].context_role, by_id[i].confidence) for i in by_id} == {
        ("tf:svc::aws_sqs_queue.q", R.PROBABLE_ROOT, C.MEDIUM),
        ("tf:svc::module.m.aws_sns_topic.t", R.PROBABLE_ROOT, C.MEDIUM),
        ("tf:bare::module.m.aws_sns_topic.t", R.PROBABLE_ROOT, C.LOW),
    }
    ctx = model.get("ctx:root:svc")
    assert isinstance(ctx, DeploymentContext) and (ctx.role, ctx.confidence) == (R.PROBABLE_ROOT, C.MEDIUM)


# --------------------------------------------------------------------------- DUAL_ROLE


def test_dual_role_has_separate_root_and_module_contexts(tmp_path):
    model = build_fixture("d_dual_role", tmp_path)
    sn = cfg(model, "shared-network")
    cl = sn.classification
    assert (cl.root_role.status.value, cl.root_role.confidence) == ("yes", C.HIGH)
    assert (cl.module_role.status.value, cl.module_role.confidence) == ("yes", C.CERTAIN)
    rec = sn.lifecycle.instantiation
    assert rec.contexts == ("ctx:root:shared-network",)
    assert rec.instances == ("ctx:root:application::module.network",)
    assert model.get("ctx:root:shared-network").basis == "dual_role_root"
    root_dep = model.get("tf:shared-network::aws_vpc.main")
    as_module = model.get("tf:application::module.network.aws_vpc.main")
    # one declaration, two desired instances in two deployment contexts
    assert root_dep.declaration == as_module.declaration == "decl:shared-network::managed.aws_vpc.main"
    assert (root_dep.context, root_dep.context_role) == ("ctx:root:shared-network", R.DUAL_ROLE)
    assert (as_module.context, as_module.context_role) == ("ctx:root:application", R.CONFIRMED_ROOT)
    assert {e.claim for e in model.evidence if e.subject == "cfg:shared-network"} >= {"R-BACKEND", "R-TFVARS", "M-CALLED"}


def test_dual_role_from_two_independent_medium_signals(tmp_path):
    """Strong root evidence without a backend: autoloaded tfvars + lock file (two artifacts, two claims)."""
    model = build_repository_model(write_tree(tmp_path / "dr", {
        "app/main.tf": 'terraform {\n  backend "s3" {}\n}\n\nmodule "net" {\n  source = "../net"\n}\n',
        "net/main.tf": 'resource "aws_vpc" "v" {}\n',
        "net/terraform.tfvars": 'x = "1"\n',
        "net/.terraform.lock.hcl": "",
    }))
    model.assert_valid()
    assert outcome(model, "net") == (R.DUAL_ROLE, C.HIGH, "ROLE-C1", S.RESOLVED_BOTH, None)
    assert signals(model, "net") == {"M-CALLED": C.CERTAIN, "R-TFVARS": C.MEDIUM, "R-LOCK": C.MEDIUM, "M-NOPROV": C.LOW}
    assert desired_ids(model) == {"tf:net::aws_vpc.v", "tf:app::module.net.aws_vpc.v"}


def test_weak_root_evidence_on_a_called_configuration_is_a_candidate_only(tmp_path):
    model = build_fixture("d_dual_role", tmp_path)
    for path in ("shared-dns", "shared-queue"):
        c = cfg(model, path)
        assert (c.classification.root_role.status.value, c.classification.root_role.confidence) == ("candidate", C.LOW)
        assert c.lifecycle.instantiation.contexts == ()  # no phantom root context
        assert model.get(f"ctx:root:{path}") is None
        inf = model.get(c.classification.inference)
        assert [(a.conclusion, a.confidence) for a in inf.alternatives] == [("role=DUAL_ROLE", C.LOW)]
    assert {d.subject for d in model.diagnostics if d.code == "RI-INSTANTIATION-DEFERRED"} == {"cfg:shared-dns", "cfg:shared-queue"}
    assert not any(i.startswith(("tf:shared-dns::", "tf:shared-queue::")) for i in desired_ids(model))


# --------------------------------------------------------------------------- ambiguity & disconnected configurations


def test_ambiguity_is_preserved_not_dropped(tmp_path):
    model = build_fixture("e_ambiguous", tmp_path)
    assert model.role_counts() == {"AMBIGUOUS": 1, "PROBABLE_ROOT": 2, "UNKNOWN": 1}
    (amb,) = model.ambiguities
    assert amb.subject == "cfg:stuff/unused" and amb.kind is AmbiguityKind.ROLE
    assert {(a.conclusion, a.confidence) for a in amb.alternatives} == {
        ("role=PROBABLE_ROOT", C.MEDIUM), ("role=MODULE_SOURCE (unused)", C.MEDIUM)}
    assert "backend or cloud block" in amb.resolution_hints
    # declarations of the deferred configuration stay in the model, but produce no desired instance
    assert "decl:stuff/unused::managed.aws_lambda_function.this" in {d.id for d in model.resource_declarations}
    assert not any(i.startswith("tf:stuff/unused::") for i in desired_ids(model))
    assert signals(model, "stuff/unused") == {"R-PROVIDER": C.MEDIUM, "R-UNCALLED": C.LOW, "M-REQVAR": C.MEDIUM}


def test_disconnected_configurations_are_classified_on_their_own_evidence(tmp_path):
    model = build_fixture("e_ambiguous", tmp_path)
    assert not model.module_calls
    assert outcome(model, "lonely")[:3] == (R.PROBABLE_ROOT, C.LOW, "ROLE-U5")
    # a configuration with no declarations (variables/outputs only) is classified normally
    assert outcome(model, "vars-only")[:3] == (R.PROBABLE_ROOT, C.LOW, "ROLE-U5")
    assert model.get("ctx:root:vars-only") is not None
    assert not any(i.startswith("tf:vars-only::") for i in desired_ids(model))
    assert desired_ids(model) == {"tf:lonely::aws_sns_topic.alerts"}


def test_declaration_inventory_survives_deferred_instantiation(tmp_path):
    model = build_fixture("e_ambiguous", tmp_path)
    inv = model.declaration_inventory()
    assert inv.total_declarations == 2
    assert inv.not_instantiated_declarations == ("decl:stuff/unused::managed.aws_lambda_function.this",)
    assert inv.summary() == (
        "1 configuration deferred (PARSE_FAILED) — 0 resource declarations not instantiated: broken (0 declarations)",
        "1 configuration deferred (AMBIGUOUS_ROLE) — 1 resource declaration not instantiated: stuff/unused (1 aws_lambda_function)",
    )


def test_unknown_cardinality_stays_unknown(tmp_path):
    model = build_fixture("a_clean", tmp_path)
    decl = model.get("decl:modules/network::managed.aws_subnet.private")
    assert decl.meta.count == "var.subnet_count" and decl.cardinality.kind is CardinalityKind.UNKNOWN
    inst = model.get("tf:root::module.network.aws_subnet.private")
    assert inst.template and inst.cardinality.kind is CardinalityKind.UNKNOWN
    assert inst.cardinality.instance_count is None and inst.cardinality.render() == "N = unknown"
    vpc = model.get("tf:root::module.network.aws_vpc.main")
    assert not vpc.template and vpc.cardinality.instance_count == 1
    f = build_fixture("f_messy", tmp_path)
    db = f.get("tf:infra/live::module.app.module.db.aws_db_instance.main")
    assert db.template and db.cardinality.kind is CardinalityKind.UNKNOWN
    # a dynamic block shapes attributes only: not a template
    sg = f.get("tf:infra/live::module.app.aws_security_group.svc")
    assert f.get(sg.declaration).meta.dynamic_blocks == ("ingress",) and not sg.template


# --------------------------------------------------------------------------- regressions G1 / G2


def test_g1_overcount_unused_module_directories_are_not_deployed(tmp_path):
    model = build_fixture("g_overcount", tmp_path)
    assert [c.id for c in model.deployment_contexts] == ["ctx:root:envs/prod"]
    assert outcome(model, "modules/lambda-tpl") == (R.MODULE_SOURCE, C.MEDIUM, "ROLE-U4", S.NOT_APPLICABLE, Why.UNUSED_MODULE_SOURCE)
    assert outcome(model, "old-stuff") == (R.MODULE_SOURCE, C.MEDIUM, "ROLE-U4", S.NOT_APPLICABLE, Why.UNUSED_MODULE_SOURCE)
    # no cascade: a module called only by the unused old-stuff is not instantiated either
    assert outcome(model, "modules/helper") == (R.AMBIGUOUS, C.LOW, "ROLE-X2", S.DEFERRED, Why.CALLER_DEFERRED)
    assert model.get("ctx:root:old-stuff::module.helper") is None
    lambdas = {i.id for i in model.desired_instances() if model.get(i.declaration).provider_type == "aws_lambda_function"}
    assert lambdas == {"tf:envs/prod::module.api.aws_lambda_function.this"}
    # nothing is lost: all six Lambda declarations stay in the model, five not instantiated
    assert set(model.declaration_inventory().not_instantiated_declarations) == {
        "decl:modules/lambda-tpl::managed.aws_lambda_function.tpl",
        "decl:old-stuff::managed.aws_lambda_function.legacy_a",
        "decl:old-stuff::managed.aws_lambda_function.legacy_b",
        "decl:old-stuff::managed.aws_lambda_function.legacy_c",
        "decl:modules/helper::managed.aws_lambda_function.helper",
    }


def test_g2_undercount_same_module_name_in_two_roots_stays_distinct(tmp_path):
    model = build_fixture("h_undercount", tmp_path)
    assert [c.id for c in model.deployment_contexts] == ["ctx:root:root-a", "ctx:root:root-b"]
    assert {m.id for m in model.module_instances} == {"ctx:root:root-a::module.nlb", "ctx:root:root-b::module.nlb"}
    nlbs = [i for i in model.desired_instances() if model.get(i.declaration).provider_type == "aws_lb"]
    assert sorted(i.id for i in nlbs) == ["tf:root-a::module.nlb.aws_lb.this", "tf:root-b::module.nlb.aws_lb.this"]
    assert {i.address for i in nlbs} == {"module.nlb.aws_lb.this"}  # Terraform-native, context-relative
    assert {i.declaration for i in nlbs} == {"decl:modules/nlb::managed.aws_lb.this"}
    assert {"tf:root-a::aws_lambda_function.this", "tf:root-b::aws_lambda_function.this"} <= desired_ids(model)
    assert not model.diagnostics


# --------------------------------------------------------------------------- messy repository


def test_messy_repository_yields_a_partial_model_with_diagnostics(tmp_path):
    model = build_fixture("f_messy", tmp_path)
    summary = summarize(model)
    assert summary.confirmed_roots == ("infra/live",)
    assert summary.module_sources == ("lib/app-stack", "lib/app-stack/db")
    assert summary.unused_module_sources == ("old/unused-tf",)
    assert summary.ambiguous == (("lib/cycle-a", "CYCLE_ONLY"), ("lib/cycle-b", "CYCLE_ONLY"), ("scratch", "AMBIGUOUS_ROLE"))
    assert ("infra/live", "module.missing", "lib/does-not-exist (unresolved)") in summary.local_module_relationships
    assert dict(summary.diagnostic_codes) == {
        "RI-AMBIGUOUS-CONFIGURATION": 3, "RI-INSTANCE-DEFERRED": 1, "RI-INSTANTIATION-DEFERRED": 3, "RI-MODULE-CYCLE": 1,
        "RI-OVERRIDE-FILE-UNMERGED": 1, "RI-PARSE-FAILED": 1, "RI-SOURCE-UNREADABLE": 1, "RI-UNSUPPORTED-CONSTRUCT": 1,
        "RI-UNUSED-MODULE-SOURCE": 1,
    }
    assert desired_ids(model) == {
        "tf:infra/live::module.app.aws_security_group.svc", "tf:infra/live::module.app.module.db.aws_db_instance.main"}
    be = model.get("backend:infra/live::backend")
    assert be.backend_type == "s3" and be.partial_config and be.keys_present == ()
    assert "infra/live" in summary.render() and "diagnostics: info 7, warning 6" in summary.render()


# --------------------------------------------------------------------------- provenance & explanation


def test_evidence_provenance_reaches_artifact_and_line(tmp_path):
    model = build_fixture("a_clean", tmp_path)
    facts = {f.id: f for f in model.facts}
    backend = next(e for e in model.evidence if e.subject == "cfg:root" and e.claim == "R-BACKEND")
    assert backend.kind is ProvenanceKind.OBSERVED and backend.strength is C.HIGH
    (fid,) = backend.facts
    fact = facts[fid]
    assert isinstance(fact, ObservedFact) and fact.kind is FactKind.BACKEND_BLOCK
    assert fact.artifact == "art:root/main.tf" and fact.locator.render() == "terraform.backend.s3:L1-7"
    called = next(e for e in model.evidence if e.subject == "cfg:modules/network" and e.claim == "M-CALLED")
    assert called.kind is ProvenanceKind.STRUCTURAL and called.strength is C.CERTAIN
    assert facts[called.facts[0]].locator.render() == "module.network:L13-16"
    # backend attribute values are never stored, only names
    assert model.get("backend:root::backend").attributes == (("bucket", "<redacted>"), ("key", "<redacted>"), ("region", "<redacted>"))


def test_explain_renders_rule_evidence_missing_and_alternatives(tmp_path):
    d = build_fixture("d_dual_role", tmp_path)
    text = explain(d, "cfg:shared-network")
    assert text.startswith("cfg:shared-network: stage INSTANTIATED, role DUAL_ROLE (HIGH)")
    assert "role=DUAL_ROLE (HIGH) [rule ROLE-C1]" in text
    assert ("[OBSERVED] R-BACKEND (HIGH): declares backend s3 in shared-network/main.tf "
            "@ art:shared-network/main.tf#terraform.backend.s3:L1-7") in text
    assert "[STRUCTURAL] M-CALLED (CERTAIN): called by application as module.network" in text
    assert "instantiation: RESOLVED_BOTH; contexts: ctx:root:shared-network; module instances: ctx:root:application::module.network" in text
    chain = explain(d, "tf:application::module.network.aws_vpc.main")
    assert chain.splitlines()[:3] == [
        "tf:application::module.network.aws_vpc.main: desired instance of decl:shared-network::managed.aws_vpc.main in "
        "ctx:root:application (context_role CONFIRMED_ROOT, confidence HIGH, N = 1)",
        "ctx:root:application: deployment context (root_role, CONFIRMED_ROOT, HIGH)",
        "cfg:application: stage INSTANTIATED, role CONFIRMED_ROOT (HIGH)",
    ]
    e = build_fixture("e_ambiguous", tmp_path)
    amb = explain(e, "cfg:stuff/unused")
    assert "role=AMBIGUOUS (MEDIUM) [rule ROLE-U3]" in amb
    assert ("despite:\n    - [STRUCTURAL] M-REQVAR (MEDIUM): "
            "required variable(s) with no default and no var file in the directory: name") in amb
    assert "alternatives: role=MODULE_SOURCE (unused) (MEDIUM), role=PROBABLE_ROOT (MEDIUM)" in amb
    assert "instantiation: DEFERRED (AMBIGUOUS_ROLE)" in amb
    assert "would change if:" in amb and "missing: R-BACKEND (backend or cloud block)" in amb


# --------------------------------------------------------------------------- identity & determinism


def test_ids_are_repository_relative_and_identical_across_checkouts(tmp_path):
    one = build_repository_model(materialize("f_messy", tmp_path / "home" / "alice" / "project"))
    two = build_repository_model(materialize("f_messy", tmp_path / "build" / "deep" / "er" / "project"))
    assert one.to_json() == two.to_json()
    for s in (str(tmp_path), "/home/", "alice"):
        assert s not in one.to_json()
    assert one.validate() == ()


def test_scanning_a_subdirectory_keeps_anchor_relative_ids(tmp_path):
    repo = materialize("f_messy", tmp_path / "repo")
    whole = build_repository_model(repo)
    sub = build_repository_model(repo / "infra")
    assert sub.anchor.scan_root_rel == "infra"
    # out-of-scan local sources are loaded (inside the anchor) and keep their anchor-relative identity
    assert [c.path for c in sub.configurations] == ["infra/live", "lib/app-stack", "lib/app-stack/db"]
    assert [c.outside_scan_root for c in sub.configurations] == [False, True, True]
    assert desired_ids(sub) == desired_ids(whole)
    assert {d.code for d in sub.diagnostics} >= {"RI-SOURCE-OUT-OF-SCAN"}


def test_without_git_the_scan_root_is_the_anchor_with_a_warning(tmp_path):
    model = build_repository_model(materialize("h_undercount", tmp_path / "h", git=False))
    assert model.anchor.kind.value == "scan_root"
    assert [d.code for d in model.diagnostics] == ["RI-ANCHOR-SCAN-ROOT"]
    assert desired_ids(model) == desired_ids(build_fixture("h_undercount", tmp_path))


def test_traversal_order_does_not_change_the_model(tmp_path, monkeypatch):
    repo = materialize("f_messy", tmp_path / "repo")
    baseline = build_repository_model(repo).to_json()
    real_scandir = os.scandir

    def reversed_scandir(path="."):
        with real_scandir(path) as it:
            return list(reversed(list(it)))

    monkeypatch.setattr(os, "scandir", reversed_scandir)
    assert build_repository_model(repo).to_json() == baseline


# --------------------------------------------------------------------------- structural HCL facts


def test_hcl_structural_facts_without_evaluation():
    text = (
        'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n'
        'locals {\n  a = 1\n  b = var.x\n}\n'
        'data "aws_ami" "img" {\n  most_recent = true\n}\n'
        'moved {\n  from = aws_sqs_queue.old\n  to   = aws_sqs_queue.new\n}\n'
        'import {\n  to = aws_sqs_queue.new\n  id = "https://sqs/q"\n}\n'
        'check "health" {\n  assert {\n    condition     = true\n    error_message = "x"\n  }\n}\n'
        'removed {\n  from = aws_sqs_queue.gone\n}\n'
        'output "o" {\n  value     = local.a\n  sensitive = true\n}\n'
        'resource "aws_sqs_queue" "new" {\n  for_each   = toset(var.names)\n  depends_on = [data.aws_ami.img]\n'
        '  provider   = aws.west\n  lifecycle {\n    create_before_destroy = true\n  }\n}\n'
    )
    parsed = parse_terraform(text, json_syntax=False)
    assert parsed.ok
    assert [b.kind for b in parsed.blocks] == ["terraform", "locals", "data", "moved", "import", "check", "removed", "output", "resource"]
    facts = [f for b in parsed.blocks for f in block_facts("art:x.tf", b)]
    by_kind = {}
    for f in facts:
        by_kind.setdefault(f.kind, []).append(f.payload_dict())
    assert {"providers": "aws"} in by_kind[FactKind.BLOCK_PRESENT]
    assert by_kind[FactKind.LOCALS_DECLARED] == [{"names": "a,b"}]
    assert by_kind[FactKind.MOVED_BLOCK] == [{"from": "aws_sqs_queue.old", "to": "aws_sqs_queue.new"}]
    assert by_kind[FactKind.IMPORT_BLOCK] == [{"to": "aws_sqs_queue.new", "id_literal": "https://sqs/q"}]
    assert by_kind[FactKind.CHECK_BLOCK] == [{"name": "health"}]
    assert by_kind[FactKind.REMOVED_BLOCK] == [{"from": "aws_sqs_queue.gone"}]
    assert by_kind[FactKind.OUTPUT_DECLARED] == [{"name": "o", "sensitive": True}]
    meta = sorted((p["arg"], p.get("expr"), p.get("literal")) for p in by_kind[FactKind.META_ARG_PRESENT])
    assert meta == [("depends_on", None, None), ("for_each", "toset(var.names)", False), ("lifecycle", None, None),
                    ("provider", "aws.west", None)]
    res = parsed.blocks[-1]
    assert (res.line_start, res.line_end) == (34, 41)


def test_provider_alias_and_pins_are_not_provider_configuration(tmp_path):
    model = build_repository_model(write_tree(tmp_path / "pa", {
        "x/main.tf": 'provider "aws" {\n  alias  = "west"\n  region = "us-west-2"\n}\n\n'
                     'resource "aws_sqs_queue" "q" {\n  provider = aws.west\n}\n',
    }))
    # an aliased provider is not a default provider configuration: no R-PROVIDER, so ROLE-U5
    assert "R-PROVIDER" not in signals(model, "x")
    assert outcome(model, "x")[:3] == (R.PROBABLE_ROOT, C.LOW, "ROLE-U5")


def test_var_file_values_are_never_stored(tmp_path):
    model = build_repository_model(write_tree(tmp_path / "vf", {
        "x/main.tf": 'variable "db_password" {}\n\nresource "aws_sqs_queue" "q" {}\n',
        "x/terraform.tfvars": 'db_password = "hunter2-very-secret"\n',
    }))
    (vf,) = model.var_files
    assert vf.variable_names == ("db_password",) and vf.autoloaded
    # the var file provides the required variable, so M-REQVAR is not emitted
    assert "M-REQVAR" not in signals(model, "x")
    assert "hunter2" not in model.to_json()


# --------------------------------------------------------------------------- dev runner


def test_dev_runner_prints_summary_and_explanations(tmp_path, capsys):
    repo = materialize("h_undercount", tmp_path / "h")
    assert recon_cli.main([str(repo), "--explain", "cfg:modules/nlb"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("3 Terraform configurations: CONFIRMED_ROOT 2, MODULE_SOURCE 1")
    assert "root-a --module.nlb--> modules/nlb" in out
    assert "cfg:modules/nlb: stage INSTANTIATED, role MODULE_SOURCE (HIGH)" in out
    assert recon_cli.main([str(repo), "--json"]) == 0
    assert capsys.readouterr().out.strip() == build_repository_model(repo).to_json()


def test_roles_cover_the_full_vocabulary(tmp_path):
    seen = set()
    for name in FIXTURE_NAMES:
        seen |= {c.role for c in build_fixture(name, tmp_path).configurations}
    assert seen == set(ConfigurationRole)
