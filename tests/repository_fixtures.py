"""Hand-built RepositoryModels for Phase-1 tests (proposal §46/§47 shapes).

Everything here is constructed directly - there is no classifier. The point is
to prove the *representation*: what a future classifier will emit must fit.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from flowlens.repository import (
    Alternative,
    Ambiguity,
    AmbiguityKind,
    AnchorKind,
    ArtifactKind,
    BackendEvidence,
    BackendKind,
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
    ModuleCall,
    ModuleInstance,
    ModuleSource,
    ModuleSourceKind,
    ObservedFact,
    ParseStatus,
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
    ids,
)

YES, NO, CANDIDATE = RoleStatus.YES, RoleStatus.NO, RoleStatus.CANDIDATE
C = Confidence


@dataclass
class Builder:
    """Accumulates entities; `model()` hands them to RepositoryModel."""

    anchor: RepositoryAnchor = field(default_factory=lambda: RepositoryAnchor(AnchorKind.GIT_TOPLEVEL))
    parts: dict[str, list] = field(default_factory=dict)

    def add(self, collection: str, item):
        self.parts.setdefault(collection, []).append(item)
        return item

    def artifact(self, path: str) -> RawArtifact:
        return self.add("artifacts", RawArtifact(path))

    def fact(self, path: str, kind: FactKind, block_kind=None, labels=(), lines=(None, None), **payload) -> ObservedFact:
        art = next((a for a in self.parts.get("artifacts", []) if a.path == path), None) or self.artifact(path)
        return self.add("facts", ObservedFact(art.id, Locator(block_kind, tuple(labels), *lines), kind, payload))

    def evidence(self, kind, claim, subject, facts, strength, **kw) -> Evidence:
        return self.add("evidence", Evidence(kind, claim, subject, tuple(f.id for f in facts), strength, **kw))

    def inference(self, rule, subject, conclusion, confidence, supporting=(), contrary=(), **kw) -> Inference:
        return self.add(
            "inferences",
            Inference(rule, subject, conclusion, confidence, tuple(e.id for e in supporting), tuple(e.id for e in contrary), **kw),
        )

    def model(self) -> RepositoryModel:
        return RepositoryModel(self.anchor, **{k: tuple(v) for k, v in self.parts.items()})


def _files(b: Builder, *paths: str) -> tuple[SourceFileRef, ...]:
    refs = []
    for p in paths:
        art = next((a for a in b.parts.get("artifacts", []) if a.path == p), None) or b.artifact(p)
        refs.append(SourceFileRef(art.id))
    return tuple(refs)


def declare(b: Builder, cfg: str, tf_type: str, name: str, file: str, meta: MetaArguments | None = None) -> ResourceDeclaration:
    f = b.fact(f"{cfg}/{file}", FactKind.BLOCK_PRESENT, "resource", (tf_type, name))
    subject = ids.declaration_id(cfg, DeclarationMode.MANAGED, tf_type, name)
    ev = b.evidence(ProvenanceKind.OBSERVED, "decl.block_present", subject, [f], C.CERTAIN)
    return b.add("resource_declarations", ResourceDeclaration(cfg, DeclarationMode.MANAGED, tf_type, name, meta or MetaArguments(), ev.id))


# --------------------------------------------------------------------------- DUAL_ROLE (§47)


def dual_role_model() -> RepositoryModel:
    b = Builder()
    # shared-network: backend + tfvars (root side), called by application (module side)
    f_sn_backend = b.fact("shared-network/main.tf", FactKind.BACKEND_BLOCK, "terraform", ("backend", "s3"), (1, 4), backend_type="s3")
    f_sn_tfvars = b.fact("shared-network/terraform.tfvars", FactKind.ARTIFACT_PRESENT)
    b.add("var_files", VarFileArtifact("shared-network/terraform.tfvars"))
    b.artifact("shared-network/outputs.tf")
    f_app_backend = b.fact("application/main.tf", FactKind.BACKEND_BLOCK, "terraform", ("backend", "s3"), (1, 4), backend_type="s3")
    f_call = b.fact("application/main.tf", FactKind.MODULE_SOURCE_LITERAL, "module", ("network",), (6, 8), source="../shared-network")

    e_sn_backend = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_backend", "cfg:shared-network", [f_sn_backend], C.CERTAIN,
                              detail='shared-network/main.tf declares backend "s3"')
    e_sn_tfvars = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_autoloaded_tfvars", "cfg:shared-network", [f_sn_tfvars], C.MEDIUM)
    e_sn_called = b.evidence(ProvenanceKind.STRUCTURAL, "cfg.called_by", "cfg:shared-network", [f_call], C.CERTAIN,
                             detail="called by application as module.network")
    e_app_backend = b.evidence(ProvenanceKind.OBSERVED, "cfg.has_backend", "cfg:application", [f_app_backend], C.CERTAIN)

    inf_sn = b.inference("ROLE-C1", "cfg:shared-network", "role=DUAL_ROLE", C.HIGH, [e_sn_backend, e_sn_tfvars, e_sn_called],
                         missing=("ci_execution",))
    inf_app = b.inference("ROLE-U1", "cfg:application", "role=CONFIRMED_ROOT", C.HIGH, [e_app_backend], missing=("ci_execution",))

    b.add("backend_evidence", BackendEvidence("shared-network", BackendKind.BACKEND, "s3", {"bucket": "tf-state", "key": "net"},
                                              evidence=e_sn_backend.id))

    ctx_sn = b.add("deployment_contexts", DeploymentContext("shared-network", ConfigurationRole.DUAL_ROLE, C.HIGH,
                                                            var_files=("varfile:shared-network/terraform.tfvars",),
                                                            backend="backend:shared-network::backend"))
    ctx_app = b.add("deployment_contexts", DeploymentContext("application", ConfigurationRole.CONFIRMED_ROOT, C.HIGH))
    src = b.add("module_sources", ModuleSource(ModuleSourceKind.LOCAL, "shared-network", raw_source="../shared-network"))
    call = b.add("module_calls", ModuleCall("application", "network", src.id, evidence=e_sn_called.id))
    mi = b.add("module_instances", ModuleInstance(ctx_app.id, "module.network", call.id, src.id, source_configuration="cfg:shared-network"))

    vpc = declare(b, "shared-network", "aws_vpc", "main", "main.tf")
    fn = declare(b, "application", "aws_lambda_function", "app", "main.tf")
    b.add("resource_instances", DesiredResourceInstance.derive(ctx_sn, vpc))
    b.add("resource_instances", DesiredResourceInstance.derive(ctx_app, vpc, mi))
    b.add("resource_instances", DesiredResourceInstance.derive(ctx_app, fn))

    inst = LifecycleStage.INSTANTIATED
    b.add("configurations", TerraformConfiguration(
        "shared-network",
        files=_files(b, "shared-network/main.tf", "shared-network/outputs.tf"),
        lifecycle=ConfigurationLifecycle(inst, InstantiationRecord(InstantiationStatus.RESOLVED_BOTH, contexts=(ctx_sn.id,),
                                                                   instances=(mi.id,))),
        classification=Classification(
            ConfigurationRole.DUAL_ROLE, C.HIGH,
            RoleAssessment(YES, C.HIGH, (e_sn_backend.id, e_sn_tfvars.id), missing=("ci_execution",)),
            RoleAssessment(YES, C.CERTAIN, (e_sn_called.id,)),
            inf_sn.id,
        ),
    ))
    b.add("configurations", TerraformConfiguration(
        "application",
        files=_files(b, "application/main.tf"),
        lifecycle=ConfigurationLifecycle(inst, InstantiationRecord(InstantiationStatus.RESOLVED_ROOT, contexts=(ctx_app.id,))),
        classification=Classification(
            ConfigurationRole.CONFIRMED_ROOT, C.HIGH,
            RoleAssessment(YES, C.HIGH, (e_app_backend.id,)), RoleAssessment(NO, C.HIGH), inf_app.id,
        ),
    ))
    return b.model()


# --------------------------------------------------------------------------- MESSY (§46 subset)


def messy_model() -> RepositoryModel:
    """potato: PROBABLE_ROOT (MEDIUM), one plain + one for_each template resource.
    stuff/a (3 decls) and stuff/b (1 decl): AMBIGUOUS, DEFERRED(AMBIGUOUS_ROLE).
    random: UNKNOWN, parse failed, DEFERRED(PARSE_FAILED).
    modules/lambda-tpl: discovered only (stops at DISCOVERED)."""
    b = Builder()
    # potato
    f_prov = b.fact("potato/main.tf", FactKind.PROVIDER_CONFIG, "provider", ("aws",), (1, 3), region="eu-west-1")
    e_prov = b.evidence(ProvenanceKind.OBSERVED, "cfg.provider_configured", "cfg:potato", [f_prov], C.MEDIUM)
    inf_potato = b.inference("ROLE-U2", "cfg:potato", "role=PROBABLE_ROOT", C.MEDIUM, [e_prov],
                             missing=("backend", "state", "lock_file", "ci_execution"),
                             alternatives=(Alternative("role=MODULE_SOURCE(unused)", C.LOW),))
    ctx = b.add("deployment_contexts", DeploymentContext("potato", ConfigurationRole.PROBABLE_ROOT, C.MEDIUM))
    handler = declare(b, "potato", "aws_lambda_function", "handler", "main.tf")
    workers = declare(b, "potato", "aws_lambda_function", "workers", "main.tf", MetaArguments(for_each="var.services"))
    b.add("resource_instances", DesiredResourceInstance.derive(ctx, handler))
    b.add("resource_instances", DesiredResourceInstance.derive(ctx, workers))
    b.add("configurations", TerraformConfiguration(
        "potato", files=_files(b, "potato/main.tf"),
        lifecycle=ConfigurationLifecycle(LifecycleStage.INSTANTIATED,
                                         InstantiationRecord(InstantiationStatus.RESOLVED_ROOT, contexts=(ctx.id,))),
        classification=Classification(ConfigurationRole.PROBABLE_ROOT, C.MEDIUM, RoleAssessment(YES, C.MEDIUM, (e_prov.id,)),
                                      RoleAssessment(NO, C.MEDIUM), inf_potato.id),
    ))

    # two AMBIGUOUS configurations, deferred, declarations kept
    for cfg, n in (("stuff/a", 3), ("stuff/b", 1)):
        f_p = b.fact(f"{cfg}/x.tf", FactKind.PROVIDER_CONFIG, "provider", ("aws",), (1, 3), region="eu-west-1")
        f_v = b.fact(f"{cfg}/x.tf", FactKind.VARIABLE_DECLARED, "variable", ("name",), (5, 5), has_default=False)
        e_root = b.evidence(ProvenanceKind.OBSERVED, "cfg.provider_configured", f"cfg:{cfg}", [f_p], C.MEDIUM)
        e_mod = b.evidence(ProvenanceKind.OBSERVED, "cfg.required_var_unsatisfied", f"cfg:{cfg}", [f_v], C.MEDIUM)
        alts = (Alternative("role=PROBABLE_ROOT", C.MEDIUM), Alternative("role=MODULE_SOURCE(unused)", C.MEDIUM))
        inf = b.inference("ROLE-U3", f"cfg:{cfg}", "role=AMBIGUOUS", C.MEDIUM, [e_root], [e_mod], alternatives=alts,
                          missing=("backend", "tfvars", "state"))
        b.add("ambiguities", Ambiguity(AmbiguityKind.ROLE, f"cfg:{cfg}", alts, (e_root.id, e_mod.id),
                                       ("backend block", "tfvars providing `name`", "state artifact", "CI step")))
        for i in range(n):
            declare(b, cfg, "aws_lambda_function", f"fn{i}", "x.tf")
        b.add("configurations", TerraformConfiguration(
            cfg, files=_files(b, f"{cfg}/x.tf"),
            lifecycle=ConfigurationLifecycle(LifecycleStage.INSTANTIATED, InstantiationRecord(
                InstantiationStatus.DEFERRED, InstantiationReason.AMBIGUOUS_ROLE, inf.id)),
            classification=Classification(ConfigurationRole.AMBIGUOUS, C.MEDIUM, RoleAssessment(CANDIDATE, C.MEDIUM, (e_root.id,)),
                                          RoleAssessment(CANDIDATE, C.MEDIUM, (e_mod.id,)), inf.id),
        ))

    # UNKNOWN: every file failed to parse
    f_err = b.fact("random/test.tf", FactKind.PARSE_ERROR, line_no=3)
    e_err = b.evidence(ProvenanceKind.OBSERVED, "cfg.parse_failed", "cfg:random", [f_err], C.CERTAIN)
    inf_r = b.inference("ROLE-P1", "cfg:random", "role=UNKNOWN", C.UNKNOWN, [e_err], missing=("parseable file",))
    b.add("diagnostics", Diagnostic("RI-PARSE-FAILED", Severity.WARNING, "cfg:random",
                                    "random/test.tf: syntax error at line 3", (e_err.id,)))
    b.add("configurations", TerraformConfiguration(
        "random", files=(SourceFileRef("art:random/test.tf", ParseStatus.FAILED),), parse_status=ParseStatus.FAILED,
        lifecycle=ConfigurationLifecycle(LifecycleStage.INSTANTIATED, InstantiationRecord(
            InstantiationStatus.DEFERRED, InstantiationReason.PARSE_FAILED, inf_r.id)),
        classification=Classification(ConfigurationRole.UNKNOWN, C.UNKNOWN, RoleAssessment.unknown(), RoleAssessment.unknown(), inf_r.id),
    ))

    # discovered but not (yet) classified: still represented
    b.add("configurations", TerraformConfiguration("modules/lambda-tpl", files=_files(b, "modules/lambda-tpl/main.tf")))
    return b.model()


def name_hint_evidence(b: Builder, cfg: str, segment: str, strength=Confidence.LOW) -> Evidence:
    art = next((a for a in b.parts.get("artifacts", []) if a.path == cfg), None) or b.add(
        "artifacts", RawArtifact(cfg, kind=ArtifactKind.DIRECTORY)
    )
    f = b.add("facts", ObservedFact(art.id, Locator(labels=(segment,)), FactKind.PATH_SEGMENT, {"segment": segment}))
    return b.evidence(ProvenanceKind.INFERRED, "cfg.path_hint_module", f"cfg:{cfg}", [f], strength, basis=EvidenceBasis.NAME_HINT)
