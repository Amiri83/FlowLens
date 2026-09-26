"""Helpers for Phase-2 reconnaissance tests.

On-disk fixtures live in tests/fixtures/recon/<name>/ (A-H). Tests copy them
into a temporary directory and add a ``.git`` marker, so the fixture directory
itself is the repository anchor and ids read ``cfg:root``, ``cfg:modules/nlb``,
... instead of being prefixed with ``tests/fixtures/recon/<name>``.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from flowlens.repository import (
    Confidence,
    ConfigurationRole,
    Evidence,
    InstantiationReason,
    InstantiationStatus,
    RepositoryModel,
    TerraformConfiguration,
    build_repository_model,
    ids,
)

RECON_FIXTURES = Path(__file__).parent / "fixtures" / "recon"
FIXTURE_NAMES = ("a_clean", "b_arbitrary", "c_multi_root", "d_dual_role", "e_ambiguous", "f_messy", "g_overcount", "h_undercount")

R = ConfigurationRole
C = Confidence
S = InstantiationStatus
Why = InstantiationReason


def materialize(name: str, dest: Path, *, git: bool = True) -> Path:
    """Copy fixture `name` to `dest` (which must not exist) and make it a repository anchor."""
    shutil.copytree(RECON_FIXTURES / name, dest)
    if git:
        (dest / ".git").mkdir()
    return dest


def build_fixture(name: str, tmp_path: Path) -> RepositoryModel:
    return build_repository_model(materialize(name, tmp_path / name))


def write_tree(root: Path, files: dict[str, str], *, git: bool = True) -> Path:
    """Create a small repository from {relative path: content}. A path ending
    in "/" creates an (empty) directory."""
    root.mkdir(parents=True, exist_ok=True)
    if git:
        (root / ".git").mkdir(exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        if rel.endswith("/"):
            p.mkdir(parents=True, exist_ok=True)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def cfg(model: RepositoryModel, path: str) -> TerraformConfiguration:
    c = model.get(ids.configuration_id(path))
    assert isinstance(c, TerraformConfiguration), f"no configuration {path!r}"
    return c


def rule(model: RepositoryModel, path: str) -> str:
    return model.get(cfg(model, path).classification.inference).rule_id


def outcome(model: RepositoryModel, path: str) -> tuple:
    """(role, confidence, rule id, instantiation status, reason) of one configuration."""
    c = cfg(model, path)
    rec = c.lifecycle.instantiation
    return (c.role, c.classification.confidence, rule(model, path), rec.status, rec.reason)


def signals(model: RepositoryModel, path: str) -> dict[str, Confidence]:
    """Signal claim -> strength, over the classification's supporting and contrary evidence."""
    inf = model.get(cfg(model, path).classification.inference)
    out = {}
    for eid in (*inf.supporting, *inf.contrary):
        ev = model.get(eid)
        assert isinstance(ev, Evidence)
        out[ev.claim] = ev.strength
    return out


def desired_ids(model: RepositoryModel) -> set[str]:
    return {i.id for i in model.desired_instances()}
