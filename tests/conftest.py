import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SAMPLE_TF_DIR = ROOT / "sample_terraform"


@pytest.fixture
def sample_tf_dir() -> Path:
    return SAMPLE_TF_DIR


@pytest.fixture
def tmp_db_path(tmp_path) -> str:
    return str(tmp_path / "flowlens_test.db")
