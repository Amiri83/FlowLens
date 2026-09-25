import os
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SAMPLE_TF_DIR = ROOT / "sample_terraform"

#: Exact env var names that would leak a real/LocalStack AWS target or
#: credentials into moto-mocked tests.
_AWS_ENV_EXACT = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_S3_ENDPOINT",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CA_BUNDLE",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
}
#: Prefixes: every per-service endpoint override (AWS_ENDPOINT_URL_EC2, ...)
#: and SSO settings.
_AWS_ENV_PREFIXES = ("AWS_ENDPOINT_URL", "AWS_SSO_")


def _is_leaky_aws_var(name: str) -> bool:
    return name in _AWS_ENV_EXACT or name.startswith(_AWS_ENV_PREFIXES)


@pytest.fixture(autouse=True)
def hermetic_aws_env(monkeypatch, tmp_path):
    """Make every test independent of the developer's shell.

    moto's @mock_aws still honors AWS_ENDPOINT_URL* (and profiles), so an
    ambient LocalStack setup would redirect "mocked" calls to a live
    endpoint. Strip all of it, point boto3 at empty config files, and set
    fake credentials so boto3 never searches the real credential chain.
    Tests that need a specific value re-set it with monkeypatch.
    """
    for name in list(os.environ):
        if _is_leaky_aws_var(name):
            monkeypatch.delenv(name, raising=False)
    empty_cfg = tmp_path / "aws_empty_config"
    empty_cfg.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(empty_cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(empty_cfg))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # Never let an instance-metadata lookup reach the network.
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    yield


@pytest.fixture
def sample_tf_dir() -> Path:
    return SAMPLE_TF_DIR


@pytest.fixture
def tmp_db_path(tmp_path) -> str:
    return str(tmp_path / "flowlens_test.db")
