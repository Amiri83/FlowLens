import json
from pathlib import Path

import boto3
from moto import mock_aws
from typer.testing import CliRunner

from flowlens.cli import app
from flowlens.storage.repository import GraphRepository

EXAMPLES = Path(__file__).parent.parent / "examples" / "terraform"
runner = CliRunner()


def _run(*args):
    return runner.invoke(app, list(args), catch_exceptions=False)


def test_scan_links_and_path_prints_route(tmp_db_path):
    result = _run("scan", str(EXAMPLES), "--db", tmp_db_path)
    assert result.exit_code == 0, result.output

    result = _run("path", "aws_api_gateway_integration.hello", "aws_subnet.private_a", "--db", tmp_db_path)
    assert result.exit_code == 0, result.output
    assert "integrates_with" in result.output and "member_of" in result.output

    result = _run("path", "aws_lb_listener.https", "aws_vpc.main", "--json", "--db", tmp_db_path)
    data = json.loads(result.output)
    assert data["found"] is True
    assert data["nodes"] == ["tf:aws_lb_listener.https", "tf:aws_lb_target_group.app", "tf:aws_vpc.main"]


def test_path_respects_direction_and_undirected_flag(tmp_db_path):
    _run("scan", str(EXAMPLES), "--db", tmp_db_path)
    assert _run("path", "aws_vpc.main", "aws_lb_listener.https", "--db", tmp_db_path).exit_code == 1
    assert _run("path", "aws_vpc.main", "aws_lb_listener.https", "--undirected", "--db", tmp_db_path).exit_code == 0


def test_path_unknown_node_exits_nonzero(tmp_db_path):
    _run("scan", str(EXAMPLES), "--db", tmp_db_path)
    result = _run("path", "nope", "aws_vpc.main", "--db", tmp_db_path)
    assert result.exit_code == 1 and "No unique node" in result.output


def test_info_by_name_attribute(tmp_db_path):
    _run("scan", str(EXAMPLES), "--db", tmp_db_path)
    result = _run("info", "shop-alb", "--db", tmp_db_path)
    assert result.exit_code == 0, result.output
    assert "tf:aws_lb.web" in result.output and "edges" in result.output


def test_scan_with_state_replaces_config_nodes(tmp_path, tmp_db_path):
    state = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_vpc",
                "name": "main",
                "instances": [{"attributes": {"id": "vpc-123", "cidr_block": "10.20.0.0/16"}}],
            }
        ],
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state))
    assert _run("scan", str(EXAMPLES), "--state", str(state_file), "--db", tmp_db_path).exit_code == 0

    repo = GraphRepository(tmp_db_path)
    graph = repo.load_graph()
    repo.close()
    assert "vpc:vpc-123" in graph.nodes and "tf:aws_vpc.main" not in graph.nodes
    # Edges that pointed at the config node now point at the state node.
    assert any(e.target_node == "vpc:vpc-123" or e.source_node == "vpc:vpc-123" for e in graph.edges.values())


@mock_aws
def test_aws_scan_and_compare(tmp_db_path, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.20.0.0/16")

    _run("scan", str(EXAMPLES), "--db", tmp_db_path)
    result = _run("aws", "scan", "--region", "us-east-1", "--db", tmp_db_path)
    assert result.exit_code == 0, result.output
    assert _run("discover-aws", "--region", "us-east-1", "--db", tmp_db_path).exit_code == 0

    result = _run("compare", "--json", "--db", tmp_db_path)
    data = json.loads(result.output)
    assert data["summary"]["TERRAFORM_ONLY"] > 0  # config-only resources have no AWS counterpart
    assert data["summary"]["AWS_ONLY"] > 0  # moto's default VPC etc.
    assert {r["status"] for r in data["results"]} <= {"MATCHED", "DIFFERENT", "TERRAFORM_ONLY", "AWS_ONLY", "UNKNOWN"}


def test_export_import_roundtrip_keeps_metadata(tmp_path, tmp_db_path):
    _run("scan", str(EXAMPLES), "--db", tmp_db_path)
    out = tmp_path / "graph.json"
    assert _run("export-json", str(out), "--db", tmp_db_path).exit_code == 0
    other_db = str(tmp_path / "other.db")
    assert _run("import-json", str(out), "--db", other_db).exit_code == 0
    assert "metadata" in json.loads(out.read_text())


def test_existing_commands_still_registered():
    help_text = _run("--help").output
    for cmd in ("ingest-tf", "discover-aws", "build-graph", "serve", "ui", "scan", "aws", "path", "info", "compare",
                "export-json", "import-json"):
        assert cmd in help_text
