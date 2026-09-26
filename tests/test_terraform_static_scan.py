"""Regression tests for static (HCL-only) Terraform scanning of repo trees.

Guards the bug where `flowlens scan <repo>` returned ~0 nodes because only
root-level .tf files were read, data/module blocks were dropped, and one
malformed file aborted the whole scan. Everything here works from HCL
source alone: no AWS credentials, `terraform init`, .terraform/ or state.
"""
from pathlib import Path

from typer.testing import CliRunner

from flowlens.cli import app
from flowlens.compare.matcher import split_graph
from flowlens.ingest.terraform import ingest_path
from flowlens.models.graph import Graph
from flowlens.storage.repository import GraphRepository


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _addresses(graph: Graph) -> set[str]:
    return {n.terraform_address for n in graph.nodes.values()}


def _edges(graph: Graph) -> set[tuple[str, str]]:
    by_id = {n.id: n.terraform_address for n in graph.nodes.values()}
    return {(by_id[e.source_node], by_id[e.target_node]) for e in graph.edges.values()}


def _node(graph: Graph, address: str):
    return next(n for n in graph.nodes.values() if n.terraform_address == address)


VPC = 'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }\n'
SUBNET = """
resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
"""


def test_simple_resource_discovery(tmp_path):
    _write(tmp_path, "main.tf", VPC)
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_vpc.main"}
    vpc = _node(graph, "aws_vpc.main")
    assert vpc.metadata["terraform_type"] == "aws_vpc"
    assert vpc.resource_type == "vpc"
    assert vpc.desired_state["cidr_block"] == "10.0.0.0/16"


def test_reference_creates_edge(tmp_path):
    _write(tmp_path, "main.tf", VPC + SUBNET)
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_vpc.main", "aws_subnet.private"}
    assert _edges(graph) == {("aws_subnet.private", "aws_vpc.main")}


def test_multiple_references_in_lists_splats_and_interpolation(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        VPC
        + """
variable "env" { default = "dev" }
locals { prefix = "app" }

resource "aws_subnet" "private" {
  count      = 2
  vpc_id     = "${aws_vpc.main.id}"
  cidr_block = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
}

resource "aws_security_group" "app" {
  name   = "${local.prefix}-${var.env}"
  vpc_id = aws_vpc.main.id
}

resource "aws_lb" "api" {
  subnets         = aws_subnet.private[*].id
  security_groups = [aws_security_group.app.id]
}

resource "aws_lb_target_group" "api" {
  vpc_id = aws_vpc.main.id
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_instance" "worker" {
  subnet_id              = element([for s in aws_subnet.private : s.id], 0)
  vpc_security_group_ids = [aws_security_group.app.id]
}
""",
    )
    graph = ingest_path(tmp_path)
    assert _edges(graph) == {
        ("aws_subnet.private", "aws_vpc.main"),
        ("aws_security_group.app", "aws_vpc.main"),
        ("aws_lb.api", "aws_subnet.private"),
        ("aws_lb.api", "aws_security_group.app"),
        ("aws_lb_target_group.api", "aws_vpc.main"),
        ("aws_lb_listener.api", "aws_lb.api"),
        ("aws_lb_listener.api", "aws_lb_target_group.api"),
        ("aws_instance.worker", "aws_subnet.private"),
        ("aws_instance.worker", "aws_security_group.app"),
    }
    # variables / locals are never nodes nor edge targets
    assert not any(a.startswith(("var.", "local.")) for a in _addresses(graph))


def test_nested_directories_are_scanned(tmp_path):
    _write(tmp_path, "versions.tf", 'terraform {\n  required_version = ">= 1.5"\n}\n')
    _write(tmp_path, "modules/network/main.tf", VPC + SUBNET)
    _write(tmp_path, "environments/dev/app.tf", 'resource "aws_security_group" "app" { vpc_id = aws_vpc.main.id }\n')
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_vpc.main", "aws_subnet.private", "aws_security_group.app"}
    assert ("aws_subnet.private", "aws_vpc.main") in _edges(graph)
    assert ("aws_security_group.app", "aws_vpc.main") in _edges(graph)
    assert _node(graph, "aws_subnet.private").metadata["terraform_file"] == "modules/network/main.tf"
    assert graph.metadata["terraform_scan"]["files_scanned"] == 3


def test_terraform_cache_and_vcs_dirs_are_skipped(tmp_path):
    _write(tmp_path, "main.tf", VPC)
    _write(tmp_path, ".terraform/modules/vpc/main.tf", 'resource "aws_vpc" "cached" {}\n')
    _write(tmp_path, "live/.terragrunt-cache/x/main.tf", 'resource "aws_vpc" "tg_cached" {}\n')
    _write(tmp_path, ".git/hooks/x.tf", 'resource "aws_vpc" "git" {}\n')
    _write(tmp_path, "terraform.tfstate", "{}")
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_vpc.main"}


def test_count_resource_yields_base_node(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_subnet" "private" {\n  count = 3\n  cidr_block = "10.0.${count.index}.0/24"\n}\n')
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_subnet.private"}
    assert _node(graph, "aws_subnet.private").resource_type == "subnet"


def test_for_each_resource_yields_base_node(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        VPC + 'resource "aws_security_group" "app" {\n  for_each = toset(["a", "b"])\n  name = each.key\n  vpc_id = aws_vpc.main.id\n}\n',
    )
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_vpc.main", "aws_security_group.app"}
    assert _edges(graph) == {("aws_security_group.app", "aws_vpc.main")}


def test_explicit_depends_on(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        """
resource "aws_iam_role_policy" "task" { policy = "{}" }
resource "aws_ecs_service" "api" {
  name       = "api"
  depends_on = [aws_iam_role_policy.task]
}
""",
    )
    graph = ingest_path(tmp_path)
    assert _edges(graph) == {("aws_ecs_service.api", "aws_iam_role_policy.task")}


def test_data_and_module_blocks_become_nodes(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        """
data "aws_ami" "ubuntu" { most_recent = true }

module "network" {
  source = "./modules/network"
  cidr   = "10.0.0.0/16"
}

resource "aws_instance" "web" {
  ami        = data.aws_ami.ubuntu.id
  subnet_id  = module.network.private_subnet_ids[0]
  depends_on = [module.network]
}
""",
    )
    graph = ingest_path(tmp_path)
    # the module call is a node; its (unresolved) child resources are not invented
    assert _addresses(graph) == {"data.aws_ami.ubuntu", "module.network", "aws_instance.web"}

    ami = _node(graph, "data.aws_ami.ubuntu")
    assert ami.metadata["terraform_type"] == "aws_ami"
    assert ami.metadata["terraform_mode"] == "data"
    assert ami.resource_type == "ami"

    mod = _node(graph, "module.network")
    assert mod.resource_type == "module"
    assert mod.metadata["terraform_mode"] == "module"
    assert mod.metadata["module_source"] == "./modules/network"

    assert _node(graph, "aws_instance.web").metadata["terraform_mode"] == "managed"
    assert _edges(graph) == {("aws_instance.web", "data.aws_ami.ubuntu"), ("aws_instance.web", "module.network")}

    # data sources / module calls are not managed resources, so compare never expects them in AWS
    desired, _actual = split_graph(graph)
    assert {n.terraform_address for n in desired} == {"aws_instance.web"}


def test_malformed_file_does_not_abort_scan(tmp_path):
    _write(tmp_path, "network/vpc.tf", VPC)
    _write(tmp_path, "network/subnet.tf", SUBNET)
    _write(tmp_path, "broken/bad.tf", 'resource "aws_vpc" "oops" {\n  cidr_block = \n')
    graph = ingest_path(tmp_path)
    assert _addresses(graph) == {"aws_vpc.main", "aws_subnet.private"}
    assert _edges(graph) == {("aws_subnet.private", "aws_vpc.main")}
    warnings = graph.metadata["terraform_scan"]["warnings"]
    assert len(warnings) == 1 and warnings[0].startswith("broken/bad.tf: failed to parse")


def test_scan_output_is_deterministic(tmp_path):
    _write(tmp_path, "b/main.tf", SUBNET)
    _write(tmp_path, "a/main.tf", VPC)
    first, second = ingest_path(tmp_path), ingest_path(tmp_path)
    assert first.to_dict() == second.to_dict()


def test_cli_scan_nested_repo_with_bad_file(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "modules/network/main.tf", VPC + SUBNET)
    _write(repo, "environments/dev/bad.tf", "resource {{{")
    db = str(tmp_path / "flowlens.db")
    result = CliRunner().invoke(app, ["scan", str(repo), "--db", db], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert "Scanned 2 Terraform resources" in result.output
    assert "environments/dev/bad.tf" in result.output

    stored = GraphRepository(db).load_graph()
    assert {"aws_vpc.main", "aws_subnet.private"} <= _addresses(stored)
