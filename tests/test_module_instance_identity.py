"""Regression tests for module-instance identity in static (HCL) scans.

Guards the bug where resources inside local modules were addressed as if
they lived in the root module (`aws_lambda_function.this`), so the same
`type.name` in two module instances collapsed to one node id and the
duplicate guard silently dropped all but the first. Identity must follow
Terraform module *instances* (`module.<call>.<type>.<name>`), never the
module's source directory.
"""
import json
from pathlib import Path

from flowlens.compare.matcher import match_nodes, split_graph
from flowlens.ingest.terraform import combine_config_and_state, ingest_path, parse_config_dir, parse_state_json
from flowlens.linking.linker import link_graph
from flowlens.models.graph import Graph, Node, RelationshipType, Source
from flowlens.reachability.facts import build_facts

FIXTURE = Path(__file__).parent / "fixtures" / "module_identity"


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _calls(**sources: str) -> str:
    """`module` blocks, one per name=source."""
    return "".join(f'module "{name}" {{ source = "{source}" }}\n' for name, source in sources.items())


def _node(graph: Graph, address: str) -> Node:
    return next(n for n in graph.nodes.values() if n.terraform_address == address)


def _of_type(graph: Graph, resource_type: str) -> dict[str, str]:
    """terraform_address -> node id for every node of `resource_type`."""
    return {n.terraform_address: n.id for n in graph.nodes.values() if n.resource_type == resource_type}


def _edges(graph: Graph, rel: RelationshipType | None = None) -> set[tuple[str, str]]:
    by_id = {n.id: n.terraform_address for n in graph.nodes.values()}
    return {
        (by_id[e.source_node], by_id[e.target_node])
        for e in graph.edges.values()
        if rel is None or e.relationship_type == rel
    }


LAMBDA = 'resource "aws_lambda_function" "this" {\n  function_name = "fn"\n}\n'
NLB = 'resource "aws_lb" "nlb" {\n  load_balancer_type = "network"\n  internal = true\n}\n'


def test_same_name_in_two_module_instances_does_not_collide(tmp_path):
    _write(tmp_path, "modules/api/main.tf", LAMBDA)
    _write(tmp_path, "modules/worker/main.tf", LAMBDA)
    _write(tmp_path, "main.tf", 'module "api" { source = "./modules/api" }\nmodule "worker" { source = "./modules/worker" }\n')
    graph = ingest_path(tmp_path)
    assert _of_type(graph, "lambda") == {
        "module.api.aws_lambda_function.this": "tf:module.api.aws_lambda_function.this",
        "module.worker.aws_lambda_function.this": "tf:module.worker.aws_lambda_function.this",
    }
    assert graph.metadata["terraform_scan"]["warnings"] == []


def test_same_source_instantiated_twice_yields_two_instances(tmp_path):
    _write(tmp_path, "modules/lambda/main.tf", LAMBDA)
    _write(tmp_path, "main.tf", 'module "one" { source = "./modules/lambda" }\nmodule "two" { source = "./modules/lambda" }\n')
    graph = ingest_path(tmp_path)
    assert set(_of_type(graph, "lambda")) == {"module.one.aws_lambda_function.this", "module.two.aws_lambda_function.this"}
    one = _node(graph, "module.one.aws_lambda_function.this")
    assert one.metadata["terraform_module"] == "module.one"
    assert one.metadata["terraform_file"] == "modules/lambda/main.tf"
    # the module calls stay nodes in the caller's (root) scope
    assert set(_of_type(graph, "module")) == {"module.one", "module.two"}
    assert graph.metadata["terraform_scan"]["warnings"] == []


def test_repeated_nlb_names_in_two_instances(tmp_path):
    _write(tmp_path, "modules/sentry/main.tf", NLB)
    _write(tmp_path, "modules/observability/main.tf", NLB)
    _write(tmp_path, "main.tf", _calls(sentry="./modules/sentry", observability="./modules/observability"))
    graph = ingest_path(tmp_path)
    assert _of_type(graph, "nlb") == {
        "module.sentry.aws_lb.nlb": "tf:module.sentry.aws_lb.nlb",
        "module.observability.aws_lb.nlb": "tf:module.observability.aws_lb.nlb",
    }
    assert _of_type(graph, "alb") == {}


def test_nested_modules_keep_full_instance_path(tmp_path):
    _write(tmp_path, "modules/worker/main.tf", LAMBDA)
    _write(tmp_path, "modules/application/main.tf", 'module "worker" { source = "../worker" }\n')
    _write(tmp_path, "modules/other/main.tf", 'module "worker" { source = "../worker" }\n')
    _write(tmp_path, "main.tf", _calls(application="./modules/application", other="./modules/other"))
    graph = ingest_path(tmp_path)
    assert set(_of_type(graph, "lambda")) == {
        "module.application.module.worker.aws_lambda_function.this",
        "module.other.module.worker.aws_lambda_function.this",
    }
    assert set(_of_type(graph, "module")) == {
        "module.application",
        "module.other",
        "module.application.module.worker",
        "module.other.module.worker",
    }
    assert _node(graph, "module.application.module.worker.aws_lambda_function.this").metadata["terraform_module"] == (
        "module.application.module.worker"
    )
    assert _node(graph, "module.application.module.worker").metadata["terraform_module"] == "module.application"
    assert graph.metadata["terraform_scan"]["warnings"] == []


def test_module_cycle_terminates_with_warning(tmp_path):
    _write(tmp_path, "modules/a/main.tf", 'module "b" { source = "../b" }\n' + LAMBDA)
    _write(tmp_path, "modules/b/main.tf", 'module "a" { source = "../a" }\n')
    _write(tmp_path, "main.tf", 'module "a" { source = "./modules/a" }\n')
    graph = ingest_path(tmp_path)
    assert set(_of_type(graph, "lambda")) == {"module.a.aws_lambda_function.this"}
    warnings = graph.metadata["terraform_scan"]["warnings"]
    assert warnings == ["modules/b/main.tf: module.a.module.b.module.a source '../a' forms a module cycle; not followed"]


def test_root_resource_identity_unchanged(tmp_path):
    _write(tmp_path, "modules/lambda/main.tf", LAMBDA)
    _write(tmp_path, "main.tf", 'resource "aws_instance" "web" { ami = "ami-1" }\nmodule "fn" { source = "./modules/lambda" }\n')
    graph = ingest_path(tmp_path)
    web = _node(graph, "aws_instance.web")
    assert web.id == "tf:aws_instance.web"
    assert web.resource_type == "instance"
    assert web.metadata == {"terraform_mode": "managed", "terraform_file": "main.tf", "terraform_type": "aws_instance"}
    assert _node(graph, "module.fn").id == "tf:module.fn"


APP_MODULE = """
resource "aws_vpc" "this" { cidr_block = "10.0.0.0/16" }

resource "aws_subnet" "this" {
  vpc_id     = aws_vpc.this.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_security_group" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_instance" "this" {
  subnet_id              = aws_subnet.this.id
  vpc_security_group_ids = [aws_security_group.this.id]
}

resource "aws_lambda_function" "this" {
  function_name = "fn"
  vpc_config {
    subnet_ids         = [aws_subnet.this.id]
    security_group_ids = [aws_security_group.this.id]
  }
}
"""


def test_references_resolve_within_their_own_module_instance(tmp_path):
    _write(tmp_path, "modules/app/main.tf", APP_MODULE)
    # a same-named root SG must not attract references from inside the modules
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_security_group" "this" {}\n' + _calls(blue="./modules/app", green="./modules/app"),
    )
    graph = link_graph(ingest_path(tmp_path))

    depends = _edges(graph, RelationshipType.DEPENDS_ON)
    for m in ("blue", "green"):
        assert (f"module.{m}.aws_instance.this", f"module.{m}.aws_security_group.this") in depends
        assert (f"module.{m}.aws_instance.this", f"module.{m}.aws_subnet.this") in depends
    assert not any(
        src.split(".")[1] != dst.split(".")[1] for src, dst in depends if src.startswith("module.") and dst.startswith("module.")
    )
    assert not any(dst == "aws_security_group.this" for _src, dst in depends)

    # linker (semantic edges) is scoped the same way
    assert {e for e in _edges(graph, RelationshipType.ALLOWS)} == {
        ("module.blue.aws_security_group.this", "module.blue.aws_lambda_function.this"),
        ("module.green.aws_security_group.this", "module.green.aws_lambda_function.this"),
    }
    assert {e for e in _edges(graph, RelationshipType.CONTAINS)} == {
        ("module.blue.aws_vpc.this", "module.blue.aws_subnet.this"),
        ("module.blue.aws_vpc.this", "module.blue.aws_security_group.this"),
        ("module.green.aws_vpc.this", "module.green.aws_subnet.this"),
        ("module.green.aws_vpc.this", "module.green.aws_security_group.this"),
    }

    # and so is reachability's fact builder
    facts = build_facts(graph)
    for m in ("blue", "green"):
        for kind in ("instance", "lambda"):
            ep = facts.endpoints[f"tf:module.{m}.aws_{'instance' if kind == 'instance' else 'lambda_function'}.this"]
            assert ep.sgs == [f"tf:module.{m}.aws_security_group.this"]
            assert ep.subnets == [f"tf:module.{m}.aws_subnet.this"]
        assert facts.subnets[f"tf:module.{m}.aws_subnet.this"].vpc == f"tf:module.{m}.aws_vpc.this"


def test_module_inputs_reference_the_callers_scope(tmp_path):
    _write(tmp_path, "modules/app/main.tf", LAMBDA)
    _write(
        tmp_path,
        "modules/wrapper/main.tf",
        'resource "aws_iam_role" "r" {}\nmodule "app" {\n  source = "../app"\n  role = aws_iam_role.r.arn\n}\n',
    )
    _write(tmp_path, "main.tf", 'resource "aws_iam_role" "r" {}\nmodule "wrapper" { source = "./modules/wrapper" }\n')
    graph = ingest_path(tmp_path)
    assert ("module.wrapper.module.app", "module.wrapper.aws_iam_role.r") in _edges(graph)
    assert ("module.wrapper.module.app", "aws_iam_role.r") not in _edges(graph)


def test_genuine_duplicate_address_is_still_reported(tmp_path):
    _write(tmp_path, "a.tf", 'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }\n')
    _write(tmp_path, "b.tf", 'resource "aws_vpc" "main" { cidr_block = "10.1.0.0/16" }\n')
    _write(tmp_path, "modules/lambda/one.tf", LAMBDA)
    _write(tmp_path, "modules/lambda/two.tf", LAMBDA)
    _write(tmp_path, "c.tf", 'module "fn" { source = "./modules/lambda" }\n')
    graph = ingest_path(tmp_path)
    assert graph.nodes["tf:aws_vpc.main"].desired_state["cidr_block"] == "10.0.0.0/16"
    assert graph.metadata["terraform_scan"]["warnings"] == [
        "b.tf: duplicate address aws_vpc.main (already defined in a.tf); kept the first",
        "modules/lambda/two.tf: duplicate address module.fn.aws_lambda_function.this "
        "(already defined in modules/lambda/one.tf); kept the first",
    ]


def test_count_and_for_each_keep_template_nodes_without_inventing_keys(tmp_path):
    _write(
        tmp_path,
        "modules/worker/main.tf",
        LAMBDA + 'resource "aws_sqs_queue" "q" {\n  for_each = var.queues\n  name = each.key\n}\n',
    )
    _write(
        tmp_path,
        "main.tf",
        'module "worker" {\n  source = "./modules/worker"\n  for_each = var.workers\n}\n'
        'module "single" { source = "./modules/worker" }\n',
    )
    graph = ingest_path(tmp_path)
    addresses = {n.terraform_address for n in graph.nodes.values()}
    assert addresses == {
        "module.worker",
        "module.worker.aws_lambda_function.this",
        "module.worker.aws_sqs_queue.q",
        "module.single",
        "module.single.aws_lambda_function.this",
        "module.single.aws_sqs_queue.q",
    }
    assert not any("[" in a for a in addresses)

    templ = _node(graph, "module.worker.aws_lambda_function.this").metadata
    assert templ["terraform_template"] is True
    assert templ["terraform_expansion"] == [{"address": "module.worker", "meta_argument": "for_each"}]
    assert _node(graph, "module.worker.aws_sqs_queue.q").metadata["terraform_expansion"] == [
        {"address": "module.worker", "meta_argument": "for_each"},
        {"address": "module.worker.aws_sqs_queue.q", "meta_argument": "for_each"},
    ]
    assert _node(graph, "module.worker").metadata["terraform_template"] is True
    assert "terraform_template" not in _node(graph, "module.single.aws_lambda_function.this").metadata
    assert _node(graph, "module.single.aws_sqs_queue.q").metadata["terraform_expansion"] == [
        {"address": "module.single.aws_sqs_queue.q", "meta_argument": "for_each"}
    ]


def test_scan_is_deterministic_and_order_independent():
    first, second = ingest_path(FIXTURE), ingest_path(FIXTURE)
    assert first.to_dict() == second.to_dict()

    files = sorted(FIXTURE.rglob("*.tf"), reverse=True)
    shuffled = parse_config_dir(FIXTURE, files=files)

    def summary(g: Graph):
        return (
            sorted((n.id, n.terraform_address, n.resource_type) for n in g.nodes.values()),
            sorted(g.edges),
        )

    assert summary(shuffled) == summary(first)


def test_ids_are_machine_independent_for_modules_outside_the_scan_root():
    # scanning the root on its own follows ../modules like Terraform does
    graph = ingest_path(FIXTURE / "email2case")
    assert len(_of_type(graph, "lambda")) == 4
    assert _node(graph, "module.classifier.aws_lambda_function.this").metadata["terraform_file"] == "../modules/consumer_sqs/main.tf"
    assert str(FIXTURE) not in json.dumps(graph.to_dict())


def test_real_world_layout_keeps_every_module_instance():
    graph = link_graph(ingest_path(FIXTURE))
    assert _of_type(graph, "lambda") == {
        "module.classifier.aws_lambda_function.this": "tf:module.classifier.aws_lambda_function.this",
        "module.data_fusion.aws_lambda_function.this": "tf:module.data_fusion.aws_lambda_function.this",
        "module.kafka_lambda_consumer.aws_lambda_function.this": "tf:module.kafka_lambda_consumer.aws_lambda_function.this",
        "module.kafka_producer.aws_lambda_function.this": "tf:module.kafka_producer.aws_lambda_function.this",
    }
    assert _of_type(graph, "nlb") == {
        "module.sentry.aws_lb.nlb": "tf:module.sentry.aws_lb.nlb",
        "module.observability.aws_lb.nlb": "tf:module.observability.aws_lb.nlb",
    }
    assert graph.metadata["terraform_scan"]["warnings"] == []

    # each Lambda uses its own instance's role; each listener its own NLB / target group
    depends = _edges(graph, RelationshipType.DEPENDS_ON)
    for m in ("classifier", "data_fusion", "kafka_lambda_consumer", "kafka_producer"):
        assert (f"module.{m}.aws_lambda_function.this", f"module.{m}.aws_iam_role.this") in depends
    for m in ("sentry", "observability"):
        assert (f"module.{m}.aws_lb_listener.this", f"module.{m}.aws_lb.nlb") in depends
    forwards = _edges(graph, RelationshipType.FORWARDS_TO)
    assert forwards == {
        ("module.sentry.aws_lb_listener.this", "module.sentry.aws_lb_target_group.this"),
        ("module.observability.aws_lb_listener.this", "module.observability.aws_lb_target_group.this"),
    }


def test_module_qualified_desired_nodes_match_aws_by_name(tmp_path):
    for m in ("classifier", "producer"):
        _write(tmp_path, f"modules/{m}/main.tf", f'resource "aws_lambda_function" "this" {{ function_name = "email2case-{m}" }}\n')
    _write(tmp_path, "main.tf", _calls(classifier="./modules/classifier", producer="./modules/producer"))
    desired, _ = split_graph(ingest_path(tmp_path))
    actual = [
        Node(id=f"lambda:{name}", name=name, resource_type="lambda", source=Source.AWS, actual_state={"function_name": name})
        for name in ("email2case-producer", "email2case-classifier")
    ]
    result = match_nodes(desired, actual)
    assert sorted((d.terraform_address, a.id, by) for d, a, by in result.pairs) == [
        ("module.classifier.aws_lambda_function.this", "lambda:email2case-classifier", "name"),
        ("module.producer.aws_lambda_function.this", "lambda:email2case-producer", "name"),
    ]
    assert result.terraform_only == [] and result.aws_only == [] and result.ambiguous == []


def test_config_module_instances_merge_with_state_by_address(tmp_path):
    _write(tmp_path, "modules/lambda/main.tf", LAMBDA)
    _write(tmp_path, "main.tf", 'module "one" { source = "./modules/lambda" }\nmodule "two" { source = "./modules/lambda" }\n')
    config = ingest_path(tmp_path)
    state = parse_state_json(
        {
            "values": {
                "root_module": {
                    "child_modules": [
                        {
                            "address": f"module.{m}",
                            "resources": [
                                {
                                    "address": f"module.{m}.aws_lambda_function.this",
                                    "mode": "managed",
                                    "type": "aws_lambda_function",
                                    "name": "this",
                                    "values": {"id": f"fn-{m}", "function_name": f"fn-{m}"},
                                }
                            ],
                        }
                        for m in ("one", "two")
                    ]
                }
            }
        }
    )
    assert _of_type(state, "lambda") == {
        "module.one.aws_lambda_function.this": "lambda:fn-one",
        "module.two.aws_lambda_function.this": "lambda:fn-two",
    }
    merged = combine_config_and_state(config, state)
    assert _of_type(merged, "lambda") == {
        "module.one.aws_lambda_function.this": "lambda:fn-one",
        "module.two.aws_lambda_function.this": "lambda:fn-two",
    }
