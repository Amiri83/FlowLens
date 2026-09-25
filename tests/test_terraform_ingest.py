import json

from flowlens.ingest.terraform import ingest_path, parse_plan_json, parse_state_json
from flowlens.models.graph import RelationshipType, Source


def test_parse_config_dir_produces_nodes(sample_tf_dir):
    graph = ingest_path(sample_tf_dir)
    resource_types = {n.resource_type for n in graph.nodes.values()}
    assert "vpc" in resource_types
    assert "subnet" in resource_types
    assert "alb" in resource_types
    assert "ecs_service" in resource_types
    assert len(graph.nodes) == 15


def test_parse_config_dir_sets_desired_state_and_source(sample_tf_dir):
    graph = ingest_path(sample_tf_dir)
    vpc = next(n for n in graph.nodes.values() if n.resource_type == "vpc")
    assert vpc.source == Source.TERRAFORM
    assert vpc.desired_state["cidr_block"] == "10.0.0.0/16"
    assert vpc.terraform_address == "aws_vpc.main"


def test_parse_config_dir_generic_depends_on_edges(sample_tf_dir):
    graph = ingest_path(sample_tf_dir)
    assert len(graph.edges) > 0
    assert all(e.relationship_type == RelationshipType.DEPENDS_ON for e in graph.edges.values())

    subnet = next(n for n in graph.nodes.values() if n.terraform_address == "aws_subnet.public_a")
    vpc = next(n for n in graph.nodes.values() if n.terraform_address == "aws_vpc.main")
    edge_ids = {(e.source_node, e.target_node) for e in graph.edges.values()}
    assert (subnet.id, vpc.id) in edge_ids


def test_single_tf_file(tmp_path):
    tf_file = tmp_path / "one.tf"
    tf_file.write_text(
        """
        resource "aws_vpc" "solo" {
          cidr_block = "10.9.0.0/16"
        }
        """
    )
    graph = ingest_path(tf_file)
    assert len(graph.nodes) == 1
    node = next(iter(graph.nodes.values()))
    assert node.resource_type == "vpc"
    assert node.desired_state["cidr_block"] == "10.9.0.0/16"


def test_parse_state_json_uses_cloud_id_for_node_id(tmp_path):
    state = {
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_vpc.main",
                        "mode": "managed",
                        "type": "aws_vpc",
                        "name": "main",
                        "values": {"id": "vpc-0abc123", "cidr_block": "10.0.0.0/16", "arn": "arn:aws:ec2:::vpc/vpc-0abc123"},
                    },
                    {
                        "address": "aws_subnet.a",
                        "mode": "managed",
                        "type": "aws_subnet",
                        "name": "a",
                        "values": {"id": "subnet-0xyz", "vpc_id": "vpc-0abc123"},
                    },
                ]
            }
        }
    }
    graph = parse_state_json(state)
    assert "vpc:vpc-0abc123" in graph.nodes
    assert "subnet:subnet-0xyz" in graph.nodes
    subnet = graph.get_node("subnet:subnet-0xyz")
    assert subnet.desired_state["vpc_id"] == "vpc-0abc123"


def test_parse_state_json_child_modules(tmp_path):
    state = {
        "values": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "resources": [
                            {
                                "address": "module.net.aws_vpc.main",
                                "mode": "managed",
                                "type": "aws_vpc",
                                "name": "main",
                                "values": {"id": "vpc-child"},
                            }
                        ]
                    }
                ],
            }
        }
    }
    graph = parse_state_json(state)
    assert "vpc:vpc-child" in graph.nodes


def test_parse_plan_json_uses_after_values():
    plan = {
        "resource_changes": [
            {
                "address": "aws_vpc.main",
                "mode": "managed",
                "type": "aws_vpc",
                "name": "main",
                "change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}},
            }
        ]
    }
    graph = parse_plan_json(plan)
    assert len(graph.nodes) == 1
    node = next(iter(graph.nodes.values()))
    assert node.desired_state["cidr_block"] == "10.0.0.0/16"
    assert node.metadata["change_actions"] == ["create"]


def test_ingest_path_dispatches_on_json_shape(tmp_path):
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_vpc.main",
                        "mode": "managed",
                        "type": "aws_vpc",
                        "name": "main",
                        "change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}},
                    }
                ]
            }
        )
    )
    graph = ingest_path(plan_file)
    assert len(graph.nodes) == 1
