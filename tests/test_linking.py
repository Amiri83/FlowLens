import pytest

from flowlens.ingest.terraform import ingest_path
from flowlens.linking.linker import link_graph
from flowlens.models.graph import Graph, Node, RelationshipType, Source


def _edge_pairs(graph, rel):
    return {(e.source_node, e.target_node) for e in graph.edges.values() if e.relationship_type == rel}


def test_link_graph_sample_terraform(sample_tf_dir):
    graph = ingest_path(sample_tf_dir)
    link_graph(graph)

    def by_addr(addr):
        return next(n for n in graph.nodes.values() if n.terraform_address == addr).id

    vpc = by_addr("aws_vpc.main")
    subnet_a = by_addr("aws_subnet.public_a")
    igw = by_addr("aws_internet_gateway.main")
    alb = by_addr("aws_lb.app")
    listener = by_addr("aws_lb_listener.app")
    tg = by_addr("aws_lb_target_group.app")
    cluster = by_addr("aws_ecs_cluster.main")
    service = by_addr("aws_ecs_service.app")
    sg_alb = by_addr("aws_security_group.alb")

    assert (vpc, subnet_a) in _edge_pairs(graph, RelationshipType.CONTAINS)
    assert (igw, vpc) in _edge_pairs(graph, RelationshipType.ATTACHED_TO)
    assert (listener, alb) in _edge_pairs(graph, RelationshipType.DEPENDS_ON)
    assert (listener, tg) in _edge_pairs(graph, RelationshipType.FORWARDS_TO)
    assert (cluster, service) in _edge_pairs(graph, RelationshipType.CONTAINS)
    assert (service, tg) in _edge_pairs(graph, RelationshipType.TARGETS)
    assert (sg_alb, alb) in _edge_pairs(graph, RelationshipType.ALLOWS)


def test_link_graph_resolves_real_cloud_ids_from_aws_discovery():
    graph = Graph()
    graph.add_node(Node(id="vpc:vpc-1", name="main", resource_type="vpc", source=Source.AWS, actual_state={}))
    graph.add_node(
        Node(
            id="subnet:subnet-1",
            name="a",
            resource_type="subnet",
            source=Source.AWS,
            actual_state={"vpc_id": "vpc-1"},
        )
    )
    link_graph(graph)
    assert ("vpc:vpc-1", "subnet:subnet-1") in _edge_pairs(graph, RelationshipType.CONTAINS)


def test_link_graph_no_edge_for_unresolvable_reference():
    graph = Graph()
    graph.add_node(
        Node(id="subnet:subnet-1", name="a", resource_type="subnet", source=Source.AWS, actual_state={"vpc_id": "vpc-does-not-exist"})
    )
    link_graph(graph)
    assert len(graph.edges) == 0


def test_link_graph_ecs_network_configuration():
    graph = Graph()
    graph.add_node(Node(id="subnet:subnet-1", name="a", resource_type="subnet", source=Source.AWS, actual_state={}))
    graph.add_node(Node(id="security_group:sg-1", name="sg", resource_type="security_group", source=Source.AWS, actual_state={}))
    graph.add_node(
        Node(
            id="ecs_service:svc-1",
            name="svc",
            resource_type="ecs_service",
            source=Source.AWS,
            actual_state={"network_configuration": [{"subnets": ["subnet-1"], "security_groups": ["sg-1"]}]},
        )
    )
    link_graph(graph)
    assert ("ecs_service:svc-1", "subnet:subnet-1") in _edge_pairs(graph, RelationshipType.MEMBER_OF)
    assert ("security_group:sg-1", "ecs_service:svc-1") in _edge_pairs(graph, RelationshipType.ALLOWS)


def _listener_graph(port):
    graph = Graph()
    graph.add_node(Node(id="target_group:tg-1", name="tg", resource_type="target_group", source=Source.AWS, actual_state={}))
    graph.add_node(
        Node(
            id="listener:l-1",
            name="l",
            resource_type="listener",
            source=Source.AWS,
            actual_state={"protocol": "HTTP", "port": port, "default_action": [{"target_group_arn": "tg-1"}]},
        )
    )
    return graph


def _forwards_to(graph):
    return [e for e in graph.edges.values() if e.relationship_type == RelationshipType.FORWARDS_TO]


def test_link_graph_dynamic_listener_port_does_not_crash():
    graph = link_graph(_listener_graph("${tonumber(each.key)}"))
    [edge] = _forwards_to(graph)
    assert (edge.source_node, edge.target_node) == ("listener:l-1", "target_group:tg-1")
    assert edge.protocol == "HTTP"
    assert edge.port is None
    assert edge.metadata["port_raw"] == "${tonumber(each.key)}"


@pytest.mark.parametrize("port", [443, "443"])
def test_link_graph_numeric_listener_port_stays_int(port):
    graph = link_graph(_listener_graph(port))
    [edge] = _forwards_to(graph)
    assert edge.port == 443
    assert isinstance(edge.port, int)
    assert "port_raw" not in edge.metadata


def test_link_graph_terraform_mixed_dynamic_and_numeric_listener_ports(tmp_path):
    (tmp_path / "main.tf").write_text(
        """
resource "aws_lb_target_group" "app" {
  name = "app"
}

resource "aws_lb_listener" "dynamic" {
  port     = "${tonumber(each.key)}"
  protocol = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "https" {
  port     = 443
  protocol = "HTTPS"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
"""
    )
    graph = link_graph(ingest_path(tmp_path))

    by_addr = {n.terraform_address: n.id for n in graph.nodes.values()}
    edges = {e.source_node: e for e in _forwards_to(graph)}
    dynamic = edges[by_addr["aws_lb_listener.dynamic"]]
    https = edges[by_addr["aws_lb_listener.https"]]
    assert dynamic.target_node == https.target_node == by_addr["aws_lb_target_group.app"]
    assert dynamic.port is None
    assert dynamic.metadata["port_raw"] == "${tonumber(each.key)}"
    assert https.port == 443
