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
