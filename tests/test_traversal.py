from flowlens.graph.traversal import resolve_node_ref, shortest_path
from flowlens.models.graph import Edge, Graph, Node, RelationshipType


def _graph(edges: list[tuple[str, str, RelationshipType]], extra_nodes: tuple[str, ...] = ()) -> Graph:
    g = Graph()
    ids = {n for a, b, _ in edges for n in (a, b)} | set(extra_nodes)
    for node_id in sorted(ids):
        g.add_node(Node(id=node_id, name=node_id.split(":", 1)[-1], resource_type=node_id.split(":", 1)[0]))
    for a, b, rel in edges:
        g.add_edge(Edge(id=f"{a}->{b}:{rel.value}", source_node=a, target_node=b, relationship_type=rel))
    return g


# listener -> tg -> vpc, plus a longer detour listener -> alb -> subnet -> vpc
MOCK = _graph(
    [
        ("listener:l1", "target_group:tg1", RelationshipType.FORWARDS_TO),
        ("target_group:tg1", "vpc:v1", RelationshipType.MEMBER_OF),
        ("listener:l1", "alb:a1", RelationshipType.DEPENDS_ON),
        ("alb:a1", "subnet:s1", RelationshipType.MEMBER_OF),
        ("subnet:s1", "vpc:v1", RelationshipType.MEMBER_OF),
    ],
    extra_nodes=("lambda:isolated",),
)


def test_path_found_is_shortest():
    result = shortest_path(MOCK, "listener:l1", "vpc:v1")
    assert result is not None
    assert result.nodes == ["listener:l1", "target_group:tg1", "vpc:v1"]
    assert result.edge_ids == ["listener:l1->target_group:tg1:forwards_to", "target_group:tg1->vpc:v1:member_of"]
    assert [s.reversed for s in result.steps] == [False, False]


def test_path_not_found_for_disconnected_node():
    assert shortest_path(MOCK, "listener:l1", "lambda:isolated") is None
    assert shortest_path(MOCK, "listener:l1", "lambda:isolated", directed=False) is None


def test_path_missing_endpoint_returns_none():
    assert shortest_path(MOCK, "listener:l1", "vpc:does-not-exist") is None


def test_directionality_respected():
    # vpc has no outgoing edges, so nothing is reachable from it when directed...
    assert shortest_path(MOCK, "vpc:v1", "listener:l1") is None
    # ...but the reverse walk exists when direction is ignored.
    result = shortest_path(MOCK, "vpc:v1", "listener:l1", directed=False)
    assert result is not None
    assert result.nodes[0] == "vpc:v1" and result.nodes[-1] == "listener:l1"
    assert all(step.reversed for step in result.steps)


def test_same_node_is_zero_hop_path():
    result = shortest_path(MOCK, "alb:a1", "alb:a1")
    assert result is not None and result.nodes == ["alb:a1"] and result.steps == []


def test_deterministic_tie_break_independent_of_insertion_order():
    edges = [
        ("a:1", "b:2", RelationshipType.CONTAINS),
        ("a:1", "b:1", RelationshipType.CONTAINS),
        ("b:1", "c:1", RelationshipType.CONTAINS),
        ("b:2", "c:1", RelationshipType.CONTAINS),
    ]
    forward = shortest_path(_graph(edges), "a:1", "c:1")
    backward = shortest_path(_graph(list(reversed(edges))), "a:1", "c:1")
    assert forward.nodes == backward.nodes == ["a:1", "b:1", "c:1"]


def test_semantic_edge_preferred_over_depends_on():
    g = _graph(
        [
            ("listener:l1", "target_group:tg1", RelationshipType.DEPENDS_ON),
            ("listener:l1", "target_group:tg1", RelationshipType.FORWARDS_TO),
        ]
    )
    result = shortest_path(g, "listener:l1", "target_group:tg1")
    assert result.steps[0].edge.relationship_type == RelationshipType.FORWARDS_TO


def test_relationship_filter_and_max_depth():
    assert shortest_path(MOCK, "listener:l1", "vpc:v1", relationship_types=["depends_on", "member_of"]).nodes == [
        "listener:l1",
        "alb:a1",
        "subnet:s1",
        "vpc:v1",
    ]
    assert shortest_path(MOCK, "listener:l1", "vpc:v1", max_depth=1) is None
    assert shortest_path(MOCK, "listener:l1", "vpc:v1", max_depth=2) is not None


def test_resolve_node_ref():
    g = _graph([("vpc:vpc-123", "subnet:subnet-1", RelationshipType.CONTAINS)])
    g.nodes["vpc:vpc-123"].terraform_address = "aws_vpc.main"
    assert resolve_node_ref(g, "vpc:vpc-123") == "vpc:vpc-123"
    assert resolve_node_ref(g, "aws_vpc.main") == "vpc:vpc-123"
    assert resolve_node_ref(g, "subnet-1") == "subnet:subnet-1"
    assert resolve_node_ref(g, "nope") is None
