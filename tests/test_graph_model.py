from flowlens.models.graph import Edge, Graph, Node, RelationshipType, ResourceStatus, Source


def make_node(node_id, source=Source.TERRAFORM, **kwargs):
    return Node(id=node_id, name=node_id, resource_type="vpc", source=source, **kwargs)


def test_add_node_new():
    graph = Graph()
    node = make_node("vpc:1", desired_state={"cidr_block": "10.0.0.0/16"})
    graph.add_node(node)
    assert graph.get_node("vpc:1") is not None
    assert graph.get_node("vpc:1").status == ResourceStatus.DESIRED_ONLY


def test_add_node_merges_terraform_and_aws():
    graph = Graph()
    graph.add_node(make_node("vpc:1", source=Source.TERRAFORM, desired_state={"cidr_block": "10.0.0.0/16"}))
    graph.add_node(make_node("vpc:1", source=Source.AWS, actual_state={"cidr_block": "10.0.0.0/16"}))

    merged = graph.get_node("vpc:1")
    assert merged.source == Source.MERGED
    assert merged.desired_state == {"cidr_block": "10.0.0.0/16"}
    assert merged.actual_state == {"cidr_block": "10.0.0.0/16"}
    assert merged.status == ResourceStatus.OK
    assert len(graph.nodes) == 1


def test_node_status_desired_only():
    graph = Graph()
    graph.add_node(make_node("vpc:1", source=Source.TERRAFORM, desired_state={"cidr_block": "10.0.0.0/16"}))
    assert graph.get_node("vpc:1").status == ResourceStatus.DESIRED_ONLY


def test_merge_two_graphs_dedups_nodes():
    g1 = Graph()
    g1.add_node(make_node("vpc:1", source=Source.TERRAFORM, desired_state={"cidr_block": "10.0.0.0/16"}))
    g2 = Graph()
    g2.add_node(make_node("vpc:1", source=Source.AWS, actual_state={"cidr_block": "10.0.0.0/16"}))
    g2.add_node(make_node("vpc:2", source=Source.AWS, actual_state={"cidr_block": "10.1.0.0/16"}))

    merged = g1.merge(g2)
    assert len(merged.nodes) == 2
    assert merged.get_node("vpc:1").status == ResourceStatus.OK
    assert merged.get_node("vpc:2").status == ResourceStatus.ACTUAL_ONLY


def test_find_path_simple_chain():
    graph = Graph()
    for nid in ["a", "b", "c", "d"]:
        graph.add_node(make_node(nid))
    graph.add_edge(Edge(id="a-b", source_node="a", target_node="b", relationship_type=RelationshipType.CONTAINS))
    graph.add_edge(Edge(id="b-c", source_node="b", target_node="c", relationship_type=RelationshipType.CONTAINS))
    graph.add_edge(Edge(id="c-d", source_node="c", target_node="d", relationship_type=RelationshipType.CONTAINS))

    path = graph.find_path("a", "d")
    assert path == ["a", "b", "c", "d"]


def test_find_path_undirected():
    graph = Graph()
    for nid in ["a", "b"]:
        graph.add_node(make_node(nid))
    graph.add_edge(Edge(id="a-b", source_node="a", target_node="b", relationship_type=RelationshipType.CONTAINS))
    assert graph.find_path("b", "a") == ["b", "a"]


def test_find_path_unreachable():
    graph = Graph()
    graph.add_node(make_node("a"))
    graph.add_node(make_node("b"))
    assert graph.find_path("a", "b") is None


def test_find_path_missing_node():
    graph = Graph()
    graph.add_node(make_node("a"))
    assert graph.find_path("a", "missing") is None


def test_find_path_same_node():
    graph = Graph()
    graph.add_node(make_node("a"))
    assert graph.find_path("a", "a") == ["a"]


def test_to_dict_from_dict_roundtrip():
    graph = Graph()
    graph.add_node(make_node("vpc:1", desired_state={"cidr_block": "10.0.0.0/16"}))
    graph.add_edge(Edge(id="e1", source_node="vpc:1", target_node="vpc:1", relationship_type=RelationshipType.CONTAINS))

    data = graph.to_dict()
    restored = Graph.from_dict(data)
    assert set(restored.nodes.keys()) == {"vpc:1"}
    assert set(restored.edges.keys()) == {"e1"}
