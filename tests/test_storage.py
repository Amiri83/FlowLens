from flowlens.ingest.terraform import ingest_path
from flowlens.linking.linker import link_graph
from flowlens.storage.repository import GraphRepository


def test_save_and_load_roundtrip(tmp_db_path, sample_tf_dir):
    graph = ingest_path(sample_tf_dir)
    link_graph(graph)

    repo = GraphRepository(tmp_db_path)
    try:
        repo.save_graph(graph)
        loaded = repo.load_graph()
    finally:
        repo.close()

    assert len(loaded.nodes) == len(graph.nodes)
    assert len(loaded.edges) == len(graph.edges)
    assert set(loaded.nodes.keys()) == set(graph.nodes.keys())


def test_save_graph_replace_clears_old_data(tmp_db_path):
    from flowlens.models.graph import Graph, Node, Source

    g1 = Graph()
    g1.add_node(Node(id="a", name="a", resource_type="vpc", source=Source.TERRAFORM))
    repo = GraphRepository(tmp_db_path)
    try:
        repo.save_graph(g1)
        assert len(repo.load_graph().nodes) == 1

        g2 = Graph()
        g2.add_node(Node(id="b", name="b", resource_type="vpc", source=Source.TERRAFORM))
        repo.save_graph(g2, replace=True)
        loaded = repo.load_graph()
    finally:
        repo.close()

    assert set(loaded.nodes.keys()) == {"b"}


def test_meta_get_set(tmp_db_path):
    repo = GraphRepository(tmp_db_path)
    try:
        assert repo.get_meta("last_run") is None
        repo.set_meta("last_run", "2026-01-01")
        assert repo.get_meta("last_run") == "2026-01-01"
        repo.set_meta("last_run", "2026-01-02")
        assert repo.get_meta("last_run") == "2026-01-02"
    finally:
        repo.close()
