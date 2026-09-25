from fastapi.testclient import TestClient

from flowlens.api.app import create_app
from flowlens.ingest.terraform import ingest_path
from flowlens.linking.linker import link_graph
from flowlens.storage.repository import GraphRepository


def _seeded_client(tmp_db_path, sample_tf_dir):
    graph = ingest_path(sample_tf_dir)
    link_graph(graph)
    repo = GraphRepository(tmp_db_path)
    try:
        repo.save_graph(graph)
    finally:
        repo.close()
    return TestClient(create_app(tmp_db_path)), graph


def test_get_graph(tmp_db_path, sample_tf_dir):
    client, graph = _seeded_client(tmp_db_path, sample_tf_dir)
    resp = client.get("/api/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodes"]) == len(graph.nodes)
    assert len(data["edges"]) == len(graph.edges)


def test_get_status(tmp_db_path, sample_tf_dir):
    client, graph = _seeded_client(tmp_db_path, sample_tf_dir)
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["node_count"] == len(graph.nodes)
    assert data["edge_count"] == len(graph.edges)


def test_get_node_found_and_not_found(tmp_db_path, sample_tf_dir):
    client, graph = _seeded_client(tmp_db_path, sample_tf_dir)
    node_id = next(iter(graph.nodes.keys()))
    resp = client.get(f"/api/node/{node_id}")
    assert resp.status_code == 200
    assert resp.json()["node"]["id"] == node_id

    resp = client.get("/api/node/does-not-exist")
    assert resp.status_code == 404


def test_get_path(tmp_db_path, sample_tf_dir):
    client, graph = _seeded_client(tmp_db_path, sample_tf_dir)
    vpc = next(n for n in graph.nodes.values() if n.resource_type == "vpc")
    subnet = next(n for n in graph.nodes.values() if n.terraform_address == "aws_subnet.public_a")

    resp = client.get("/api/path", params={"start": vpc.id, "end": subnet.id})
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["nodes"][0] == vpc.id
    assert data["nodes"][-1] == subnet.id


def test_get_path_missing_node(tmp_db_path, sample_tf_dir):
    client, _graph = _seeded_client(tmp_db_path, sample_tf_dir)
    resp = client.get("/api/path", params={"start": "nope", "end": "also-nope"})
    assert resp.status_code == 404


def test_index_serves_ui(tmp_db_path, sample_tf_dir):
    client, _graph = _seeded_client(tmp_db_path, sample_tf_dir)
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"FlowLens" in resp.content
