"""FastAPI app serving the graph API and the Cytoscape.js single-page UI.

No AI/LLM involved anywhere here — this is a thin, deterministic read layer
over the SQLite-backed graph plus a couple of pure graph algorithms
(shortest path, desired-vs-actual compare) from flowlens.graph and
flowlens.compare.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from flowlens.compare.diff import compare_graph, summarize
from flowlens.graph.traversal import resolve_node_ref, shortest_path
from flowlens.storage.repository import GraphRepository

STATIC_DIR = Path(__file__).parent / "static"


class ReachabilityRequest(BaseModel):
    source: str
    destination: str
    protocol: str = "tcp"
    port: str | int | None = None


def create_app(db_path: str | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("FLOWLENS_DB_PATH", "data/flowlens.db")
    app = FastAPI(title="FlowLens", description="Local-first infrastructure visualization", version="0.1.0")
    app.state.db_path = db_path

    def _repo() -> GraphRepository:
        return GraphRepository(app.state.db_path)

    def _load():
        repo = _repo()
        try:
            return repo.load_graph()
        finally:
            repo.close()

    @app.get("/api/graph")
    def get_graph():
        repo = _repo()
        try:
            graph = repo.load_graph()
            return graph.to_dict()
        finally:
            repo.close()

    @app.get("/api/node/{node_id}")
    def get_node(node_id: str):
        repo = _repo()
        try:
            graph = repo.load_graph()
        finally:
            repo.close()
        node = graph.get_node(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail=f"Node not found: {node_id}")
        return {
            "node": node.model_dump(mode="json"),
            "edges": [e.model_dump(mode="json") for e in graph.edges_for(node_id)],
        }

    @app.get("/api/path")
    def get_path(start: str, end: str):
        repo = _repo()
        try:
            graph = repo.load_graph()
        finally:
            repo.close()
        if start not in graph.nodes:
            raise HTTPException(status_code=404, detail=f"Node not found: {start}")
        if end not in graph.nodes:
            raise HTTPException(status_code=404, detail=f"Node not found: {end}")
        path = graph.find_path(start, end)
        if path is None:
            return {"found": False, "nodes": [], "edges": []}
        edge_ids = []
        for a, b in zip(path, path[1:], strict=False):
            for edge in graph.edges.values():
                if {edge.source_node, edge.target_node} == {a, b}:
                    edge_ids.append(edge.id)
                    break
        return {"found": True, "nodes": path, "edges": edge_ids}

    @app.get("/api/paths")
    def get_paths(source: str, target: str, directed: bool = True, max_depth: int | None = None):
        """Deterministic BFS shortest path. `source`/`target` accept a node id,
        terraform address, ARN, cloud id or unique name.
        """
        graph = _load()
        src, dst = resolve_node_ref(graph, source), resolve_node_ref(graph, target)
        if src is None:
            raise HTTPException(status_code=404, detail=f"Node not found: {source}")
        if dst is None:
            raise HTTPException(status_code=404, detail=f"Node not found: {target}")
        result = shortest_path(graph, src, dst, directed=directed, max_depth=max_depth)
        if result is None:
            return {"found": False, "source": src, "target": dst, "directed": directed, "nodes": [], "edges": [], "hops": []}
        return {"source": src, "target": dst, "directed": directed, **result.to_dict()}

    @app.get("/api/reachability/endpoints")
    def get_reachability_endpoints():
        """Resources usable as reachability source/destination (plus 'internet')."""
        from flowlens.reachability.facts import build_facts

        facts = build_facts(_load())
        endpoints = [{"id": "internet", "label": "Internet (0.0.0.0/0)", "kind": "internet"}]
        endpoints += sorted(
            ({"id": ep.node_id, "label": ep.display, "kind": ep.kind} for ep in facts.endpoints.values() if ep.node_id),
            key=lambda e: (e["kind"], e["label"]),
        )
        return {"endpoints": endpoints}

    @app.post("/api/reachability")
    def post_reachability(request: ReachabilityRequest):
        """Deterministic reachability analysis (routes, NACLs, security groups,
        load balancer port transitions). Never mutates anything.
        """
        from flowlens.reachability import EndpointError, ReachabilityEngine

        try:
            result = ReachabilityEngine(_load()).analyze(request.source, request.destination, request.protocol, request.port)
        except (EndpointError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.to_dict()

    @app.get("/api/compare")
    def get_compare():
        results = compare_graph(_load())
        return {"summary": summarize(results), "results": [r.to_dict() for r in results]}

    @app.get("/api/status")
    def get_status():
        repo = _repo()
        try:
            graph = repo.load_graph()
        finally:
            repo.close()
        counts: dict[str, int] = {}
        for node in graph.nodes.values():
            counts[node.status.value] = counts.get(node.status.value, 0) + 1
        return {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "status_counts": counts,
            "aws_scan": graph.metadata.get("aws_scan"),
        }

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def index():
        index_file = STATIC_DIR / "index.html"
        if not index_file.exists():
            raise HTTPException(status_code=404, detail="UI not built")
        return FileResponse(str(index_file))

    return app


app = create_app()
