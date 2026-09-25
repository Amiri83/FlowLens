"""FastAPI app serving the graph API and the Cytoscape.js single-page UI.

No AI/LLM involved anywhere here — this is a thin, deterministic read layer
over the SQLite-backed graph plus a couple of pure graph algorithms
(shortest path) from flowlens.models.graph.Graph.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from flowlens.storage.repository import GraphRepository

STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: Optional[str] = None) -> FastAPI:
    db_path = db_path or os.environ.get("FLOWLENS_DB_PATH", "data/flowlens.db")
    app = FastAPI(title="FlowLens", description="Local-first infrastructure visualization", version="0.1.0")
    app.state.db_path = db_path

    def _repo() -> GraphRepository:
        return GraphRepository(app.state.db_path)

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
        for a, b in zip(path, path[1:]):
            for edge in graph.edges.values():
                if {edge.source_node, edge.target_node} == {a, b}:
                    edge_ids.append(edge.id)
                    break
        return {"found": True, "nodes": path, "edges": edge_ids}

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
        return {"node_count": len(graph.nodes), "edge_count": len(graph.edges), "status_counts": counts}

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
