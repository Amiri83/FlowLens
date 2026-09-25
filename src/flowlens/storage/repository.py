"""DAO layer over SQLite for persisting and reloading a Graph."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from flowlens.models.graph import Edge, Graph, Node
from flowlens.storage.db import connect


class GraphRepository:
    def __init__(self, db_path: str | Path):
        self.db_path = db_path
        self.conn: sqlite3.Connection = connect(db_path)

    def close(self) -> None:
        self.conn.close()

    def clear(self) -> None:
        self.conn.execute("DELETE FROM edges")
        self.conn.execute("DELETE FROM nodes")
        self.conn.commit()

    def save_graph(self, graph: Graph, *, replace: bool = True) -> None:
        if replace:
            self.clear()
        cur = self.conn.cursor()
        for node in graph.nodes.values():
            cur.execute(
                """
                INSERT INTO nodes (id, name, resource_type, provider, source, terraform_address,
                                    aws_arn, region, account_id, metadata, desired_state, actual_state, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, resource_type=excluded.resource_type, provider=excluded.provider,
                    source=excluded.source, terraform_address=excluded.terraform_address, aws_arn=excluded.aws_arn,
                    region=excluded.region, account_id=excluded.account_id, metadata=excluded.metadata,
                    desired_state=excluded.desired_state, actual_state=excluded.actual_state, status=excluded.status
                """,
                (
                    node.id,
                    node.name,
                    node.resource_type,
                    node.provider,
                    node.source.value,
                    node.terraform_address,
                    node.aws_arn,
                    node.region,
                    node.account_id,
                    json.dumps(node.metadata),
                    json.dumps(node.desired_state) if node.desired_state is not None else None,
                    json.dumps(node.actual_state) if node.actual_state is not None else None,
                    node.status.value,
                ),
            )
        for edge in graph.edges.values():
            cur.execute(
                """
                INSERT INTO edges (id, source_node, target_node, relationship_type, protocol, port,
                                    direction, metadata, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source_node=excluded.source_node, target_node=excluded.target_node,
                    relationship_type=excluded.relationship_type, protocol=excluded.protocol,
                    port=excluded.port, direction=excluded.direction, metadata=excluded.metadata,
                    source=excluded.source
                """,
                (
                    edge.id,
                    edge.source_node,
                    edge.target_node,
                    edge.relationship_type.value,
                    edge.protocol,
                    edge.port,
                    edge.direction,
                    json.dumps(edge.metadata),
                    edge.source.value,
                ),
            )
        self.conn.commit()

    def load_graph(self) -> Graph:
        graph = Graph()
        for row in self.conn.execute("SELECT * FROM nodes"):
            graph.nodes[row["id"]] = Node(
                id=row["id"],
                name=row["name"],
                resource_type=row["resource_type"],
                provider=row["provider"],
                source=row["source"],
                terraform_address=row["terraform_address"],
                aws_arn=row["aws_arn"],
                region=row["region"],
                account_id=row["account_id"],
                metadata=json.loads(row["metadata"] or "{}"),
                desired_state=json.loads(row["desired_state"]) if row["desired_state"] else None,
                actual_state=json.loads(row["actual_state"]) if row["actual_state"] else None,
                status=row["status"],
            )
        for row in self.conn.execute("SELECT * FROM edges"):
            graph.edges[row["id"]] = Edge(
                id=row["id"],
                source_node=row["source_node"],
                target_node=row["target_node"],
                relationship_type=row["relationship_type"],
                protocol=row["protocol"],
                port=row["port"],
                direction=row["direction"],
                metadata=json.loads(row["metadata"] or "{}"),
                source=row["source"],
            )
        return graph

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
