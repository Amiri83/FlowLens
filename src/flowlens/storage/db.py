"""SQLite connection management and schema for the local graph/cache store."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    source TEXT NOT NULL,
    terraform_address TEXT,
    aws_arn TEXT,
    region TEXT,
    account_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    desired_state TEXT,
    actual_state TEXT,
    status TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    source_node TEXT NOT NULL,
    target_node TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    protocol TEXT,
    port INTEGER,
    direction TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL,
    FOREIGN KEY (source_node) REFERENCES nodes (id),
    FOREIGN KEY (target_node) REFERENCES nodes (id)
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON edges (source_node);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges (target_node);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes (resource_type);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
