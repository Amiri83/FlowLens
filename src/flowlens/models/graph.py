"""Core graph data model shared by ingesters, discoverers, storage, and the API.

Kept deliberately provider-agnostic: a Node/Edge here doesn't know whether it
came from Terraform or AWS discovery, only that it carries a `source` tag and
optional `desired_state` / `actual_state` payloads so callers can diff them.
"""
from __future__ import annotations

from collections import deque
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Source(str, Enum):
    TERRAFORM = "terraform"
    AWS = "aws"
    MERGED = "merged"


class ResourceStatus(str, Enum):
    OK = "ok"
    DESIRED_ONLY = "desired_only"  # in Terraform but not observed in AWS
    ACTUAL_ONLY = "actual_only"  # observed in AWS but not in Terraform
    DRIFTED = "drifted"  # present in both but attributes disagree
    UNKNOWN = "unknown"


class RelationshipType(str, Enum):
    CONTAINS = "contains"
    ROUTES_TO = "routes_to"
    TARGETS = "targets"
    ALLOWS = "allows"
    ATTACHED_TO = "attached_to"
    MEMBER_OF = "member_of"
    INVOKES = "invokes"
    INTEGRATES_WITH = "integrates_with"
    FORWARDS_TO = "forwards_to"
    DEPENDS_ON = "depends_on"
    RESOLVES_TO = "resolves_to"
    ASSOCIATED_WITH = "associated_with"


def _compute_status(desired: Optional[dict[str, Any]], actual: Optional[dict[str, Any]]) -> ResourceStatus:
    if desired is not None and actual is not None:
        return ResourceStatus.OK
    if desired is not None:
        return ResourceStatus.DESIRED_ONLY
    if actual is not None:
        return ResourceStatus.ACTUAL_ONLY
    return ResourceStatus.UNKNOWN


class Node(BaseModel):
    id: str
    name: str
    resource_type: str
    provider: str = "aws"
    source: Source = Source.MERGED
    terraform_address: Optional[str] = None
    aws_arn: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    desired_state: Optional[dict[str, Any]] = None
    actual_state: Optional[dict[str, Any]] = None
    status: ResourceStatus = ResourceStatus.UNKNOWN

    def merge(self, other: "Node") -> "Node":
        """Combine this node with another representation of the same resource.

        Used to reconcile a Terraform-sourced node with an AWS-discovered node
        that refer to the same real-world resource (matched by id/arn upstream
        in the linker). Terraform contributes desired_state, AWS contributes
        actual_state; status is derived from which sides are present.
        """
        desired = self.desired_state if self.source == Source.TERRAFORM else other.desired_state
        actual = self.actual_state if self.source == Source.AWS else other.actual_state
        desired = desired or (other.desired_state if other.source == Source.TERRAFORM else self.desired_state)
        actual = actual or (other.actual_state if other.source == Source.AWS else self.actual_state)

        status = _compute_status(desired, actual)

        merged_metadata = {**other.metadata, **self.metadata}
        return Node(
            id=self.id,
            name=self.name or other.name,
            resource_type=self.resource_type or other.resource_type,
            provider=self.provider or other.provider,
            source=Source.MERGED,
            terraform_address=self.terraform_address or other.terraform_address,
            aws_arn=self.aws_arn or other.aws_arn,
            region=self.region or other.region,
            account_id=self.account_id or other.account_id,
            metadata=merged_metadata,
            desired_state=desired,
            actual_state=actual,
            status=status,
        )


class Edge(BaseModel):
    id: str
    source_node: str
    target_node: str
    relationship_type: RelationshipType
    protocol: Optional[str] = None
    port: Optional[int] = None
    direction: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: Source = Source.MERGED


class Graph(BaseModel):
    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: dict[str, Edge] = Field(default_factory=dict)

    def add_node(self, node: Node) -> Node:
        """Insert a node, merging with any existing node sharing the same id.

        Status is (re)computed from desired/actual presence on every insert,
        not just when merging two sources, so a single AWS-only or
        Terraform-only node still gets a meaningful status.
        """
        existing = self.nodes.get(node.id)
        if existing is not None and existing.source != node.source:
            node = node.merge(existing)
        else:
            node = node.model_copy(update={"status": _compute_status(node.desired_state, node.actual_state)})
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> Edge:
        self.edges[edge.id] = edge
        return edge

    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def neighbors(self, node_id: str) -> list[tuple[Edge, str]]:
        """Return (edge, other_node_id) pairs for edges touching node_id, undirected."""
        result = []
        for edge in self.edges.values():
            if edge.source_node == node_id:
                result.append((edge, edge.target_node))
            elif edge.target_node == node_id:
                result.append((edge, edge.source_node))
        return result

    def edges_for(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges.values() if e.source_node == node_id or e.target_node == node_id]

    def find_path(self, start_id: str, end_id: str) -> Optional[list[str]]:
        """Breadth-first shortest path between two node ids, treating edges as undirected.

        Returns a list of node ids from start to end (inclusive), or None if
        unreachable or either endpoint is missing.
        """
        if start_id not in self.nodes or end_id not in self.nodes:
            return None
        if start_id == end_id:
            return [start_id]

        visited = {start_id}
        queue: deque[list[str]] = deque([[start_id]])
        while queue:
            path = queue.popleft()
            current = path[-1]
            for _edge, other in self.neighbors(current):
                if other in visited:
                    continue
                new_path = path + [other]
                if other == end_id:
                    return new_path
                visited.add(other)
                queue.append(new_path)
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.model_dump(mode="json") for n in self.nodes.values()],
            "edges": [e.model_dump(mode="json") for e in self.edges.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Graph":
        graph = cls()
        for n in data.get("nodes", []):
            graph.add_node(Node.model_validate(n))
        for e in data.get("edges", []):
            graph.add_edge(Edge.model_validate(e))
        return graph

    def merge(self, other: "Graph") -> "Graph":
        """Merge another graph into a new graph, deduping nodes by id via Node.merge."""
        result = Graph()
        for node in self.nodes.values():
            result.add_node(node)
        for node in other.nodes.values():
            result.add_node(node)
        for edge in self.edges.values():
            result.add_edge(edge)
        for edge in other.edges.values():
            result.add_edge(edge)
        return result
