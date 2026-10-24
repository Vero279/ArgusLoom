"""Graph persistence helpers for JSON-backed graph storage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import structlog

from argusloom.domain.enums import Criticality, NodeKind, StrideCategory
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode

logger = structlog.get_logger()


class GraphStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Graph:
        logger.info("graph_store.load", path=str(self.path))
        if not self.exists():
            raise FileNotFoundError(f"Graph store not found: {self.path}")

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        nodes: list[GraphNode] = []
        for item in payload.get("nodes", []):
            stride = []
            for raw_stride in item.get("stride", []):
                try:
                    stride.append(StrideCategory(str(raw_stride)))
                except ValueError:
                    continue

            nodes.append(
                GraphNode(
                    id=str(item["id"]),
                    kind=NodeKind(str(item.get("kind", "compute")).strip().lower()),
                    name=str(item.get("name", item["id"])),
                    source=str(item.get("source", "manual")),
                    criticality=Criticality(
                        str(item.get("criticality", "low")).strip().lower()
                    ),
                    exposure=float(item.get("exposure", 0.0)),
                    metadata=dict(item.get("metadata", {}) or {}),
                    stride=stride,
                    cves=list(item.get("cves", []) or []),
                    mitre_techniques=list(item.get("mitre_techniques", []) or []),
                    cvss_max=float(item.get("cvss_max", 0.0)),
                )
            )

        edges: list[GraphEdge] = []
        for item in payload.get("edges", []):
            edges.append(
                GraphEdge(
                    source=str(item["source"]),
                    target=str(item["target"]),
                    relation=str(item.get("relation", "depends_on")),
                    confidence=float(item.get("confidence", 1.0)),
                    metadata=dict(item.get("metadata", {}) or {}),
                )
            )

        logger.info("graph_store.loaded", node_count=len(nodes), edge_count=len(edges))
        return Graph(nodes=nodes, edges=edges)

    def save(self, graph: Graph) -> None:
        self.path.write_text(json.dumps(graph.to_dict(), indent=2), encoding="utf-8")
        logger.info(
            "graph_store.saved",
            path=str(self.path),
            node_count=len(graph.nodes),
            edge_count=len(graph.edges),
        )

    def exists(self) -> bool:
        return self.path.exists()

    def get_node(self, graph: Graph, node_id: str) -> GraphNode:
        for node in graph.nodes:
            if node.id == node_id:
                return node
        raise NodeNotFound(node_id)

    def get_neighbors(
        self,
        graph: Graph,
        node_id: str,
        direction: Literal["out", "in", "both"] = "out",
    ) -> list[GraphEdge]:
        neighbors: list[GraphEdge] = []
        for edge in graph.edges:
            is_out = edge.source == node_id
            is_in = edge.target == node_id
            if (
                direction == "out"
                and is_out
                or direction == "in"
                and is_in
                or direction == "both"
                and (is_out or is_in)
            ):
                neighbors.append(edge)
        return sorted(
            neighbors, key=lambda edge: (edge.source, edge.target, edge.relation)
        )

    def get_subgraph(self, graph: Graph, node_ids: set[str]) -> Graph:
        subgraph_nodes = [node for node in graph.nodes if node.id in node_ids]
        subgraph_edges = [
            edge
            for edge in graph.edges
            if edge.source in node_ids and edge.target in node_ids
        ]
        return Graph(nodes=subgraph_nodes, edges=subgraph_edges)
