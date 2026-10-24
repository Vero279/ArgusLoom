"""Core graph and node representations used by the ingestion pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from argusloom.domain.enums import Criticality, NodeKind, StrideCategory


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str = "depends_on"
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class GraphNode:
    id: str
    kind: NodeKind
    name: str
    source: str
    criticality: Criticality = Criticality.LOW
    exposure: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    stride: list[StrideCategory] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    cvss_max: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "name": self.name,
            "source": self.source,
            "criticality": self.criticality.value,
            "exposure": self.exposure,
            "metadata": self.metadata,
            "stride": [item.value for item in self.stride],
            "cves": list(self.cves),
            "mitre_techniques": list(self.mitre_techniques),
            "cvss_max": self.cvss_max,
        }


@dataclass(slots=True)
class Graph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def add_node(self, node: GraphNode) -> None:
        if not any(existing.id == node.id for existing in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        if not any(
            existing.source == edge.source
            and existing.target == edge.target
            and existing.relation == edge.relation
            for existing in self.edges
        ):
            self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }
