"""Blast-radius analysis for graph-based risk propagation."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from argusloom.analysis.threat_model import ThreatFinding
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode


@dataclass(slots=True)
class BlastRadiusResult:
    root_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    depth_map: dict[str, int]
    risk_score: float
    max_depth: int


def compute_blast_radius(
    graph: Graph,
    findings: list[ThreatFinding],
    node_id: str,
    max_depth: int = 3,
    weighted: bool = True,
) -> BlastRadiusResult:
    """Compute reachable graph nodes and aggregate risk from a root node."""

    graph_nodes = {node.id: node for node in graph.nodes}
    if node_id not in graph_nodes:
        raise NodeNotFound(node_id)

    adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in sorted(
        graph.edges, key=lambda item: (item.source, item.target, item.relation)
    ):
        adjacency[edge.source].append(edge)

    findings_by_id = {finding.node_id: finding for finding in findings}
    depth_map: dict[str, int] = {node_id: 0}
    queue: deque[tuple[str, int]] = deque([(node_id, 0)])
    seen: set[str] = {node_id}

    while queue:
        current_id, current_depth = queue.popleft()
        if current_depth >= max_depth:
            continue
        for edge in sorted(
            adjacency.get(current_id, []), key=lambda item: (item.target, item.relation)
        ):
            if edge.target in seen:
                continue
            seen.add(edge.target)
            depth_map[edge.target] = current_depth + 1
            queue.append((edge.target, current_depth + 1))

    ordered_nodes = [
        graph_nodes[node_key]
        for node_key in sorted(depth_map, key=lambda key: (depth_map[key], key))
    ]
    ordered_edges = [
        edge
        for edge in sorted(
            graph.edges, key=lambda item: (item.source, item.target, item.relation)
        )
        if edge.source in depth_map and edge.target in depth_map
    ]

    total_risk = 0.0
    for node_key, depth in depth_map.items():
        finding = findings_by_id.get(node_key)
        risk = finding.risk_score if finding is not None else 0.0
        if weighted:
            total_risk += risk * (0.7**depth)
        else:
            total_risk += risk

    return BlastRadiusResult(
        root_id=node_id,
        nodes=ordered_nodes,
        edges=ordered_edges,
        depth_map=depth_map,
        risk_score=round(total_risk, 4),
        max_depth=max(depth_map.values(), default=0),
    )
