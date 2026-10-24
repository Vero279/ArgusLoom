"""Attack path discovery and scoring utilities."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge


@dataclass(slots=True)
class AttackPath:
    nodes: list[str]
    edges: list[GraphEdge]
    score: float
    mitre_chain: list[str]
    length: int


def _edge_cost(graph: Graph, edge: GraphEdge) -> float:
    by_id = {node.id: node for node in graph.nodes}
    source = by_id.get(edge.source)
    target = by_id.get(edge.target)
    if source is None or target is None:
        return 1.0

    exposure_term = (
        getattr(source, "cvss_max", 0.0) * float(getattr(target, "exposure", 0.0))
    ) + 0.1
    base = 1.0 / max(0.1, exposure_term)
    if edge.metadata.get("mitre_technique") is not None:
        base *= 0.8
    if edge.relation in {"iam", "network", "lateral"}:
        base *= 0.9
    return float(base)


def _sorted_paths(
    graph: Graph, source_id: str, target_id: str
) -> list[tuple[list[str], list[GraphEdge]]]:
    adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in sorted(
        graph.edges, key=lambda item: (item.source, item.target, item.relation)
    ):
        adjacency[edge.source].append(edge)

    results: list[tuple[list[str], list[GraphEdge]]] = []

    def dfs(
        current_id: str,
        path_nodes: list[str],
        path_edges: list[GraphEdge],
        seen: set[str],
    ) -> None:
        if current_id == target_id:
            results.append((list(path_nodes), list(path_edges)))
            return

        for edge in sorted(
            adjacency.get(current_id, []), key=lambda item: (item.target, item.relation)
        ):
            if edge.target in seen:
                continue
            seen.add(edge.target)
            path_nodes.append(edge.target)
            path_edges.append(edge)
            dfs(edge.target, path_nodes, path_edges, seen)
            path_nodes.pop()
            path_edges.pop()
            seen.remove(edge.target)

    dfs(source_id, [source_id], [], {source_id})
    return results


def find_attack_paths(
    graph: Graph,
    source_id: str,
    target_id: str,
    strategy: Literal["dijkstra", "bfs"] = "dijkstra",
    top_k: int = 3,
) -> list[AttackPath]:
    """Return ordered attack paths seeded at the source and ending at the target."""

    node_ids = {node.id for node in graph.nodes}
    if source_id not in node_ids:
        raise NodeNotFound(source_id)
    if target_id not in node_ids:
        raise NodeNotFound(target_id)

    if source_id == target_id:
        return [
            AttackPath(nodes=[source_id], edges=[], score=0.0, mitre_chain=[], length=0)
        ]

    paths = _sorted_paths(graph, source_id, target_id)
    if not paths:
        return []

    scored: list[tuple[float, tuple[str, ...], list[GraphEdge]]] = []
    for path_nodes, path_edges in paths:
        score = sum(_edge_cost(graph, edge) for edge in path_edges)
        if strategy == "bfs":
            score = float(len(path_edges))
        scored.append((score, tuple(path_nodes), path_edges))

    scored.sort(
        key=lambda item: (
            item[0],
            tuple(node for node in item[1]),
        )
    )
    result: list[AttackPath] = []
    seen_paths: set[tuple[str, ...]] = set()
    for score, path_nodes, path_edges in scored[:top_k]:
        key = tuple(path_nodes)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        mitre_chain = [
            str(edge.metadata["mitre_technique"])
            for edge in path_edges
            if edge.metadata.get("mitre_technique") is not None
        ]
        result.append(
            AttackPath(
                nodes=list(path_nodes),
                edges=list(path_edges),
                score=float(score),
                mitre_chain=mitre_chain,
                length=len(path_edges),
            )
        )

    return result
