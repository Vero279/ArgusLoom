"""Discover weighted shortest paths in a directed attack graph.

Dijkstra returns the minimum-cost path, or the K minimum-cost simple paths when requested.
Yen returns K minimum-cost, structurally distinct simple paths.
Both strategies score paths with ``_edge_cost`` and break ties deterministically.
Yen uses SciPy when available and NetworkX as its fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from math import isclose
from typing import Literal

import networkx as nx

from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge

try:
    from scipy.sparse import csr_matrix
    from scipy.sparse.csgraph import yen as scipy_yen
except ImportError:  # pragma: no cover - depends on the installed environment
    csr_matrix = None
    scipy_yen = None


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


def _path_edges(graph: Graph) -> dict[tuple[str, str], GraphEdge]:
    selected: dict[tuple[str, str], GraphEdge] = {}
    node_ids = {node.id for node in graph.nodes}
    for edge in sorted(
        graph.edges,
        key=lambda item: (
            item.source,
            item.target,
            _edge_cost(graph, item),
            item.relation,
        ),
    ):
        if edge.source not in node_ids or edge.target not in node_ids:
            continue
        selected.setdefault((edge.source, edge.target), edge)
    return selected


def _path_signature(path: list[str]) -> frozenset[tuple[str, str]]:
    return frozenset(pairwise(path))


def _networkx_graph(
    graph: Graph,
) -> tuple[nx.DiGraph, dict[tuple[str, str], GraphEdge]]:
    selected_edges = _path_edges(graph)
    network = nx.DiGraph()
    network.add_nodes_from(sorted(node.id for node in graph.nodes))
    for (source, target), edge in sorted(selected_edges.items()):
        network.add_edge(source, target, weight=_edge_cost(graph, edge))
    return network, selected_edges


def _networkx_paths(
    graph: Graph,
    source_id: str,
    target_id: str,
    top_k: int,
    excluded_signatures: set[frozenset[tuple[str, str]]] | None = None,
) -> list[list[str]]:
    network, selected_edges = _networkx_graph(graph)
    candidates: list[tuple[float, tuple[str, ...]]] = []
    seen = set(excluded_signatures or ())
    cutoff: float | None = None
    try:
        paths = nx.shortest_simple_paths(network, source_id, target_id, weight="weight")
        for path in paths:
            node_path = tuple(path)
            signature = _path_signature(list(node_path))
            if signature in seen:
                continue
            score = sum(
                _edge_cost(graph, selected_edges[(source, target)])
                for source, target in pairwise(node_path)
            )
            if (
                cutoff is not None
                and score > cutoff
                and not isclose(score, cutoff, rel_tol=1e-12, abs_tol=1e-12)
            ):
                break
            seen.add(signature)
            candidates.append((score, node_path))
            candidates.sort(key=lambda item: (item[0], item[1]))
            if len(candidates) >= top_k:
                cutoff = candidates[top_k - 1][0]
    except nx.NetworkXNoPath:
        return []

    return [list(path) for _, path in candidates[:top_k]]


def _dijkstra_single_path(
    graph: Graph,
    source_id: str,
    target_id: str,
) -> list[str]:
    network, _ = _networkx_graph(graph)
    forward_distances, _ = nx.single_source_dijkstra(
        network, source_id, weight="weight"
    )
    if target_id not in forward_distances:
        return []
    reverse_distances, _ = nx.single_source_dijkstra(
        network.reverse(copy=False), target_id, weight="weight"
    )

    best_score = forward_distances[target_id]
    path = [source_id]
    visited = {source_id}
    current = source_id
    prefix_score = 0.0
    while current != target_id:
        next_node = next(
            (
                candidate
                for candidate in sorted(network.successors(current))
                if candidate not in visited
                and candidate in reverse_distances
                and isclose(
                    prefix_score
                    + network[current][candidate]["weight"]
                    + reverse_distances[candidate],
                    best_score,
                    rel_tol=1e-12,
                    abs_tol=1e-12,
                )
            ),
            None,
        )
        if next_node is None:
            return []
        prefix_score += network[current][next_node]["weight"]
        path.append(next_node)
        visited.add(next_node)
        current = next_node
    return path


def _scipy_paths(
    graph: Graph,
    source_id: str,
    target_id: str,
    top_k: int,
) -> list[list[str]]:
    node_ids = sorted(node.id for node in graph.nodes)
    node_indices = {node_id: index for index, node_id in enumerate(node_ids)}
    selected_edges = _path_edges(graph)
    weighted_edges = [
        (node_indices[source], node_indices[target], _edge_cost(graph, edge))
        for (source, target), edge in sorted(selected_edges.items())
    ]
    rows = [source for source, _, _ in weighted_edges]
    columns = [target for _, target, _ in weighted_edges]
    values = [weight for _, _, weight in weighted_edges]
    matrix = csr_matrix((values, (rows, columns)), shape=(len(node_ids), len(node_ids)))
    _, predecessors = scipy_yen(
        matrix,
        node_indices[source_id],
        node_indices[target_id],
        K=top_k,
        directed=True,
        return_predecessors=True,
    )

    paths: list[list[str]] = []
    for predecessor_row in predecessors:
        path_indices = [node_indices[target_id]]
        current_index = node_indices[target_id]
        for _ in range(len(node_ids)):
            if current_index == node_indices[source_id]:
                break
            current_index = int(predecessor_row[current_index])
            if current_index < 0 or current_index >= len(node_ids):
                path_indices = []
                break
            path_indices.append(current_index)
        else:
            path_indices = []
        if path_indices and path_indices[-1] == node_indices[source_id]:
            paths.append([node_ids[index] for index in reversed(path_indices)])
    return paths


def find_attack_paths(
    graph: Graph,
    source_id: str,
    target_id: str,
    strategy: Literal["dijkstra", "yen"] = "dijkstra",
    top_k: int = 3,
) -> list[AttackPath]:
    """Return paths from source to target.

    Dijkstra returns the single lowest-cost path. `top_k` is ignored for this strategy.
    Yen returns up to ``top_k`` structurally distinct paths ordered by cost.
    """

    if strategy not in {"dijkstra", "yen"}:
        raise ValueError("strategy must be 'dijkstra' or 'yen'")
    if strategy == "yen" and top_k < 1:
        raise ValueError("top_k must be >= 1")

    node_ids = {node.id for node in graph.nodes}
    if source_id not in node_ids:
        raise NodeNotFound(source_id)
    if target_id not in node_ids:
        raise NodeNotFound(target_id)

    if source_id == target_id:
        return [
            AttackPath(nodes=[source_id], edges=[], score=0.0, mitre_chain=[], length=0)
        ]
    if strategy == "dijkstra":
        node_paths = [_dijkstra_single_path(graph, source_id, target_id)]
        node_paths = [path for path in node_paths if path]
    elif scipy_yen is not None and csr_matrix is not None:
        node_paths = _scipy_paths(graph, source_id, target_id, top_k)
        unique_paths: list[list[str]] = []
        seen_signatures: set[frozenset[tuple[str, str]]] = set()
        for path in node_paths:
            signature = _path_signature(path)
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_paths.append(path)
        node_paths = unique_paths
        if len(node_paths) < top_k:
            node_paths.extend(
                _networkx_paths(
                    graph,
                    source_id,
                    target_id,
                    top_k - len(node_paths),
                    excluded_signatures=seen_signatures,
                )
            )
    else:
        node_paths = _networkx_paths(graph, source_id, target_id, top_k)

    selected_edges = _path_edges(graph)
    result: list[AttackPath] = []
    seen_signatures: set[frozenset[tuple[str, str]]] = set()
    for path_nodes in node_paths:
        signature = _path_signature(path_nodes)
        if strategy == "yen" and signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        path_edges = [
            selected_edges[(source, target)] for source, target in pairwise(path_nodes)
        ]
        score = sum(_edge_cost(graph, edge) for edge in path_edges)
        mitre_chain = [
            str(edge.metadata["mitre_technique"])
            for edge in path_edges
            if edge.metadata.get("mitre_technique") is not None
        ]
        result.append(
            AttackPath(
                nodes=path_nodes,
                edges=path_edges,
                score=float(score),
                mitre_chain=mitre_chain,
                length=len(path_edges),
            )
        )

    result.sort(key=lambda path: (path.score, tuple(path.nodes)))
    return result[:1] if strategy == "dijkstra" else result[:top_k]
