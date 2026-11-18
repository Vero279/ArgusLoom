from pathlib import Path

import pytest

from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.graph.pathfinding import (
    find_attack_path_through_waypoints,
    find_attack_paths,
)
from argusloom.graph.store import GraphStore


def _graph_linear() -> Graph:
    return Graph(
        nodes=[
            GraphNode(
                id="A",
                kind=NodeKind.COMPUTE,
                name="A",
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.6,
                cvss_max=5.0,
            ),
            GraphNode(
                id="B",
                kind=NodeKind.NETWORK,
                name="B",
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.8,
                cvss_max=8.0,
            ),
            GraphNode(
                id="C",
                kind=NodeKind.DATA,
                name="C",
                source="fixture",
                criticality=Criticality.CRITICAL,
                exposure=0.9,
                cvss_max=9.0,
            ),
        ],
        edges=[
            GraphEdge(
                source="A",
                target="B",
                relation="depends_on",
                metadata={"mitre_technique": "T1078"},
            ),
            GraphEdge(source="B", target="C", relation="depends_on"),
        ],
    )


def _graph_branching() -> Graph:
    return Graph(
        nodes=[
            GraphNode(
                id="A",
                kind=NodeKind.COMPUTE,
                name="A",
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.6,
                cvss_max=5.0,
            ),
            GraphNode(
                id="B",
                kind=NodeKind.NETWORK,
                name="B",
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.8,
                cvss_max=8.0,
            ),
            GraphNode(
                id="C",
                kind=NodeKind.DATA,
                name="C",
                source="fixture",
                criticality=Criticality.CRITICAL,
                exposure=0.9,
                cvss_max=9.0,
            ),
            GraphNode(
                id="D",
                kind=NodeKind.EXTERNAL,
                name="D",
                source="fixture",
                criticality=Criticality.LOW,
                exposure=0.4,
                cvss_max=3.0,
            ),
        ],
        edges=[
            GraphEdge(
                source="A",
                target="B",
                relation="depends_on",
                metadata={"mitre_technique": "T1078"},
            ),
            GraphEdge(source="B", target="C", relation="depends_on"),
            GraphEdge(source="A", target="D", relation="network"),
            GraphEdge(source="D", target="C", relation="depends_on"),
        ],
    )


def test_find_attack_paths_linear_graph_returns_single_path() -> None:
    paths = find_attack_paths(_graph_linear(), "A", "C", strategy="dijkstra")

    assert len(paths) == 1
    assert paths[0].length == 2
    assert paths[0].nodes == ["A", "B", "C"]


def test_find_attack_paths_prefers_less_cost_route() -> None:
    graph = _graph_branching()

    paths = find_attack_paths(graph, "A", "C", strategy="dijkstra")

    assert paths[0].nodes == ["A", "B", "C"]


def test_find_attack_paths_yen_returns_distinct_alternatives() -> None:
    graph = _graph_branching()

    paths = find_attack_paths(graph, "A", "C", strategy="yen", top_k=2)

    assert len(paths) == 2
    first_edges = {(edge.source, edge.target) for edge in paths[0].edges}
    second_edges = {(edge.source, edge.target) for edge in paths[1].edges}
    assert first_edges - second_edges
    assert second_edges - first_edges


def test_dijkstra_ignores_top_k_and_returns_one_path() -> None:
    graph = _graph_branching()

    paths = find_attack_paths(graph, "A", "C", strategy="dijkstra", top_k=5)

    assert len(paths) == 1
    assert paths[0].nodes == ["A", "B", "C"]


def test_yen_rejects_invalid_top_k() -> None:
    with pytest.raises(ValueError, match="top_k must be >= 1"):
        find_attack_paths(_graph_branching(), "A", "C", strategy="yen", top_k=0)


def test_find_attack_paths_with_no_route_returns_empty_list() -> None:
    graph = Graph(
        nodes=[
            GraphNode(id="A", kind=NodeKind.COMPUTE, name="A", source="fixture"),
            GraphNode(id="B", kind=NodeKind.DATA, name="B", source="fixture"),
        ],
        edges=[],
    )

    assert find_attack_paths(graph, "A", "B") == []


def test_find_attack_paths_source_equals_target_is_trivial() -> None:
    graph = _graph_linear()

    paths = find_attack_paths(graph, "A", "A")

    assert len(paths) == 1
    assert paths[0].nodes == ["A"]
    assert paths[0].score == 0.0
    assert paths[0].length == 0


def test_find_attack_paths_unknown_source_raises() -> None:
    try:
        find_attack_paths(_graph_branching(), "missing", "C")
        raise AssertionError("Expected NodeNotFound")
    except NodeNotFound as exc:
        assert str(exc) == "Node 'missing' not found"


def test_find_attack_paths_returns_distinct_paths() -> None:
    graph = Graph(
        nodes=[
            GraphNode(id=node_id, kind=NodeKind.COMPUTE, name=node_id, source="fixture")
            for node_id in ("A", "B", "C", "D")
        ],
        edges=[
            GraphEdge(source="A", target="B"),
            GraphEdge(source="B", target="D"),
            GraphEdge(source="A", target="C"),
            GraphEdge(source="C", target="D"),
            GraphEdge(source="B", target="C"),
        ],
    )

    paths = find_attack_paths(graph, "A", "D", strategy="yen", top_k=2)

    assert len(paths) == 2
    assert {tuple(path.nodes[1:-1]) for path in paths} == {("B",), ("C",)}


def test_yen_returns_structurally_distinct_paths_on_diamond_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id=node_id,
                kind=NodeKind.COMPUTE,
                name=node_id,
                source="fixture",
            )
            for node_id in ("A", "B", "C", "D", "E")
        ],
        edges=[
            GraphEdge(source="A", target="B"),
            GraphEdge(source="A", target="C"),
            GraphEdge(source="B", target="D"),
            GraphEdge(source="C", target="D"),
            GraphEdge(source="B", target="C"),
            GraphEdge(source="A", target="E"),
            GraphEdge(source="E", target="D"),
        ],
    )
    edge_weights = {
        ("A", "B"): 1.0,
        ("A", "C"): 2.0,
        ("B", "D"): 1.0,
        ("C", "D"): 1.0,
        ("B", "C"): 10.0,
        ("A", "E"): 1.0,
        ("E", "D"): 1.0,
    }
    monkeypatch.setattr(
        "argusloom.graph.pathfinding._edge_cost",
        lambda _graph, edge: edge_weights[(edge.source, edge.target)],
    )

    dijkstra_paths = find_attack_paths(graph, "A", "D", strategy="dijkstra", top_k=3)
    yen_paths = find_attack_paths(graph, "A", "D", strategy="yen", top_k=3)
    dijkstra_single = find_attack_paths(graph, "A", "D", strategy="dijkstra", top_k=1)

    assert dijkstra_paths
    assert yen_paths
    assert dijkstra_paths[0].score == yen_paths[0].score
    assert dijkstra_paths[0].nodes == yen_paths[0].nodes
    assert len(yen_paths) >= 2
    assert len(dijkstra_single) == 1
    assert dijkstra_single[0].nodes == dijkstra_paths[0].nodes
    yen_signatures = [
        {(edge.source, edge.target) for edge in path.edges} for path in yen_paths
    ]
    for index, first in enumerate(yen_signatures):
        for second in yen_signatures[index + 1 :]:
            assert first - second
            assert second - first
    assert [path.nodes for path in yen_paths] == [
        ["A", "B", "D"],
        ["A", "E", "D"],
        ["A", "C", "D"],
    ]
    assert [path.score for path in yen_paths] == [2.0, 2.0, 3.0]


def test_find_attack_paths_rejects_bfs_strategy() -> None:
    try:
        find_attack_paths(_graph_linear(), "A", "C", strategy="bfs")
        raise AssertionError("Expected ValueError")
    except ValueError as exc:
        assert str(exc) == "strategy must be 'dijkstra' or 'yen'"


def test_hybrid_primary_path_follows_explicit_waypoints() -> None:
    graph = GraphStore(Path("data/graph_C.json")).load()
    expected = [
        "aws_security_group.public",
        "aws_instance.web",
        "aws_lambda_function.handler",
        "aws_lambda_function.processor",
        "aws_db_instance.database",
    ]

    path = find_attack_path_through_waypoints(graph, expected)

    assert path.nodes == expected
    assert [edge.relation for edge in path.edges] == [
        "attached_to",
        "depends_on",
        "depends_on",
        "depends_on",
    ]


def test_waypoint_path_does_not_reverse_dependency_edges() -> None:
    graph = Graph(
        nodes=[
            GraphNode(id="consumer", kind=NodeKind.COMPUTE, name="consumer", source="fixture"),
            GraphNode(id="dependency", kind=NodeKind.DATA, name="dependency", source="fixture"),
        ],
        edges=[GraphEdge(source="consumer", target="dependency", relation="depends_on")],
    )

    with pytest.raises(ValueError, match="No directed edge"):
        find_attack_path_through_waypoints(graph, ["dependency", "consumer"])
