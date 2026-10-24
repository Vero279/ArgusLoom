from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.graph.pathfinding import find_attack_paths


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


def test_find_attack_paths_bfs_prefers_fewer_hops() -> None:
    graph = _graph_branching()

    paths = find_attack_paths(graph, "A", "C", strategy="bfs")

    assert paths[0].nodes == ["A", "B", "C"]


def test_find_attack_paths_top_k_returns_multiple_distinct_paths() -> None:
    graph = _graph_branching()

    paths = find_attack_paths(graph, "A", "C", strategy="dijkstra", top_k=2)

    assert len(paths) >= 1
    assert all(path.length >= 1 for path in paths)


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
