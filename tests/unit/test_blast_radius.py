from argusloom.analysis.threat_model import ThreatFinding
from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.graph.blast_radius import compute_blast_radius


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
            ),
            GraphNode(
                id="B",
                kind=NodeKind.NETWORK,
                name="B",
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.8,
            ),
            GraphNode(
                id="C",
                kind=NodeKind.DATA,
                name="C",
                source="fixture",
                criticality=Criticality.CRITICAL,
                exposure=0.9,
            ),
        ],
        edges=[
            GraphEdge(source="A", target="B", relation="depends_on"),
            GraphEdge(source="B", target="C", relation="depends_on"),
        ],
    )


def test_compute_blast_radius_includes_full_linear_path() -> None:
    graph = _graph_linear()
    findings = [
        ThreatFinding(node_id="A", risk_score=1.0),
        ThreatFinding(node_id="B", risk_score=2.0),
        ThreatFinding(node_id="C", risk_score=3.0),
    ]

    result = compute_blast_radius(graph, findings, "A", max_depth=3)

    assert result.root_id == "A"
    assert [node.id for node in result.nodes] == ["A", "B", "C"]
    assert result.max_depth == 2


def test_compute_blast_radius_respects_max_depth() -> None:
    graph = _graph_linear()
    findings = [
        ThreatFinding(node_id="A", risk_score=1.0),
        ThreatFinding(node_id="B", risk_score=2.0),
        ThreatFinding(node_id="C", risk_score=3.0),
    ]

    result = compute_blast_radius(graph, findings, "A", max_depth=1)

    assert [node.id for node in result.nodes] == ["A", "B"]


def test_compute_blast_radius_depth_map_for_branching_graph() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="A",
                kind=NodeKind.COMPUTE,
                name="A",
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.6,
            ),
            GraphNode(
                id="B",
                kind=NodeKind.NETWORK,
                name="B",
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.7,
            ),
            GraphNode(
                id="C",
                kind=NodeKind.NETWORK,
                name="C",
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.7,
            ),
            GraphNode(
                id="D",
                kind=NodeKind.DATA,
                name="D",
                source="fixture",
                criticality=Criticality.CRITICAL,
                exposure=0.9,
            ),
        ],
        edges=[
            GraphEdge(source="A", target="B", relation="depends_on"),
            GraphEdge(source="A", target="C", relation="depends_on"),
            GraphEdge(source="B", target="D", relation="depends_on"),
        ],
    )
    findings = [
        ThreatFinding(node_id="A", risk_score=1.0),
        ThreatFinding(node_id="B", risk_score=2.0),
        ThreatFinding(node_id="C", risk_score=2.0),
        ThreatFinding(node_id="D", risk_score=5.0),
    ]

    result = compute_blast_radius(graph, findings, "A", max_depth=2)

    assert result.depth_map == {"A": 0, "B": 1, "C": 1, "D": 2}


def test_compute_blast_radius_weighted_risk_is_lower_than_simple_total() -> None:
    graph = _graph_linear()
    findings = [
        ThreatFinding(node_id="A", risk_score=6.0),
        ThreatFinding(node_id="B", risk_score=4.0),
        ThreatFinding(node_id="C", risk_score=3.0),
    ]

    weighted = compute_blast_radius(graph, findings, "A", max_depth=3, weighted=True)
    unweighted = compute_blast_radius(graph, findings, "A", max_depth=3, weighted=False)

    assert weighted.risk_score < unweighted.risk_score


def test_compute_blast_radius_unknown_root_raises() -> None:
    graph = _graph_linear()

    try:
        compute_blast_radius(graph, [], "missing")
        raise AssertionError("Expected NodeNotFound")
    except NodeNotFound as exc:
        assert str(exc) == "Node 'missing' not found"
