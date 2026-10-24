from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.analysis.threat_model import analyze_graph


def test_analyze_graph_prioritizes_exposed_assets() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="aws_security_group.app",
                name="app",
                kind=NodeKind.NETWORK,
                source="terraform",
                criticality=Criticality.MEDIUM,
                exposure=0.9,
            ),
            GraphNode(
                id="aws_db_instance.db",
                name="db",
                kind=NodeKind.DATA,
                source="terraform",
                criticality=Criticality.HIGH,
                exposure=0.4,
            ),
            GraphNode(
                id="aws_instance.web",
                name="web",
                kind=NodeKind.COMPUTE,
                source="terraform",
                criticality=Criticality.HIGH,
                exposure=0.8,
            ),
        ],
        edges=[
            GraphEdge(source="aws_security_group.app", target="aws_instance.web", relation="exposes"),
            GraphEdge(source="aws_instance.web", target="aws_db_instance.db", relation="depends_on"),
        ],
    )

    findings = analyze_graph(graph)

    assert findings
    assert findings[0].node_id == "aws_db_instance.db"
    assert findings[0].risk_score > findings[1].risk_score


def test_analyze_graph_assigns_stride_categories() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="k8s_ingress.web",
                name="web",
                kind=NodeKind.NETWORK,
                source="kubernetes",
                criticality=Criticality.MEDIUM,
                exposure=0.9,
                stride=["information_disclosure"],
            ),
        ],
        edges=[],
    )

    findings = analyze_graph(graph)

    assert findings[0].threats
    assert "information_disclosure" in findings[0].threats
