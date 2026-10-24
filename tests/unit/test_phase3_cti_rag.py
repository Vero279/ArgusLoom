from argusloom.cti.mock_cti import enrich_graph_with_cti
from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.rag.knowledge_base import KnowledgeBase, search_knowledge


def test_knowledge_base_returns_related_mitigation_for_exposure() -> None:
    kb = KnowledgeBase()
    results = search_knowledge(kb, "ingress", "information_disclosure")

    assert results
    assert any("ingress" in item.lower() or "tls" in item.lower() for item in results)


def test_enrich_graph_with_cti_attaches_references() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="k8s_ingress.web",
                name="web",
                kind=NodeKind.NETWORK,
                source="kubernetes",
                criticality=Criticality.MEDIUM,
                exposure=0.9,
            ),
            GraphNode(
                id="aws_db_instance.db",
                name="db",
                kind=NodeKind.DATA,
                source="terraform",
                criticality=Criticality.HIGH,
                exposure=0.5,
            ),
        ],
        edges=[GraphEdge(source="k8s_ingress.web", target="aws_db_instance.db", relation="depends_on")],
    )

    enriched = enrich_graph_with_cti(graph)

    entry = next(node for node in enriched.nodes if node.id == "k8s_ingress.web")
    assert "cti" in entry.metadata
    assert entry.metadata["cti"][0]["source"] in {"MITRE ATT&CK", "NVD", "CISA"}

    db_entry = next(node for node in enriched.nodes if node.id == "aws_db_instance.db")
    assert db_entry.metadata["cti"]
