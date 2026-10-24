from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import Graph, GraphNode
from argusloom.rag.embeddings import EmbeddingModel
from argusloom.rag.retriever import CTIRetriever
from argusloom.rag.vector_store import VectorStore


def test_retriever_index_graph_query_returns_network_node(tmp_path) -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="public_ingress",
                name="public ingress",
                kind=NodeKind.NETWORK,
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.9,
            ),
            GraphNode(
                id="iam_role",
                name="iam role",
                kind=NodeKind.IAM,
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.5,
            ),
        ],
        edges=[],
    )
    store = VectorStore(tmp_path / "chroma", collection_name="retriever-network")
    retriever = CTIRetriever(embeddings=EmbeddingModel(), store=store)

    retriever.index_graph(graph)
    hits = retriever.query("network exposure", top_k=5)

    assert hits
    assert any(hit.metadata.get("kind") == "network" for hit in hits)


def test_retriever_query_returns_iam_node_for_privilege_prompt(tmp_path) -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="public_ingress",
                name="public ingress",
                kind=NodeKind.NETWORK,
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.9,
            ),
            GraphNode(
                id="iam_role",
                name="iam role",
                kind=NodeKind.IAM,
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.5,
            ),
        ],
        edges=[],
    )
    store = VectorStore(tmp_path / "chroma", collection_name="retriever-iam")
    retriever = CTIRetriever(embeddings=EmbeddingModel(), store=store)

    retriever.index_graph(graph)
    hits = retriever.query("IAM privilege escalation", top_k=5)

    assert hits
    assert any(hit.metadata.get("kind") == "iam" for hit in hits)


def test_retriever_top_k_respected(tmp_path) -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="node-1",
                name="node 1",
                kind=NodeKind.NETWORK,
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.8,
            ),
            GraphNode(
                id="node-2",
                name="node 2",
                kind=NodeKind.DATA,
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.8,
            ),
            GraphNode(
                id="node-3",
                name="node 3",
                kind=NodeKind.IAM,
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.8,
            ),
        ],
        edges=[],
    )
    store = VectorStore(tmp_path / "chroma", collection_name="retriever-topk")
    retriever = CTIRetriever(embeddings=EmbeddingModel(), store=store)

    retriever.index_graph(graph)
    hits = retriever.query("network exposure", top_k=1)

    assert len(hits) == 1
