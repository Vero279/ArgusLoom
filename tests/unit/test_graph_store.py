from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.graph.store import GraphStore


def _sample_graph() -> Graph:
    return Graph(
        nodes=[
            GraphNode(
                id="a",
                kind=NodeKind.COMPUTE,
                name="A",
                source="fixture",
                criticality=Criticality.HIGH,
                exposure=0.8,
            ),
            GraphNode(
                id="b",
                kind=NodeKind.NETWORK,
                name="B",
                source="fixture",
                criticality=Criticality.MEDIUM,
                exposure=0.6,
            ),
            GraphNode(
                id="c",
                kind=NodeKind.DATA,
                name="C",
                source="fixture",
                criticality=Criticality.CRITICAL,
                exposure=0.9,
            ),
        ],
        edges=[
            GraphEdge(source="a", target="b", relation="depends_on"),
            GraphEdge(source="b", target="c", relation="depends_on"),
        ],
    )


def test_graph_store_round_trip(tmp_path) -> None:
    path = tmp_path / "graph.json"
    store = GraphStore(path)
    graph = _sample_graph()

    store.save(graph)

    assert store.exists()
    loaded = store.load()
    assert [node.id for node in loaded.nodes] == ["a", "b", "c"]
    assert [edge.target for edge in loaded.edges] == ["b", "c"]


def test_graph_store_get_node_returns_expected_node(tmp_path) -> None:
    store = GraphStore(tmp_path / "graph.json")
    graph = _sample_graph()
    store.save(graph)

    node = store.get_node(graph, "b")

    assert node.id == "b"
    assert node.kind == NodeKind.NETWORK


def test_graph_store_get_node_raises_for_unknown_id(tmp_path) -> None:
    store = GraphStore(tmp_path / "graph.json")
    graph = _sample_graph()
    store.save(graph)

    try:
        store.get_node(graph, "missing")
        raise AssertionError("Expected NodeNotFound")
    except NodeNotFound as exc:
        assert str(exc) == "Node 'missing' not found"


def test_graph_store_get_subgraph_filters_edges(tmp_path) -> None:
    store = GraphStore(tmp_path / "graph.json")
    graph = _sample_graph()
    store.save(graph)

    subgraph = store.get_subgraph(graph, {"a", "c"})

    assert [node.id for node in subgraph.nodes] == ["a", "c"]
    assert subgraph.edges == []
