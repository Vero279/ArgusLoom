from importlib import import_module
from itertools import permutations
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.graph.pathfinding import find_attack_paths
from argusloom.graph.store import GraphStore

api_module = import_module("argusloom.api.app")
app = api_module.app
client = TestClient(app)


def test_blast_radius_endpoint_uses_isolated_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="node-a",
                kind=NodeKind.COMPUTE,
                name="node-a",
                source="test",
                criticality=Criticality.LOW,
            )
        ]
    )
    store = GraphStore(tmp_path / "graph.json")
    store.save(graph)
    monkeypatch.setattr(api_module, "_load_graph_from_store", store.load)

    response = client.get("/nodes/node-a/blast-radius?max_depth=3&weighted=true")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["root_id"] == "node-a"
    assert body["max_depth"] >= 0


def test_blast_radius_endpoint_missing_node_returns_404() -> None:
    response = client.get("/nodes/missing/blast-radius")

    assert response.status_code == 404
    assert response.json() == {"detail": "Node 'missing' not found"}


@pytest.mark.parametrize("scenario", ["A", "B", "C"])
def test_attack_paths_endpoint_returns_paths_for_connected_nodes(
    scenario: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario_path = Path(f"data/graph_{scenario}.json")
    if not scenario_path.is_file():
        pytest.skip(f"scenario {scenario} graph not found: {scenario_path}")

    graph = GraphStore(scenario_path).load()
    node_ids = sorted(node.id for node in graph.nodes)
    pair = next(
        (
            (source_id, target_id)
            for source_id, target_id in permutations(node_ids, 2)
            if find_attack_paths(graph, source_id, target_id, top_k=1)
        ),
        None,
    )
    if pair is None:
        pytest.skip(f"scenario {scenario} has no path")

    monkeypatch.setattr(api_module, "_load_graph_from_store", lambda: graph)
    source_id, target_id = pair
    response = client.post(
        "/attack-paths",
        json={
            "source_id": source_id,
            "target_id": target_id,
            "strategy": "dijkstra",
            "top_k": 3,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source_id"] == source_id
    assert body["target_id"] == target_id
    assert len(body["paths"]) >= 1


def test_attack_paths_endpoint_dijkstra_ignores_top_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = Graph(
        nodes=[
            GraphNode(id=node_id, kind=NodeKind.COMPUTE, name=node_id, source="test")
            for node_id in ("A", "B", "C")
        ],
        edges=[
            GraphEdge(source="A", target="B"),
            GraphEdge(source="B", target="C"),
        ],
    )
    store = GraphStore(tmp_path / "graph.json")
    store.save(graph)
    monkeypatch.setattr(api_module, "_load_graph_from_store", store.load)

    response = client.post(
        "/attack-paths",
        json={
            "source_id": "A",
            "target_id": "C",
            "strategy": "dijkstra",
            "top_k": 5,
        },
    )

    assert response.status_code == 200, response.text
    paths = response.json()["paths"]
    assert len(paths) == 1
    assert paths[0]["nodes"] == ["A", "B", "C"]
    assert paths[0]["length"] == 2


def test_attack_paths_endpoint_yen_returns_up_to_top_k_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = Graph(
        nodes=[
            GraphNode(id=node_id, kind=NodeKind.COMPUTE, name=node_id, source="test")
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
    store = GraphStore(tmp_path / "graph.json")
    store.save(graph)
    monkeypatch.setattr(api_module, "_load_graph_from_store", store.load)

    response = client.post(
        "/attack-paths",
        json={
            "source_id": "A",
            "target_id": "D",
            "strategy": "yen",
            "top_k": 3,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["strategy"] == "yen"
    assert 1 <= len(body["paths"]) <= 3
