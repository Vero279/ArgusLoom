from fastapi.testclient import TestClient

from argusloom.api.app import app

client = TestClient(app)


def test_blast_radius_endpoint_uses_fixture_graph() -> None:
    response = client.get("/nodes/A/blast-radius?max_depth=3&weighted=true")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["root_id"] == "A"
    assert body["max_depth"] >= 0


def test_blast_radius_endpoint_missing_node_returns_404() -> None:
    response = client.get("/nodes/missing/blast-radius")

    assert response.status_code == 404
    assert response.json() == {"detail": "Node 'missing' not found"}


def test_attack_paths_endpoint_returns_paths_for_connected_nodes() -> None:
    response = client.post(
        "/attack-paths",
        json={"source_id": "A", "target_id": "C", "strategy": "dijkstra", "top_k": 3},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source_id"] == "A"
    assert body["target_id"] == "C"
    assert len(body["paths"]) >= 1
