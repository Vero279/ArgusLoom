from fastapi.testclient import TestClient

from argusloom.api.app import create_app

client = TestClient(create_app())


def test_graph_endpoint_returns_fixture_nodes_and_edges() -> None:
    response = client.get("/graph")

    assert response.status_code == 200
    payload = response.json()
    assert payload["nodes"]
    assert payload["edges"]
    assert {"id", "kind", "criticality", "exposure", "cvss_max"} <= payload["nodes"][
        0
    ].keys()


def test_graph_endpoint_allows_vite_development_origin() -> None:
    response = client.get(
        "/graph",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
