from fastapi.testclient import TestClient

from argusloom.api.app import app
from argusloom.domain.errors import NodeNotFound

client = TestClient(app)


def test_node_not_found_message() -> None:
    exc = NodeNotFound("node-404")

    assert str(exc) == "Node 'node-404' not found"


def test_node_not_found_http_handler() -> None:
    @app.get("/test-node-not-found")
    def _boom() -> None:
        raise NodeNotFound("missing-node")

    response = client.get("/test-node-not-found")

    assert response.status_code == 404
    assert response.json() == {"detail": "Node 'missing-node' not found"}
