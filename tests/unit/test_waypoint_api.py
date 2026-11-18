from importlib import import_module
from pathlib import Path

from fastapi.testclient import TestClient

from argusloom.api.app import create_app
from argusloom.graph.store import GraphStore

ROOT = Path(__file__).resolve().parents[2]
PRIMARY_PATH = [
    "aws_security_group.public",
    "aws_instance.web",
    "aws_lambda_function.handler",
    "aws_lambda_function.processor",
    "aws_db_instance.database",
]


def test_attack_path_endpoint_accepts_exact_primary_waypoints(monkeypatch) -> None:
    graph = GraphStore(ROOT / "data/graph_C.json").load()
    app_module = import_module("argusloom.api.app")
    monkeypatch.setattr(app_module, "_load_graph_from_store", lambda: graph)
    client = TestClient(create_app())

    response = client.post(
        "/attack-paths",
        json={
            "source_id": PRIMARY_PATH[0],
            "target_id": PRIMARY_PATH[-1],
            "waypoints": PRIMARY_PATH,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["paths"][0]["nodes"] == PRIMARY_PATH


def test_attack_path_endpoint_rejects_mismatched_waypoint_endpoints() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/attack-paths",
        json={
            "source_id": "start",
            "target_id": "end",
            "waypoints": ["other", "end"],
        },
    )

    assert response.status_code == 422
