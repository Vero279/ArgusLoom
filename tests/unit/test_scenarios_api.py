import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from argusloom.api.app import create_app
from argusloom.config import get_settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def scenario_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for scenario_id in ("A", "B", "C"):
        shutil.copyfile(
            ROOT / "data" / f"graph_{scenario_id}.json",
            data_dir / f"graph_{scenario_id}.json",
        )
    shutil.copyfile(ROOT / "data/graph_A.json", data_dir / "graph.json")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARGUS_DEV_MODE", "true")
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


def test_list_scenarios_returns_expected_counts(scenario_client: TestClient) -> None:
    response = scenario_client.get("/dev/scenarios")

    assert response.status_code == 200
    assert response.json() == [
        {"id": "A", "nodes": 16, "edges": 23},
        {"id": "B", "nodes": 15, "edges": 7},
        {"id": "C", "nodes": 42, "edges": 51},
    ]


def test_current_scenario_is_derived_from_active_graph(
    scenario_client: TestClient,
) -> None:
    response = scenario_client.get("/dev/scenarios/current")

    assert response.status_code == 200
    assert response.json() == {"id": "A", "nodes": 16, "edges": 23}


def test_activate_scenario_updates_graph_endpoint(scenario_client: TestClient) -> None:
    activated = scenario_client.post("/dev/scenarios/A/activate")
    graph = scenario_client.get("/graph")

    assert activated.status_code == 200
    assert activated.json() == {"id": "A", "nodes": 16, "edges": 23}
    assert len(graph.json()["nodes"]) == 16


def test_activate_missing_scenario_returns_404(scenario_client: TestClient) -> None:
    response = scenario_client.post("/dev/scenarios/missing/activate")

    assert response.status_code == 404


def test_scenario_routes_are_disabled_outside_dev_mode(
    scenario_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUS_DEV_MODE")
    monkeypatch.setenv("ARGUS_ENVIRONMENT", "production")
    get_settings.cache_clear()

    response = scenario_client.get("/dev/scenarios")

    assert response.status_code == 403
