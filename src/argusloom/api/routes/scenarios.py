"""Development-only endpoints for switching between demo graph scenarios."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from argusloom.config import get_settings
from argusloom.graph.store import GraphStore

router = APIRouter(tags=["development scenarios"])


def require_dev_mode() -> None:
    if not get_settings().dev_mode:
        raise HTTPException(
            status_code=403,
            detail="As ferramentas de cenários estão desativadas neste ambiente.",
        )


def _scenario_path(scenario_id: str) -> Path:
    if scenario_id not in {"A", "B", "C"}:
        raise HTTPException(status_code=404, detail="Cenário não encontrado.")
    path = Path("data") / f"graph_{scenario_id}.json"
    if not path.is_file():
        raise HTTPException(
            status_code=404, detail="Ficheiro do cenário não encontrado."
        )
    return path


def _graph_counts(path: Path) -> dict[str, int]:
    graph = GraphStore(path).load()
    return {"nodes": graph.node_count, "edges": graph.edge_count}


def _available_scenarios() -> list[dict[str, int | str]]:
    scenarios: list[dict[str, int | str]] = []
    for scenario_id in ("A", "B", "C"):
        path = Path("data") / f"graph_{scenario_id}.json"
        if path.is_file():
            scenarios.append({"id": scenario_id, **_graph_counts(path)})
    return scenarios


@router.get("/scenarios", dependencies=[Depends(require_dev_mode)])
def list_scenarios() -> list[dict[str, int | str]]:
    """List generated demo graphs and their node/edge counts."""
    return _available_scenarios()


@router.get("/scenarios/current", dependencies=[Depends(require_dev_mode)])
def get_current_scenario() -> dict[str, int | str]:
    """Identify the active scenario by matching graph node and edge counts."""
    current_path = Path("data/graph.json")
    if not current_path.is_file():
        return {"id": "unknown"}

    current_counts = _graph_counts(current_path)
    matches = [
        scenario
        for scenario in _available_scenarios()
        if scenario["nodes"] == current_counts["nodes"]
        and scenario["edges"] == current_counts["edges"]
    ]
    return matches[0] if len(matches) == 1 else {"id": "unknown"}


@router.post(
    "/scenarios/{scenario_id}/activate", dependencies=[Depends(require_dev_mode)]
)
def activate_scenario(scenario_id: str) -> dict[str, int | str]:
    """Make a generated scenario graph the graph served by the API."""
    source = _scenario_path(scenario_id)
    target = Path("data/graph.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return {"id": scenario_id, **_graph_counts(target)}
