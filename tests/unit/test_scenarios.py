from pathlib import Path

import pytest
from typer.testing import CliRunner

from argusloom.cli import app
from argusloom.ingestion.graph_builder import build_graph

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = {
    "A": ROOT / "data/fixtures/scenarios/A_terraform_only",
    "B": ROOT / "data/fixtures/scenarios/B_k8s_only",
    "C": ROOT / "data/fixtures/scenarios/C_hybrid",
}


@pytest.mark.parametrize(
    ("scenario", "min_nodes", "min_edges"),
    [("A", 12, 15), ("B", 10, 5), ("C", 30, 30)],
)
def test_scenario_fixtures_build_graph(
    scenario: str,
    min_nodes: int,
    min_edges: int,
) -> None:
    fixture_dir = SCENARIOS[scenario]
    graph = build_graph(
        terraform_path=fixture_dir,
        k8s_path=fixture_dir,
    )

    assert graph.node_count >= min_nodes
    assert graph.edge_count >= min_edges


def test_scenario_cli_lists_and_activates_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    scenario_graph = data_dir / "graph_A.json"
    scenario_graph.write_text(
        '{"nodes": [{"id": "demo"}], "edges": []}\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    listed = runner.invoke(app, ["scenario", "list"])
    activated = runner.invoke(app, ["scenario", "A"])

    assert listed.exit_code == 0
    assert "A: 1 nodes, 0 edges" in listed.output
    assert activated.exit_code == 0
    assert "Scenario A activated:" in activated.output
    assert (data_dir / "graph.json").read_bytes() == scenario_graph.read_bytes()
