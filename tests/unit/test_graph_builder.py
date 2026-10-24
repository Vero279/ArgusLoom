from pathlib import Path

from argusloom.ingestion.graph_builder import build_graph


def test_graph_builder_persists_runtime_graph(tmp_path: Path) -> None:
    output_file = tmp_path / "graph.json"

    graph = build_graph(
        terraform_path="data/fixtures/terraform",
        k8s_path="data/fixtures/k8s",
        output_path=output_file,
    )

    assert graph.node_count >= 8
    assert graph.edge_count >= 6
    assert output_file.exists()

    payload = output_file.read_text(encoding="utf-8")
    assert '"nodes"' in payload
    assert '"edges"' in payload
