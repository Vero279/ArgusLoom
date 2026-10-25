from pathlib import Path

from argusloom.analysis.threat_model import analyze_graph
from argusloom.cti.enrich import CTIEnricher
from argusloom.cti.mitre_loader import MITRELoader
from argusloom.cti.nvd_client import MockNVDClient
from argusloom.graph.blast_radius import compute_blast_radius
from argusloom.graph.pathfinding import find_attack_paths
from argusloom.graph.store import GraphStore
from argusloom.ingestion.graph_builder import build_graph
from argusloom.rag.embeddings import EmbeddingModel
from argusloom.rag.retriever import CTIRetriever
from argusloom.rag.vector_store import VectorStore


def test_full_pipeline_from_fixtures(tmp_path: Path) -> None:
    graph = build_graph(
        terraform_path=Path("data/fixtures/terraform"),
        k8s_path=Path("data/fixtures/k8s"),
        output_path=None,
    )

    mitre = MITRELoader(Path("data/mitre/attack.json"), Path("data/mitre/atlas.json"))
    nvd = MockNVDClient(Path("data/fixtures/cves.json"))
    enriched = CTIEnricher(nvd=nvd, mitre=mitre).enrich(graph)

    output_path = tmp_path / "graph.json"
    GraphStore(output_path).save(enriched)
    loaded = GraphStore(output_path).load()

    findings = analyze_graph(loaded)
    assert findings

    root_id = loaded.nodes[0].id
    radius = compute_blast_radius(loaded, findings, root_id, max_depth=2, weighted=True)
    assert radius.root_id == root_id
    assert radius.nodes

    same_node_paths = find_attack_paths(loaded, root_id, root_id, top_k=3)
    assert isinstance(same_node_paths, list)
    assert same_node_paths[0].length == 0

    other_paths = find_attack_paths(loaded, root_id, loaded.nodes[-1].id, top_k=3)
    assert isinstance(other_paths, list)

    retriever = CTIRetriever(EmbeddingModel(), VectorStore(tmp_path / "chroma"))
    retriever.index_graph(loaded)
    hits = retriever.query("network exposure", top_k=5)
    assert hits

    assert all(node.mitre_techniques for node in loaded.nodes)
