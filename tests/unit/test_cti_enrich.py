from pathlib import Path

from argusloom.cti.enrich import CTIEnricher
from argusloom.cti.mitre_loader import MITRELoader
from argusloom.cti.nvd_client import CVE, MockNVDClient
from argusloom.domain.enums import NodeKind
from argusloom.domain.graph import Graph, GraphNode


def _enricher():
    project_root = Path(__file__).resolve().parents[2]
    return CTIEnricher(
        nvd=MockNVDClient(project_root / "data" / "fixtures" / "cves.json"),
        mitre=MITRELoader(
            attack_path=project_root / "data" / "mitre" / "attack.json",
            atlas_path=project_root / "data" / "mitre" / "atlas.json",
        ),
    )


def test_network_node_receives_relevant_mitre_technique() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="network-1",
                kind=NodeKind.NETWORK,
                name="public-api",
                source="test",
            )
        ]
    )

    enriched = _enricher().enrich(graph)

    assert any(
        technique_id in {"T1190", "AML.T0051", "AML.T0051.001"}
        for technique_id in enriched.nodes[0].mitre_techniques
    )


def test_data_node_receives_related_cve() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="data-1",
                kind=NodeKind.DATA,
                name="data-store",
                source="test",
            )
        ]
    )

    enriched = _enricher().enrich(graph)

    assert "CVE-2018-16603" in enriched.nodes[0].cves


def test_cvss_max_is_highest_score_of_matching_cves() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="network-2",
                kind=NodeKind.NETWORK,
                name="network-edge",
                source="test",
            )
        ]
    )
    cves = [
        CVE("CVE-2024-0002", "network issue", 6.1, "MEDIUM", "2024-01-01"),
        CVE("CVE-2024-0001", "network exposure", 8.3, "HIGH", "2024-01-02"),
    ]

    class MatchingNVDClient:
        def fetch_cves_for_keyword(self, keyword: str, limit: int = 20) -> list[CVE]:
            return cves[:limit]

    enricher = CTIEnricher(
        nvd=MatchingNVDClient(),
        mitre=MITRELoader(
            attack_path=Path(__file__).resolve().parents[2]
            / "data"
            / "mitre"
            / "attack.json",
            atlas_path=Path(__file__).resolve().parents[2]
            / "data"
            / "mitre"
            / "atlas.json",
        ),
    )

    enriched = enricher.enrich(graph)

    assert enriched.nodes[0].cvss_max == 8.3


def test_unmatched_node_keeps_heuristic_cvss_and_empty_cves() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="custom-1",
                kind=NodeKind.EXTERNAL,
                name="unmatched-resource",
                source="test",
                exposure=0.2,
            )
        ]
    )

    enriched = _enricher().enrich(graph)

    assert enriched.nodes[0].cves == []
    assert enriched.nodes[0].mitre_techniques
    assert enriched.nodes[0].cvss_max == 4.0
