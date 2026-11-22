import json
from pathlib import Path

from argusloom.cti.cpe_matcher import (
    CPEProductMapping,
    SnapshotCPEMatcher,
)
from argusloom.cti.enrich import CTIEnricher
from argusloom.cti.mitre_loader import MITRELoader
from argusloom.domain.enums import NodeKind
from argusloom.domain.graph import Graph, GraphNode

ROOT = Path(__file__).resolve().parents[2]


def _mitre_loader() -> MITRELoader:
    return MITRELoader(
        attack_path=ROOT / "data" / "mitre" / "attack.json",
        atlas_path=ROOT / "data" / "mitre" / "atlas.json",
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

    enriched = CTIEnricher(mitre=_mitre_loader()).enrich(graph)

    assert any(
        technique_id in {"T1190", "AML.T0051", "AML.T0051.001"}
        for technique_id in enriched.nodes[0].mitre_techniques
    )


def test_cve_links_require_a_verified_cpe_match() -> None:
    cve = {
        "id": "CVE-2024-0001",
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:postgresql:postgresql:*:" "*:*:*:*:*:*:*"
                                ),
                                "versionEndIncluding": "14.10",
                            }
                        ],
                    }
                ]
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.3,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
    }
    matcher = SnapshotCPEMatcher(
        [
            CPEProductMapping(
                software_key="postgresql",
                part="a",
                vendor="postgresql",
                product="postgresql",
                verified=True,
            )
        ],
        [cve],
    )
    graph = Graph(
        nodes=[
            GraphNode(
                id="db-1",
                kind=NodeKind.DATA,
                name="database",
                source="test",
                metadata={
                    "software_inventory": [
                        {"software_key": "postgresql", "version": "14.10"}
                    ]
                },
                cves=["CVE-2018-16603"],
            )
        ]
    )

    enriched = CTIEnricher(
        mitre=_mitre_loader(),
        cpe_matcher=matcher,
    ).enrich(graph)

    assert enriched.nodes[0].cves == ["CVE-2024-0001"]
    assert enriched.nodes[0].cvss_max == 8.3


def test_freertos_cve_is_not_linked_to_postgresql_database() -> None:
    matcher = SnapshotCPEMatcher.from_files(
        ROOT,
        ROOT / "data" / "cti_snapshot_manifest.json",
        ROOT / "data" / "cpe_product_mappings.json",
    )
    graph = Graph(
        nodes=[
            GraphNode(
                id="aws_db_instance.database",
                kind=NodeKind.DATA,
                name="database",
                source="terraform",
                metadata={
                    "resource_type": "aws_db_instance",
                    "attributes": {"engine": "postgres", "engine_version": "14.10"},
                    "software_inventory": [
                        {"software_key": "postgresql", "version": "14.10"}
                    ],
                },
            )
        ]
    )

    enriched = CTIEnricher(
        mitre=_mitre_loader(),
        cpe_matcher=matcher,
    ).enrich(graph)

    assert "CVE-2018-16603" not in enriched.nodes[0].cves


def test_committed_graph_cve_links_require_declared_versions() -> None:
    paths = [
        ROOT / "data" / "graph.json",
        ROOT / "data" / "graph_A.json",
        ROOT / "data" / "graph_B.json",
        ROOT / "data" / "graph_C.json",
        ROOT / "data" / "graph.json_control",
    ]

    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        for node in payload.get("nodes", []):
            if node.get("cves"):
                inventory = (node.get("metadata") or {}).get("software_inventory") or []
                assert any(item.get("version") for item in inventory), (
                    path.name,
                    node["id"],
                )
