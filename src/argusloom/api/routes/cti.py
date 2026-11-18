"""CTI enrichment endpoint backed by configurable NVD and MITRE providers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from argusloom.cti.cpe_matcher import SnapshotCPEMatcher
from argusloom.cti.enrich import CTIEnricher
from argusloom.cti.mitre_loader import MITRELoader
from argusloom.domain.enums import Criticality, NodeKind, StrideCategory
from argusloom.domain.graph import Graph, GraphEdge, GraphNode

router = APIRouter(prefix="/cti", tags=["cti"])


class CTIEnrichRequest(BaseModel):
    graph: dict[str, Any]


def _graph_from_payload(payload: dict[str, Any]) -> Graph:
    nodes = [
        GraphNode(
            id=str(item["id"]),
            kind=NodeKind(str(item.get("kind", "compute")).strip().lower()),
            name=str(item.get("name", item["id"])),
            source=str(item.get("source", "manual")),
            criticality=Criticality(
                str(item.get("criticality", "low")).strip().lower()
            ),
            exposure=float(item.get("exposure", 0.0)),
            metadata=dict(item.get("metadata", {}) or {}),
            stride=[
                StrideCategory(str(value).replace("-", "_").replace(" ", "_"))
                for value in item.get("stride", [])
            ],
            cves=[str(value) for value in item.get("cves", [])],
            mitre_techniques=[str(value) for value in item.get("mitre_techniques", [])],
            cvss_max=float(item.get("cvss_max", 0.0)),
        )
        for item in payload.get("nodes", [])
    ]
    edges = [
        GraphEdge(
            source=str(item["source"]),
            target=str(item["target"]),
            relation=str(item.get("relation", "depends_on")),
            confidence=float(item.get("confidence", 1.0)),
            metadata=dict(item.get("metadata", {}) or {}),
        )
        for item in payload.get("edges", [])
    ]
    return Graph(nodes=nodes, edges=edges)


@router.post("/enrich")
def enrich_cti(request: CTIEnrichRequest) -> dict[str, Any]:
    mitre_loader = MITRELoader(
        attack_path=Path("data/mitre/attack.json"),
        atlas_path=Path("data/mitre/atlas.json"),
    )
    cpe_matcher = SnapshotCPEMatcher.from_files(
        Path.cwd(),
        Path("data/cti_snapshot_manifest.json"),
        Path("data/cpe_product_mappings.json"),
    )
    graph = _graph_from_payload(request.graph)
    enriched = CTIEnricher(
        mitre=mitre_loader,
        cpe_matcher=cpe_matcher,
    ).enrich(graph)
    enriched_count = sum(
        bool(node.cves or node.mitre_techniques or node.cvss_max > 0)
        for node in enriched.nodes
    )
    return {"graph": enriched.to_dict(), "enriched_count": enriched_count}
