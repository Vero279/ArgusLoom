"""Threat enrichment and graph risk scoring for infrastructure assets."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import Graph


CRITICALITY_BONUS = {
    Criticality.LOW: 1.0,
    Criticality.MEDIUM: 2.5,
    Criticality.HIGH: 4.0,
    Criticality.CRITICAL: 5.5,
}

KIND_BONUS = {
    NodeKind.COMPUTE: 1.2,
    NodeKind.DATA: 2.8,
    NodeKind.STORAGE: 2.5,
    NodeKind.NETWORK: 1.8,
    NodeKind.IAM: 1.7,
    NodeKind.EXTERNAL: 0.8,
}

STRIDE_DEFAULTS = {
    NodeKind.NETWORK: ["information_disclosure", "tampering", "denial_of_service"],
    NodeKind.DATA: ["tampering", "information_disclosure", "repudiation"],
    NodeKind.STORAGE: ["information_disclosure", "tampering"],
    NodeKind.IAM: ["spoofing", "elevation_of_privilege"],
    NodeKind.COMPUTE: ["denial_of_service", "elevation_of_privilege"],
    NodeKind.EXTERNAL: ["information_disclosure"],
}


@dataclass(slots=True)
class ThreatFinding:
    node_id: str
    risk_score: float
    threats: list[str] = field(default_factory=list)
    rationale: str = ""


def _normalize_threats(threats: list[str] | list[Any] | None) -> list[str]:
    if not threats:
        return []
    normalized: list[str] = []
    for item in threats:
        value = str(item).strip()
        if value:
            normalized.append(value)
    return normalized


def _node_risk_score(node: Any, graph: Graph) -> float:
    criticality_weight = CRITICALITY_BONUS.get(node.criticality, 1.0)
    kind_weight = KIND_BONUS.get(node.kind, 1.0)
    direct_exposure = node.exposure * 3.0
    inbound_links = sum(1 for edge in graph.edges if edge.target == node.id and edge.relation in {"exposes", "depends_on", "attached_to"})
    outbound_links = sum(1 for edge in graph.edges if edge.source == node.id)
    data_bias = 2.5 if node.kind in {NodeKind.DATA, NodeKind.STORAGE} else 0.0
    network_bias = 1.5 if node.kind == NodeKind.NETWORK and node.exposure > 0.7 else 0.0
    inherited_exposure = 0.8 * inbound_links + 0.4 * outbound_links

    return criticality_weight + kind_weight + direct_exposure + data_bias + network_bias + inherited_exposure


def _infer_threats(node: Any) -> list[str]:
    if getattr(node, "stride", None):
        normalized = _normalize_threats([
            item.value if hasattr(item, "value") else str(item)
            for item in node.stride
        ])
        if normalized:
            return normalized

    return STRIDE_DEFAULTS.get(node.kind, ["information_disclosure"])


def analyze_graph(graph: Graph) -> list[ThreatFinding]:
    """Score infrastructure assets and rank them by risk in descending order."""

    findings: list[ThreatFinding] = []
    for node in graph.nodes:
        score = _node_risk_score(node, graph)
        threats = _infer_threats(node)
        findings.append(
            ThreatFinding(
                node_id=node.id,
                risk_score=score,
                threats=threats,
                rationale=f"Asset {node.id} has exposure {node.exposure:.2f} and criticality {node.criticality.value}.",
            )
        )

    findings.sort(key=lambda item: item.risk_score, reverse=True)
    return findings
