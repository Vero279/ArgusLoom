"""Mitigation planning based on graph exposure and risk findings."""

from __future__ import annotations

from typing import Any

from argusloom.analysis.threat_model import analyze_graph
from argusloom.domain.graph import Graph

CRITICALITY_WEIGHT = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.5,
    "critical": 5.0,
}


def _default_actions(node: Any) -> list[str]:
    return [
        "Review exposure boundaries and tighten network controls.",
        "Enforce least-privilege access and verify dependency trust boundaries.",
    ]


def _actions_for_node(node: Any) -> list[str]:
    kind = getattr(node, "kind", "")
    normalized_kind = str(kind.value if hasattr(kind, "value") else kind).lower()
    node_id = str(getattr(node, "id", "")).lower()

    if "ingress" in node_id or normalized_kind == "network":
        return [
            "Restrict public ingress and validate origin rules for externally reachable services.",
            "Enforce TLS 1.2+ and rate limiting on the entry point to reduce information disclosure and denial-of-service risk.",
            "Add workload identity and mTLS verification before trusted downstream dependencies are reached.",
        ]

    if "db" in node_id or normalized_kind in {"data", "storage"}:
        return [
            "Encrypt data at rest and in transit for the storage boundary.",
            "Review access policies and isolate sensitive data stores from unrestricted attachment paths.",
            "Enable audit logging and rotate credentials to reduce tampering and exfiltration risk.",
        ]

    if "role" in node_id or normalized_kind == "iam":
        return [
            "Reduce privilege scope and enforce least privilege for the identity model.",
            "Separate responsibilities and verify role assumptions for sensitive workloads.",
        ]

    return _default_actions(node)


def build_remediation_plan(graph: Graph) -> list[dict[str, Any]]:
    """Return a prioritized mitigation plan for graph nodes."""

    findings = analyze_graph(graph)
    findings_by_id = {item.node_id: item for item in findings}
    prioritized: list[dict[str, Any]] = []

    for node in graph.nodes:
        criticality = str(getattr(node, "criticality", "low")).lower()
        risk_score = float(getattr(node, "exposure", 0.0) * 10.0)
        risk_score += CRITICALITY_WEIGHT.get(criticality, 1.0)
        finding = findings_by_id.get(node.id)
        if finding is not None:
            risk_score += float(finding.risk_score)

        kind_value = getattr(node, "kind", None)
        normalized_kind = str(
            kind_value.value if hasattr(kind_value, "value") else kind_value
        ).lower()
        if "ingress" in str(node.id).lower() or normalized_kind == "network":
            risk_score += 2.0

        prioritized.append(
            {
                "node_id": node.id,
                "kind": str(node.kind),
                "risk_score": round(risk_score, 2),
                "exposure": float(node.exposure),
                "actions": _actions_for_node(node),
            }
        )

    prioritized.sort(
        key=lambda item: (item["risk_score"], item["exposure"]), reverse=True
    )
    return prioritized
