"""Offline CTI mock layer for Phase 3 enrichment."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from argusloom.domain.graph import Graph


def _cvss_hint_for_node(node: Any) -> float:
    kind = str(getattr(node, "kind", "") or "").lower()
    mapping = {
        "network": 9.0,
        "data": 7.5,
        "storage": 6.0,
        "iam": 8.0,
        "compute": 5.0,
        "external": 4.0,
    }
    if kind in mapping:
        return float(mapping[kind])
    return float(max(0.0, float(getattr(node, "exposure", 0.0) or 0.0) * 10.0))


def _cve_hint_for_node(node: Any) -> list[str]:
    kind = str(getattr(node, "kind", "") or "").lower()
    node_id = str(getattr(node, "id", "") or "").lower()

    if "ingress" in node_id or kind == "network":
        return ["CVE-NETWORK-EXPOSURE"]
    if "db" in node_id or "storage" in kind or "data" in kind:
        return ["CVE-DB-ACCESS"]
    if "iam" in kind or "role" in node_id:
        return ["CVE-IAM-PRIVILEGE-ESCALATION"]
    return ["CVE-GENERIC-ASSET-EXPOSURE"]


def _intel_for_node(node: Any) -> list[dict[str, Any]]:
    node_id = str(node.id).lower()
    kind = str(getattr(node, "kind", "")).lower()
    exposure = float(getattr(node, "exposure", 0.0) or 0.0)

    if "ingress" in node_id or kind == "network":
        return [
            {
                "source": "MITRE ATT&CK",
                "reference": "T1190",
                "title": "Exploit public-facing application",
                "summary": "Public-facing services should enforce TLS, rate limits, and ingress policy controls.",
                "confidence": 0.9,
                "tags": ["ingress", "exposure", "tls"],
            },
            {
                "source": "CISA",
                "reference": "CISA-INGRESS-01",
                "title": "Ingress hardening guidance",
                "summary": "Review ingress and firewall policies for externally reachable workloads.",
                "confidence": 0.8,
                "tags": ["ingress", "firewall", "hardening"],
            },
        ]

    if "db" in node_id or "storage" in kind or "data" in kind:
        result = [
            {
                "source": "NVD",
                "reference": "CVE-DB-ACCESS",
                "title": "Database exposure risk",
                "summary": "Sensitive data stores are attractive targets for data exfiltration and tampering.",
                "confidence": 0.85,
                "tags": ["database", "data", "tampering"],
            }
        ]
        if exposure > 0.6:
            result.append(
                {
                    "source": "CISA",
                    "reference": "CISA-DATA-02",
                    "title": "Encrypt data in transit and at rest",
                    "summary": "Apply encryption and access control for exposed data-bearing services.",
                    "confidence": 0.8,
                    "tags": ["encryption", "data", "controls"],
                }
            )
        return result

    if "iam" in kind or "role" in node_id:
        return [
            {
                "source": "MITRE ATT&CK",
                "reference": "T1078",
                "title": "Valid accounts",
                "summary": "Identity and access misconfiguration can enable privilege escalation via over-permissive roles.",
                "confidence": 0.9,
                "tags": ["iam", "privilege", "spoofing"],
            }
        ]

    return [
        {
            "source": "NVD",
            "reference": "NVD-GENERIC",
            "title": "Asset exposure review",
            "summary": "Review exposure and dependency paths for this asset given its current risk posture.",
            "confidence": 0.7,
            "tags": ["review", "exposure", "monitoring"],
        }
    ]


def _collect_typed_fields(intel: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    mitre_techniques: list[str] = []
    cves: list[str] = []
    seen_mitre: set[str] = set()
    seen_cves: set[str] = set()

    for item in intel:
        reference = str(item.get("reference", "")).strip()
        if reference.startswith("T") and reference not in seen_mitre:
            seen_mitre.add(reference)
            mitre_techniques.append(reference)
        if reference.upper().startswith("CVE-") and reference not in seen_cves:
            seen_cves.add(reference)
            cves.append(reference)
        if item.get("source") == "NVD" and "CVE" in item.get("title", ""):
            ref = reference or item.get("title", "")
            if ref not in seen_cves:
                seen_cves.add(ref)
                cves.append(ref)

    return mitre_techniques, cves


def enrich_graph_with_cti(graph: Graph) -> Graph:
    """Attach a mock CTI layer to each node in the graph while populating typed fields."""

    enriched = Graph(nodes=deepcopy(graph.nodes), edges=deepcopy(graph.edges))
    for node in enriched.nodes:
        intel = _intel_for_node(node)
        node.metadata.setdefault("cti", intel)
        node.metadata["intel_summary"] = "; ".join(item["title"] for item in intel)

        mitre_techniques, cves = _collect_typed_fields(intel)
        if not cves:
            cves = _cve_hint_for_node(node)
        node.mitre_techniques = list(mitre_techniques)
        node.cves = list(cves)
        node.cvss_max = _cvss_hint_for_node(node)

    return enriched
