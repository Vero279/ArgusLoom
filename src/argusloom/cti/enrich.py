"""Deterministic graph enrichment using local or live CTI provider interfaces."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Protocol

from argusloom.cti.mitre_loader import MAX_TECHNIQUES_PER_NODE, MITRELoader
from argusloom.domain.enums import NodeKind
from argusloom.domain.graph import Graph, GraphNode

_CVSS_FALLBACKS = {
    NodeKind.NETWORK: 9.0,
    NodeKind.DATA: 7.5,
    NodeKind.STORAGE: 6.0,
    NodeKind.IAM: 8.0,
    NodeKind.COMPUTE: 5.0,
    NodeKind.EXTERNAL: 4.0,
}

_KIND_KEYWORDS = {
    NodeKind.NETWORK: "network",
    NodeKind.DATA: "data",
    NodeKind.STORAGE: "storage",
    NodeKind.IAM: "iam",
    NodeKind.COMPUTE: "compute",
    NodeKind.EXTERNAL: "public",
}


class _CPEMatcher(Protocol):
    def cves_for_metadata(self, metadata: dict[str, Any]) -> list[dict[str, Any]]: ...


class CTIEnricher:
    def __init__(
        self,
        mitre: MITRELoader,
        cpe_matcher: _CPEMatcher | None = None,
    ) -> None:
        self.mitre = mitre
        self.cpe_matcher = cpe_matcher

    @staticmethod
    def _keywords_for_node(node: GraphNode) -> list[str]:
        kind_keyword = _KIND_KEYWORDS.get(node.kind, "")
        metadata = node.metadata if isinstance(node.metadata, dict) else {}
        resource_type = str(metadata.get("resource_type", "") or "")
        extra_keywords = re.findall(
            r"[a-z0-9]+", f"{node.name} {resource_type}".casefold()
        )
        keywords: list[str] = []
        for keyword in [kind_keyword, *extra_keywords]:
            if len(keyword) > 2 and keyword not in keywords:
                keywords.append(keyword)
            if len(keywords) == 2:
                break
        return keywords

    @staticmethod
    def _fallback_cvss(node: GraphNode) -> float:
        return _CVSS_FALLBACKS.get(
            node.kind,
            max(0.0, float(node.exposure or 0.0) * 10.0),
        )

    def enrich(self, graph: Graph) -> Graph:
        enriched = Graph(nodes=deepcopy(graph.nodes), edges=deepcopy(graph.edges))
        for node in enriched.nodes:
            matched_cves = (
                self.cpe_matcher.cves_for_metadata(node.metadata)
                if self.cpe_matcher is not None
                else []
            )
            matched_techniques = {}
            for keyword in self._keywords_for_node(node):
                for technique in self.mitre.find_by_keyword(keyword):
                    matched_techniques[technique.id] = technique

            node.cves = sorted(
                cve["id"] for cve in matched_cves if isinstance(cve.get("id"), str)
            )
            node.mitre_techniques = sorted(matched_techniques)[
                :MAX_TECHNIQUES_PER_NODE
            ]
            node.cvss_max = (
                max(float(cve["score"]) for cve in matched_cves)
                if matched_cves
                else self._fallback_cvss(node)
            )
        return enriched
