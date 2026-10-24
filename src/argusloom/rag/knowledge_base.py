"""In-memory knowledge retrieval for threat and control context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class KnowledgeEntry:
    title: str
    content: str
    keywords: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "content": self.content,
            "keywords": list(self.keywords),
        }


class KnowledgeBase:
    """Minimal retrieval layer for CTI and control knowledge."""

    def __init__(self, entries: list[KnowledgeEntry] | None = None) -> None:
        default_entries = [
            KnowledgeEntry(
                title="Ingress exposure hardening",
                content="Restrict public ingress, enforce TLS 1.2+, and validate mTLS for externally exposed services to reduce information disclosure risk.",
                keywords=["ingress", "tls", "mtls", "public", "information_disclosure"],
            ),
            KnowledgeEntry(
                title="Database encryption controls",
                content="Encrypt data at rest and in transit, rotate credentials, and isolate high-value data stores from unrestricted dependency paths.",
                keywords=["database", "data", "encryption", "tampering", "dependence"],
            ),
            KnowledgeEntry(
                title="IAM least privilege",
                content="Apply least privilege, role separation, and permission boundaries to prevent privilege escalation and spoofing across workloads.",
                keywords=["iam", "privilege", "spoofing", "least_privilege", "escalation"],
            ),
            KnowledgeEntry(
                title="Service resilience and monitoring",
                content="Deploy rate limits, circuit breakers, logging, and anomaly detection to reduce denial of service and accelerate incident response.",
                keywords=["network", "dos", "denial_of_service", "logging", "monitoring"],
            ),
        ]
        self.entries = list(entries) if entries is not None else default_entries

    def add_entry(self, entry: KnowledgeEntry) -> None:
        self.entries.append(entry)

    def add_document(self, title: str, content: str, keywords: list[str] | None = None) -> None:
        self.add_entry(KnowledgeEntry(title=title, content=content, keywords=list(keywords or [])))

    def search(self, asset_type: str | None = None, threat: str | None = None) -> list[str]:
        return search_knowledge(self, asset_type=asset_type, threat=threat)


def _tokenize(value: str) -> set[str]:
    if not value:
        return set()
    lowered = value.lower()
    tokens = re.findall(r"[a-z0-9_]+", lowered)
    return {token for token in tokens if token}


def search_knowledge(kb: KnowledgeBase, asset_type: str | None = None, threat: str | None = None) -> list[str]:
    """Return ranked knowledge snippets for a given asset type and threat theme."""

    query_tokens: set[str] = set()
    if asset_type:
        query_tokens.update(_tokenize(asset_type))
    if threat:
        query_tokens.update(_tokenize(threat))

    scored: list[tuple[int, str]] = []
    for entry in kb.entries:
        combined = _tokenize(entry.title) | _tokenize(entry.content) | set(entry.keywords)
        match_score = len(query_tokens & combined)
        if not match_score and not query_tokens:
            match_score = 1
        if match_score:
            scored.append((match_score, f"{entry.title}: {entry.content}"))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [result for _, result in scored[:5]]
