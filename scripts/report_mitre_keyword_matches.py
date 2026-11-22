"""Report deterministic MITRE keyword matches for graph_C.json before/after."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argusloom.cti.mitre_loader import MITRELoader
from argusloom.cti.mitre_loader import MAX_TECHNIQUES_PER_NODE
from argusloom.cti.enrich import CTIEnricher
from argusloom.domain.enums import NodeKind
from argusloom.domain.graph import Graph, GraphNode


def node_keywords(node: dict[str, object]) -> list[str]:
    kind_keywords = {
        "network": "network",
        "data": "data",
        "storage": "storage",
        "iam": "iam",
        "compute": "compute",
        "external": "public",
    }
    metadata = node.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    resource_type = str(metadata.get("resource_type", "") or "")
    extra = re.findall(r"[a-z0-9]+", f"{node['name']} {resource_type}".casefold())
    keywords: list[str] = []
    for keyword in [kind_keywords.get(str(node["kind"]), ""), *extra]:
        if len(keyword) > 2 and keyword not in keywords:
            keywords.append(keyword)
        if len(keywords) == 2:
            break
    return keywords


def match_report(loader: MITRELoader) -> dict[str, list[str]]:
    enricher = CTIEnricher(mitre=loader)
    payload = json.loads((ROOT / "data" / "graph_C.json").read_text(encoding="utf-8"))
    report: dict[str, list[str]] = {}
    for node in payload["nodes"]:
        graph_node = GraphNode(
            id=node["id"],
            kind=NodeKind(node["kind"]),
            name=node["name"],
            source=node.get("source", ""),
            metadata=node.get("metadata") or {},
        )
        report[node["id"]] = enricher.enrich(
            Graph(nodes=[graph_node], edges=[])
        ).nodes[0].mitre_techniques
    return report


def legacy_match_report() -> dict[str, list[str]]:
    """Reproduce the former upstream-keyword behavior for comparison only."""
    payload = json.loads((ROOT / "data" / "graph_C.json").read_text(encoding="utf-8"))
    report: dict[str, list[str]] = {}
    for node in payload["nodes"]:
        terms = set(node_keywords(node))
        matches: set[str] = set()
        for filename in ("attack.json", "atlas.json"):
            records = json.loads(
                (ROOT / "data" / "mitre" / filename).read_text(encoding="utf-8")
            )
            for record in records:
                searchable = set(
                    re.findall(
                        r"[a-z0-9]+",
                        " ".join(
                            [
                                str(record.get("name", "")),
                                str(record.get("tactic", "")),
                                *[
                                    str(keyword)
                                    for keyword in record.get("keywords", [])
                                ],
                            ]
                        ).casefold(),
                    )
                )
                if terms & searchable:
                    matches.add(str(record["id"]))
        report[str(node["id"])] = sorted(matches)[:MAX_TECHNIQUES_PER_NODE]
    return report


def main() -> int:
    loader = MITRELoader(
        ROOT / "data" / "mitre" / "attack.json",
        ROOT / "data" / "mitre" / "atlas.json",
    )
    before = legacy_match_report()
    after = match_report(loader)
    changed = {
        node_id: {
            "before": before[node_id],
            "after": after[node_id],
        }
        for node_id in sorted(set(before) | set(after))
        if before.get(node_id) != after.get(node_id)
    }
    print(
        json.dumps(
            {
                "per_node_cap": MAX_TECHNIQUES_PER_NODE,
                "before": before,
                "after": after,
                "changed_nodes": changed,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
