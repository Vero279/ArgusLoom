"""Kubernetes manifest ingestion parser."""

from __future__ import annotations

from pathlib import Path

import yaml

from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import GraphEdge, GraphNode


def _kind_to_node_kind(kind: str) -> NodeKind:
    kind_map = {
        "Deployment": NodeKind.COMPUTE,
        "StatefulSet": NodeKind.COMPUTE,
        "DaemonSet": NodeKind.COMPUTE,
        "Service": NodeKind.NETWORK,
        "Ingress": NodeKind.NETWORK,
        "ConfigMap": NodeKind.EXTERNAL,
        "Secret": NodeKind.EXTERNAL,
        "ServiceAccount": NodeKind.IAM,
    }
    return kind_map.get(kind, NodeKind.EXTERNAL)


def _resource_id(kind: str, name: str) -> str:
    return f"k8s_{kind.lower()}.{name}"


def _infer_criticality(kind: str) -> Criticality:
    if kind in {"Secret", "ConfigMap"}:
        return Criticality.MEDIUM
    if kind in {"Deployment", "StatefulSet"}:
        return Criticality.HIGH
    if kind == "Service":
        return Criticality.MEDIUM
    return Criticality.LOW


def parse_kubernetes_directory(path: str | Path) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Parse a directory of Kubernetes manifests and return graph nodes and edges."""

    root = Path(path)
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    if not root.exists():
        return nodes, edges

    manifests = sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml"))
    if not manifests:
        return nodes, edges

    for manifest in manifests:
        content = manifest.read_text(encoding="utf-8")
        for doc in yaml.safe_load_all(content):
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            metadata = doc.get("metadata", {})
            name = metadata.get("name")
            if not kind or not name:
                continue

            node_id = _resource_id(kind, name)
            nodes.append(
                GraphNode(
                    id=node_id,
                    kind=_kind_to_node_kind(kind),
                    name=name,
                    source="kubernetes",
                    criticality=_infer_criticality(kind),
                    exposure=0.4 if kind == "Ingress" else 0.2,
                    metadata={"kind": kind, "manifest": manifest.name},
                )
            )

            if kind == "Service":
                selector = doc.get("spec", {}).get("selector")
                if isinstance(selector, dict):
                    for selector_key, selector_value in selector.items():
                        if selector_key == "app":
                            target_id = _resource_id("Deployment", selector_value)
                            edges.append(GraphEdge(source=node_id, target=target_id, relation="selects"))
            elif kind == "Ingress":
                rules = doc.get("spec", {}).get("rules", [])
                if rules:
                    edges.append(GraphEdge(source=node_id, target="external.internet", relation="exposes"))

    return nodes, edges
