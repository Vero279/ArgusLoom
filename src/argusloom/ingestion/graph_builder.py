"""Graph assembly and persistence utilities for the ingestion pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from argusloom.domain.graph import Graph
from argusloom.ingestion.k8s_parser import parse_kubernetes_directory
from argusloom.ingestion.terraform_parser import parse_terraform_directory


def build_graph(terraform_path: str | Path, k8s_path: str | Path, output_path: str | Path | None = None) -> Graph:
    """Build a unified graph from Terraform and Kubernetes inputs."""

    terraform_nodes, terraform_edges = parse_terraform_directory(terraform_path)
    k8s_nodes, k8s_edges = parse_kubernetes_directory(k8s_path)

    graph = Graph(nodes=[*terraform_nodes, *k8s_nodes], edges=[*terraform_edges, *k8s_edges])

    for edge in graph.edges:
        if edge.source == "external.internet":
            continue
        if edge.target == "external.internet":
            continue

    if output_path is not None:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(graph.to_dict(), indent=2), encoding="utf-8")

    return graph
