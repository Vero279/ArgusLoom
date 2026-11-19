"""Normalise Checkov JSON findings and attach them to graph resources."""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from typing import Any

from argusloom.domain.graph import Graph


def parse_checkov_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return stable finding records from a Checkov JSON report."""

    results = report.get("results", {})
    if not isinstance(results, dict):
        raise TypeError("Checkov report results must be an object")

    checks = results.get("failed_checks", [])
    if not isinstance(checks, list):
        raise TypeError("Checkov failed_checks must be a list")

    findings: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise TypeError("Checkov finding must be an object")
        resource_id = check.get("resource")
        check_id = check.get("check_id")
        if not isinstance(resource_id, str) or not resource_id:
            raise TypeError("Checkov finding resource must be a non-empty string")
        if not isinstance(check_id, str) or not check_id:
            raise TypeError("Checkov finding check_id must be a non-empty string")
        findings.append(
            {
                "source": "checkov",
                "check_id": check_id,
                "title": str(check.get("check_name", "")),
                "severity": str(check.get("severity") or "UNKNOWN").upper(),
                "resource_id": resource_id,
                "file_path": str(check.get("file_path", "")),
                "status": "failed",
                "guideline": str(check.get("guideline") or ""),
            }
        )
    return findings


def annotate_graph_with_checkov(
    graph: Graph,
    findings: list[dict[str, Any]],
) -> Graph:
    """Copy the graph and attach findings to matching resource nodes."""

    annotated = Graph(nodes=deepcopy(graph.nodes), edges=deepcopy(graph.edges))
    nodes_by_id = {node.id: node for node in annotated.nodes}
    for finding in findings:
        resource_id = finding.get("resource_id")
        if not isinstance(resource_id, str) or resource_id not in nodes_by_id:
            continue
        node = nodes_by_id[resource_id]
        metadata = dict(node.metadata)
        existing = metadata.get("checkov_findings", [])
        if not isinstance(existing, list):
            raise TypeError(
                f"Node '{resource_id}' metadata checkov_findings must be a list"
            )
        metadata["checkov_findings"] = [*existing, dict(finding)]
        node.metadata = metadata
        for edge in annotated.edges:
            if resource_id not in {edge.source, edge.target}:
                continue
            edge_metadata = dict(edge.metadata)
            edge_findings = edge_metadata.get("checkov_findings", [])
            if not isinstance(edge_findings, list):
                raise TypeError("Edge metadata checkov_findings must be a list")
            edge_metadata["checkov_findings"] = [*edge_findings, dict(finding)]
            edge.metadata = edge_metadata
    return annotated


def run_checkov(terraform_directory: str) -> tuple[int, list[dict[str, Any]]]:
    """Run Checkov for Terraform and return its findings, including fail status."""

    completed = subprocess.run(
        [
            "checkov",
            "--directory",
            terraform_directory,
            "--framework",
            "terraform",
            "--output",
            "json",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(
            f"Checkov failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Checkov did not return valid JSON output") from exc
    if not isinstance(report, dict):
        raise TypeError("Checkov JSON output must be an object")
    return completed.returncode, parse_checkov_findings(report)
