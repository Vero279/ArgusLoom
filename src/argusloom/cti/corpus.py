"""Load and deterministically re-index source-snapshotted CTI documents."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from argusloom.cti.snapshots import (
    require_experiment_ready_manifest,
    verify_snapshot_manifest,
)
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph
from argusloom.rag.retriever import CTIDocument, CTIRetriever

_EXCLUDED_PROMPT_INJECTION_IDS = {
    "AML.T0051",
    "AML.T0051.001",
    "AML.T0054",
    "AML.T0065",
}


def _nvd_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD snapshot must contain a vulnerabilities list")

    records: list[dict[str, Any]] = []
    for item in vulnerabilities:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
            raise ValueError("NVD vulnerability must contain a CVE id")
        description = next(
            (
                entry.get("value", "")
                for entry in cve.get("descriptions", [])
                if entry.get("lang") == "en"
            ),
            "",
        )
        metrics = cve.get("metrics", {})
        cvss = 0.0
        severity = "UNKNOWN"
        for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_entries = metrics.get(metric_name, [])
            if metric_entries:
                cvss_data = metric_entries[0].get("cvssData", {})
                cvss = float(cvss_data.get("baseScore", 0.0))
                severity = str(
                    cvss_data.get("baseSeverity")
                    or metric_entries[0].get("baseSeverity")
                    or "UNKNOWN"
                ).upper()
                break
        records.append(
            {
                "id": cve["id"],
                "name": cve["id"],
                "description": str(description),
                "cvss_score": cvss,
                "severity": severity,
                "published": cve.get("published"),
            }
        )
    return records


def _mitre_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        objects = payload
    elif isinstance(payload, dict):
        objects = payload.get("objects", payload.get("techniques"))
    else:
        objects = None
    if not isinstance(objects, list):
        raise ValueError("MITRE snapshot must contain a records list")

    records: list[dict[str, Any]] = []
    for item in objects:
        if not isinstance(item, dict):
            continue
        external_id = item.get("id")
        for reference in item.get("external_references", []):
            if isinstance(reference, dict) and reference.get("external_id"):
                external_id = reference["external_id"]
                break
        name = item.get("name", item.get("title", external_id))
        if not isinstance(external_id, str) or not isinstance(name, str):
            continue
        description = item.get("description", "")
        combined_text = f"{name} {description}".casefold()
        if external_id in _EXCLUDED_PROMPT_INJECTION_IDS or any(
            phrase in combined_text
            for phrase in ("prompt injection", "indirect prompt", "jailbreak")
        ):
            continue
        records.append(
            {
                "id": external_id,
                "name": name,
                "description": str(description or ""),
                "tactic": str(item.get("tactic", "")),
            }
        )
    return records


def load_snapshot_corpus(
    repository_root: str | Path,
    manifest_path: str | Path,
    *,
    expected_count: int = 300,
) -> tuple[list[CTIDocument], str]:
    """Load exactly the eligible corpus described by a verified manifest."""

    root = Path(repository_root).resolve()
    manifest_file = Path(manifest_path)
    if not manifest_file.is_absolute():
        manifest_file = root / manifest_file
    manifest = require_experiment_ready_manifest(manifest_file)
    verified = verify_snapshot_manifest(root, manifest_file)
    documents: list[CTIDocument] = []
    seen_ids: set[str] = set()

    for snapshot in verified:
        if not snapshot.get("experiment_eligible"):
            raise ValueError(f"Snapshot is not experiment-eligible: {snapshot['path']}")
        source_path = root / snapshot["path"]
        suffix = source_path.suffix.casefold()
        if suffix == ".json":
            payload = json.loads(source_path.read_text(encoding="utf-8"))
        elif suffix in {".yaml", ".yml"}:
            payload = yaml.safe_load(source_path.read_text(encoding="utf-8"))
        else:
            raise ValueError(f"Unsupported CTI snapshot format: {source_path.suffix}")

        if isinstance(payload, dict) and "vulnerabilities" in payload:
            records = _nvd_records(payload)
        else:
            records = _mitre_records(payload)
        for record in records:
            document_id = str(record["id"])
            if document_id in seen_ids:
                raise ValueError(f"Duplicate CTI document id: {document_id}")
            seen_ids.add(document_id)
            text = " | ".join(
                str(record.get(field, ""))
                for field in ("id", "name", "description", "severity", "cvss_score", "tactic")
                if record.get(field) not in (None, "")
            )
            documents.append(
                CTIDocument(
                    id=document_id,
                    text=text,
                    metadata={
                        "source": snapshot["source"],
                        "snapshot_hash": snapshot["sha256"],
                        "record_type": "nvd" if "vulnerabilities" in (
                            payload if isinstance(payload, dict) else {}
                        ) else "mitre",
                        "severity": str(record.get("severity", "UNKNOWN")),
                        "cvss_score": float(record.get("cvss_score", 0.0)),
                    },
                )
            )

    if len(documents) != expected_count:
        raise ValueError(
            f"Expected {expected_count} CTI documents, found {len(documents)}"
        )
    corpus_hash = hashlib.sha256(
        json.dumps(
            [
                {"id": document.id, "text": document.text, "metadata": document.metadata}
                for document in sorted(documents, key=lambda value: value.id)
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return documents, corpus_hash


def reindex_snapshot_corpus(
    retriever: CTIRetriever,
    repository_root: str | Path,
    manifest_path: str | Path,
    *,
    expected_count: int = 300,
) -> str:
    documents, corpus_hash = load_snapshot_corpus(
        repository_root,
        manifest_path,
        expected_count=expected_count,
    )
    retriever.store.reset()
    retriever.index_documents(documents)
    return corpus_hash


def mark_poisoned_document(
    graph: Graph,
    node_id: str,
    document_id: str,
) -> Graph:
    """Return a graph copy marking the asset whose CTI record was poisoned."""

    if not document_id.strip():
        raise ValueError("document_id must not be empty")
    marked = Graph(nodes=deepcopy(graph.nodes), edges=deepcopy(graph.edges))
    node = next((item for item in marked.nodes if item.id == node_id), None)
    if node is None:
        raise NodeNotFound(node_id)
    node.metadata = dict(node.metadata)
    document_ids = list(node.metadata.get("poisoned_documents", []))
    if document_id not in document_ids:
        document_ids.append(document_id)
    node.metadata["poisoned"] = True
    node.metadata["poisoned_documents"] = document_ids
    return marked
