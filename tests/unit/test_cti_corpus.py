import hashlib
import json

import pytest

from argusloom.cti.corpus import load_snapshot_corpus, mark_poisoned_document
from argusloom.domain.enums import NodeKind
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphNode


def test_snapshot_corpus_requires_exact_count_and_preserves_provenance(
    tmp_path,
) -> None:
    snapshot = tmp_path / "cves.json"
    snapshot.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2025-1234",
                            "published": "2025-01-01",
                            "descriptions": [
                                {"lang": "en", "value": "A test description."}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 7.5,
                                            "baseSeverity": "HIGH",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    snapshot_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest().upper()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "status": "ready",
                "snapshots": [
                    {
                        "path": "cves.json",
                        "source": "fixture-source",
                        "sha256": snapshot_hash,
                        "experiment_eligible": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    documents, corpus_hash = load_snapshot_corpus(tmp_path, manifest, expected_count=1)

    assert documents[0].id == "CVE-2025-1234"
    assert documents[0].metadata["snapshot_hash"] == snapshot_hash
    assert documents[0].metadata["severity"] == "HIGH"
    assert corpus_hash


def test_snapshot_corpus_rejects_duplicate_document_ids(tmp_path) -> None:
    snapshot = tmp_path / "mitre.json"
    snapshot.write_text(
        json.dumps(
            [
                {"id": "T1000", "name": "First"},
                {"id": "T1000", "name": "Duplicate"},
            ]
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "status": "ready",
                "snapshots": [
                    {
                        "path": "mitre.json",
                        "source": "fixture-source",
                        "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                        "experiment_eligible": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate CTI document id"):
        load_snapshot_corpus(tmp_path, manifest, expected_count=2)


def test_poisoned_document_marks_only_its_related_node() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="aws_db_instance.database",
                kind=NodeKind.DATA,
                name="database",
                source="terraform",
            )
        ]
    )

    marked = mark_poisoned_document(graph, "aws_db_instance.database", "synthetic-1")

    assert marked.nodes[0].metadata["poisoned"] is True
    assert marked.nodes[0].metadata["poisoned_documents"] == ["synthetic-1"]
    assert graph.nodes[0].metadata == {}
    with pytest.raises(NodeNotFound):
        mark_poisoned_document(graph, "missing", "synthetic-1")


def test_corpus_loader_excludes_prompt_injection_records(tmp_path) -> None:
    snapshot = tmp_path / "atlas.json"
    snapshot.write_text(
        json.dumps(
            [
                {
                    "id": "AML.T0051.001",
                    "name": "LLM Prompt Injection: Indirect",
                    "description": "Place instructions in retrieved content.",
                },
                {
                    "id": "AML.T0071",
                    "name": "False RAG Entry Injection",
                    "description": "Insert false records into a retrieval corpus.",
                },
            ]
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "status": "ready",
                "snapshots": [
                    {
                        "path": "atlas.json",
                        "source": "fixture-source",
                        "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                        "experiment_eligible": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    documents, _ = load_snapshot_corpus(tmp_path, manifest, expected_count=1)

    assert [document.id for document in documents] == ["AML.T0071"]
