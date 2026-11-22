from argusloom.domain.enums import NodeKind
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.ingestion.checkov import (
    annotate_graph_with_checkov,
    parse_checkov_findings,
)


def test_checkov_findings_are_normalized_and_annotate_matching_node() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="aws_s3_bucket.cti_corpus",
                kind=NodeKind.STORAGE,
                name="cti_corpus",
                source="terraform",
            )
        ],
        edges=[
            GraphEdge(
                source="aws_s3_bucket.cti_corpus",
                target="rag.cti_index",
                relation="feeds",
            )
        ],
    )
    report = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "Bucket allows public access",
                    "severity": "HIGH",
                    "resource": "aws_s3_bucket.cti_corpus",
                    "file_path": "/terraform/main.tf",
                }
            ]
        }
    }

    findings = parse_checkov_findings(report)
    annotated = annotate_graph_with_checkov(graph, findings)

    assert annotated.nodes[0].metadata["checkov_findings"] == findings
    assert annotated.edges[0].metadata["checkov_findings"] == findings
    assert graph.nodes[0].metadata == {}
    assert findings[0]["status"] == "failed"


def test_checkov_parser_rejects_malformed_failed_checks() -> None:
    try:
        parse_checkov_findings({"results": {"failed_checks": {}}})
    except TypeError as exc:
        assert "failed_checks must be a list" in str(exc)
    else:
        raise AssertionError("Expected malformed Checkov results to fail")
