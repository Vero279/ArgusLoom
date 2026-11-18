"""Test-only synthetic corpus poisoning helpers restricted to local LocalStack."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

LOCALSTACK_ENDPOINT = "http://127.0.0.1:4566"
CTI_BUCKET = "argusloom-cti-corpus"
_FACT_FIELDS = {
    "cve_id",
    "severity",
    "cvss_score",
    "applies_to_node",
    "path_risk",
}
_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def build_forged_document(
    *,
    document_id: str,
    false_facts: dict[str, Any],
) -> dict[str, Any]:
    """Create an explicitly synthetic false-fact record, never model instructions."""

    if not isinstance(document_id, str) or not document_id.strip():
        raise ValueError("document_id must not be empty")
    if not false_facts or not set(false_facts).issubset(_FACT_FIELDS):
        raise ValueError("false_facts must be a non-empty object")
    for key, value in false_facts.items():
        if key == "severity" and (
            not isinstance(value, str) or value not in _RISK_LEVELS
        ):
            raise ValueError("severity must be a recognised severity label")
        if key == "path_risk" and (
            not isinstance(value, str) or value not in _RISK_LEVELS
        ):
            raise ValueError("path_risk must be a recognised risk label")
        if key == "cve_id" and (
            not isinstance(value, str)
            or re.fullmatch(r"CVE-\d{4}-\d{4,}", value) is None
        ):
            raise ValueError("cve_id must have the standard CVE identifier form")
        if key == "applies_to_node" and (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None
        ):
            raise ValueError("applies_to_node must be a graph node identifier")
        if key == "cvss_score" and (
            not isinstance(value, (int, float)) or not 0 <= value <= 10
        ):
            raise ValueError("cvss_score must be between 0 and 10")

    return {
        "id": document_id,
        "source": "synthetic_llm08_test",
        "synthetic": True,
        "facts": false_facts,
    }


def inject_document(document: dict[str, Any], object_key: str) -> None:
    """Upload a synthetic record to the fixed local S3 endpoint only."""

    client = _local_s3_client()
    client.put_object(
        Bucket=CTI_BUCKET,
        Key=object_key,
        Body=json.dumps(document, sort_keys=True).encode("utf-8"),
        ContentType="application/json",
    )


def _local_s3_client() -> Any:
    endpoint = os.environ.get("ARGUS_LOCALSTACK_ENDPOINT", LOCALSTACK_ENDPOINT)
    parsed = urlparse(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("LLM08 injection is restricted to localhost LocalStack")
    if parsed.port != 4566 or parsed.path not in {"", "/"}:
        raise ValueError("LLM08 injection requires the LocalStack S3 endpoint on port 4566")
    if endpoint.rstrip("/") != LOCALSTACK_ENDPOINT:
        raise ValueError("LLM08 injection requires the configured fixed LocalStack endpoint")

    import boto3

    return boto3.client(
        "s3",
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
