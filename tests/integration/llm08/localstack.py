"""LocalStack S3 corpus loading and fixed-policy control checks."""

from __future__ import annotations

import json
from typing import Any

from argusloom.rag.retriever import CTIDocument, CTIRetriever
from tests.integration.llm08.attack import CTI_BUCKET, _local_s3_client


def read_bucket_documents() -> list[CTIDocument]:
    client = _local_s3_client()
    documents: list[CTIDocument] = []
    continuation_token: str | None = None
    while True:
        request: dict[str, Any] = {"Bucket": CTI_BUCKET}
        if continuation_token:
            request["ContinuationToken"] = continuation_token
        response = client.list_objects_v2(**request)
        for item in response.get("Contents", []):
            key = item.get("Key")
            if not isinstance(key, str):
                raise TypeError("S3 object listing returned an invalid object key")
            result = client.get_object(Bucket=CTI_BUCKET, Key=key)
            body = result["Body"]
            try:
                payload = json.loads(body.read().decode("utf-8"))
            finally:
                body.close()
            if not isinstance(payload, dict):
                raise TypeError(f"CTI object '{key}' must contain a JSON object")
            document_id = payload.get("id", key)
            if not isinstance(document_id, str) or not document_id:
                raise TypeError(f"CTI object '{key}' has no usable document id")
            text = payload.get("text")
            if not isinstance(text, str):
                text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
            documents.append(
                CTIDocument(
                    id=document_id,
                    text=text,
                    metadata={
                        "source": str(payload.get("source", "localstack_s3")),
                        "bucket_key": key,
                        "snapshot_hash": str(payload.get("snapshot_hash", "unknown")),
                        "poisoned": bool(payload.get("synthetic", False)),
                    },
                )
            )
        if not response.get("IsTruncated", False):
            break
        continuation_token = response.get("NextContinuationToken")
        if not isinstance(continuation_token, str) or not continuation_token:
            raise TypeError("Truncated S3 listing did not provide a continuation token")
    if not documents:
        raise ValueError("CTI corpus bucket is empty")
    return documents


def reindex_localstack_corpus(retriever: CTIRetriever) -> int:
    documents = read_bucket_documents()
    retriever.store.reset()
    retriever.index_documents(documents)
    return len(documents)


def verify_fixed_bucket_rejects_write(object_key: str) -> None:
    """Fail unless a non-role LocalStack client is denied a bucket write."""

    from botocore.exceptions import ClientError

    client = _local_s3_client()
    try:
        client.put_object(
            Bucket=CTI_BUCKET,
            Key=object_key,
            Body=b'{"synthetic":true}',
            ContentType="application/json",
        )
    except ClientError as exc:
        error_code = str(exc.response.get("Error", {}).get("Code", ""))
        if error_code not in {"AccessDenied", "403"}:
            raise RuntimeError(
                f"Expected S3 write denial, received {error_code or 'unknown error'}"
            ) from exc
        return
    raise AssertionError("Fixed LocalStack bucket unexpectedly accepted a write")
