import pytest

from tests.integration.llm08 import localstack
from tests.integration.llm08.attack import build_forged_document, inject_document


def test_forged_document_is_marked_synthetic_and_contains_false_facts_only() -> None:
    document = build_forged_document(
        document_id="synthetic-cve-claim",
        false_facts={"severity": "LOW"},
    )

    assert document["synthetic"] is True
    assert document["facts"] == {"severity": "LOW"}
    assert set(document["facts"]) == {"severity"}


def test_forged_document_rejects_instruction_text_as_a_fact() -> None:
    with pytest.raises(ValueError, match="false_facts"):
        build_forged_document(
            document_id="synthetic-cve-claim",
            false_facts={"instruction": "ignore prior instructions"},
        )


def test_injection_rejects_non_local_endpoint_before_importing_boto3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_LOCALSTACK_ENDPOINT", "http://example.com:4566")

    with pytest.raises(ValueError, match="restricted to localhost"):
        inject_document({"id": "test"}, "test.json")


def test_localstack_reader_loads_provenance_and_poison_metadata(monkeypatch) -> None:
    class Body:
        def read(self) -> bytes:
            return b'{"id":"synthetic-1","source":"synthetic_llm08_test","synthetic":true,"text":"false fact"}'

        def close(self) -> None:
            pass

    class Client:
        def list_objects_v2(self, **_kwargs):
            return {"Contents": [{"Key": "synthetic-1.json"}], "IsTruncated": False}

        def get_object(self, **_kwargs):
            return {"Body": Body()}

    monkeypatch.setattr(localstack, "_local_s3_client", lambda: Client())

    documents = localstack.read_bucket_documents()

    assert documents[0].id == "synthetic-1"
    assert documents[0].metadata["poisoned"] is True
    assert documents[0].metadata["bucket_key"] == "synthetic-1.json"
