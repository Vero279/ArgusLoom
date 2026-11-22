import pytest

from argusloom.evaluation.ollama import OllamaClient, format_retrieved_context


def test_ollama_client_rejects_non_local_endpoint() -> None:
    with pytest.raises(ValueError, match="must use a local endpoint"):
        OllamaClient("https://ollama.example.com:11434")


def test_context_format_contains_document_provenance() -> None:
    formatted = format_retrieved_context(
        [
            {
                "id": "CVE-1",
                "text": "Retrieved text",
                "metadata": {"source": "NVD", "snapshot_hash": "abc"},
            }
        ]
    )

    assert "[document_id=CVE-1 source=NVD snapshot=abc]" in formatted
    assert "Retrieved text" in formatted


def test_context_format_rejects_missing_identifiers() -> None:
    with pytest.raises(TypeError, match="string id and text"):
        format_retrieved_context([{"text": "no identifier"}])
