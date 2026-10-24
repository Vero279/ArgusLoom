from fastapi.testclient import TestClient

from argusloom.api.app import app

client = TestClient(app)


def test_rag_query_returns_hits() -> None:
    response = client.post("/rag/query", json={"query": "network exposure", "top_k": 3})

    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["hits"]) >= 1


def test_rag_query_respects_top_k() -> None:
    response = client.post("/rag/query", json={"query": "iam privilege", "top_k": 1})

    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["hits"]) == 1


def test_rag_query_include_llm_answer_returns_text() -> None:
    response = client.post(
        "/rag/query", json={"query": "network exposure", "include_llm_answer": True}
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["llm_answer"]
