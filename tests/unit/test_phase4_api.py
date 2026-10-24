from fastapi.testclient import TestClient

from argusloom.api.app import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_graph_analysis_endpoint() -> None:
    payload = {
        "nodes": [
            {
                "id": "k8s_ingress.web",
                "kind": "network",
                "name": "web",
                "source": "kubernetes",
                "criticality": "high",
                "exposure": 0.9,
                "metadata": {"cti": [{"source": "MITRE ATT&CK", "title": "Ingress exposure"}]},
                "stride": ["information_disclosure", "denial_of_service"],
            },
            {
                "id": "aws_db_instance.db",
                "kind": "data",
                "name": "db",
                "source": "terraform",
                "criticality": "critical",
                "exposure": 0.7,
                "metadata": {"cti": [{"source": "NVD", "title": "Data store"}]},
                "stride": ["tampering", "information_disclosure"],
            },
        ],
        "edges": [{"source": "k8s_ingress.web", "target": "aws_db_instance.db", "relation": "depends_on"}],
    }

    response = client.post("/graph/analyze", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert "findings" in body
    assert len(body["findings"]) >= 2
    assert any(item["node_id"] == "k8s_ingress.web" for item in body["findings"])
