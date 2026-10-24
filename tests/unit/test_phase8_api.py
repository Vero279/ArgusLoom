from fastapi.testclient import TestClient

from argusloom.api.app import create_app


def test_cti_enrich_endpoint_returns_enriched_graph() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/cti/enrich",
        json={
            "graph": {
                "nodes": [
                    {
                        "id": "public-api",
                        "kind": "network",
                        "name": "public api",
                        "source": "test",
                    },
                    {
                        "id": "s3-data",
                        "kind": "data",
                        "name": "s3 data bucket",
                        "source": "test",
                        "metadata": {"resource_type": "AWS S3 bucket"},
                    },
                ],
                "edges": [],
            }
        },
    )

    assert response.status_code == 200
    nodes = response.json()["graph"]["nodes"]
    assert any(node["mitre_techniques"] for node in nodes)
    assert any(node["cves"] for node in nodes)


def test_cti_enrich_endpoint_reports_enriched_node_count() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/cti/enrich",
        json={
            "graph": {
                "nodes": [
                    {
                        "id": "public-api",
                        "kind": "network",
                        "name": "public api",
                        "source": "test",
                    }
                ],
                "edges": [],
            }
        },
    )

    assert response.status_code == 200
    assert response.json()["enriched_count"] > 0
