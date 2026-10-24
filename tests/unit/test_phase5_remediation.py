from fastapi.testclient import TestClient

from argusloom.api.app import app
from argusloom.domain.enums import Criticality, NodeKind
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.workflow.remediation import build_remediation_plan


client = TestClient(app)


def test_build_remediation_plan_prioritizes_high_risk_exposure() -> None:
    graph = Graph(
        nodes=[
            GraphNode(
                id="k8s_ingress.web",
                kind=NodeKind.NETWORK,
                name="web",
                source="kubernetes",
                criticality=Criticality.HIGH,
                exposure=0.9,
                metadata={"cti": [{"source": "MITRE ATT&CK", "title": "Ingress exposure"}]},
                stride=["information_disclosure", "denial_of_service"],
            ),
            GraphNode(
                id="aws_db_instance.db",
                kind=NodeKind.DATA,
                name="db",
                source="terraform",
                criticality=Criticality.CRITICAL,
                exposure=0.7,
                metadata={"cti": [{"source": "NVD", "title": "Data store"}]},
                stride=["tampering", "information_disclosure"],
            ),
        ],
        edges=[GraphEdge(source="k8s_ingress.web", target="aws_db_instance.db", relation="depends_on")],
    )

    plan = build_remediation_plan(graph)

    assert plan
    assert plan[0]["node_id"] == "k8s_ingress.web"
    assert any("tls" in action.lower() or "ingress" in action.lower() for action in plan[0]["actions"])


def test_remediation_endpoint() -> None:
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
            }
        ],
        "edges": [],
    }

    response = client.post("/graph/remediation", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert "plan" in body
    assert body["plan"][0]["node_id"] == "k8s_ingress.web"
