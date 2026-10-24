from argusloom.ingestion.k8s_parser import parse_kubernetes_directory


def test_parse_kubernetes_directory_creates_expected_nodes() -> None:
    nodes, edges = parse_kubernetes_directory("data/fixtures/k8s")

    node_ids = {node.id for node in nodes}
    assert "k8s_deployment.web" in node_ids
    assert "k8s_service.web-svc" in node_ids
    assert "k8s_ingress.web-ingress" in node_ids
    assert "k8s_configmap.web-config" in node_ids
    assert "k8s_secret.web-secret" in node_ids
    assert "k8s_serviceaccount.web-sa" in node_ids
    assert len(edges) >= 1


def test_kubernetes_parser_builds_selector_edges() -> None:
    _, edges = parse_kubernetes_directory("data/fixtures/k8s")

    assert any(edge.source == "k8s_service.web-svc" and edge.target == "k8s_deployment.web" for edge in edges)


def test_kubernetes_parser_handles_empty_directory() -> None:
    nodes, edges = parse_kubernetes_directory("data/fixtures/empty")
    assert nodes == []
    assert edges == []
