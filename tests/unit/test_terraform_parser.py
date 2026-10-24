from argusloom.domain.enums import Criticality, NodeKind
from argusloom.ingestion.terraform_parser import parse_terraform_directory


def test_parse_terraform_directory_builds_common_aws_assets() -> None:
    nodes, edges = parse_terraform_directory("data/fixtures/terraform")

    node_ids = {node.id for node in nodes}
    assert "aws_vpc.main" in node_ids
    assert "aws_instance.web" in node_ids
    assert "aws_s3_bucket.logs" in node_ids
    assert "aws_iam_role.lambda_exec" in node_ids
    assert "aws_security_group.app" in node_ids
    assert all(node.kind in NodeKind for node in nodes)


def test_terraform_parser_sets_security_group_exposure() -> None:
    nodes, _ = parse_terraform_directory("data/fixtures/terraform")
    security_group = next(node for node in nodes if node.id == "aws_security_group.app")

    assert security_group.exposure > 0.0
    assert security_group.criticality in {Criticality.medium, Criticality.high, Criticality.critical}


def test_terraform_parser_derives_edges_from_references() -> None:
    _, edges = parse_terraform_directory("data/fixtures/terraform")

    assert any(edge.source == "aws_security_group.app" and edge.target == "aws_instance.web" for edge in edges)
    assert any(edge.source == "aws_iam_role.lambda_exec" and edge.target == "aws_lambda_function.handler" for edge in edges)


def test_terraform_parser_handles_empty_directory() -> None:
    nodes, edges = parse_terraform_directory("data/fixtures/empty")
    assert nodes == []
    assert edges == []
