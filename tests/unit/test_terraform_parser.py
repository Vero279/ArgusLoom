from pathlib import Path

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


def test_terraform_parser_detects_nested_environment_reference(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "argus-logs-demo"
}

resource "aws_lambda_function" "handler" {
  function_name = "argus-handler"
  environment {
    variables = {
      LOGS_BUCKET = aws_s3_bucket.logs.bucket
    }
  }
}
""",
        encoding="utf-8",
    )

    _, edges = parse_terraform_directory(tmp_path)

    assert any(
        edge.source == "aws_lambda_function.handler"
        and edge.target == "aws_s3_bucket.logs"
        and edge.relation == "depends_on"
        for edge in edges
    )


def test_terraform_parser_attaches_security_group_to_lambda(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """
resource "aws_security_group" "public" {
  name = "public"
}

resource "aws_lambda_function" "handler" {
  function_name = "handler"
  vpc_security_group_ids = [aws_security_group.public.id]
}
""",
        encoding="utf-8",
    )

    _, edges = parse_terraform_directory(tmp_path)

    assert any(
        edge.source == "aws_security_group.public"
        and edge.target == "aws_lambda_function.handler"
        and edge.relation == "attached_to"
        for edge in edges
    )


def test_terraform_parser_attaches_security_group_to_db(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """
resource "aws_security_group" "public" {
  name = "public"
}

resource "aws_db_instance" "db" {
  allocated_storage = 20
  engine = "postgres"
  vpc_security_group_ids = [aws_security_group.public.id]
}
""",
        encoding="utf-8",
    )

    _, edges = parse_terraform_directory(tmp_path)

    assert any(
        edge.source == "aws_security_group.public"
        and edge.target == "aws_db_instance.db"
        and edge.relation == "attached_to"
        for edge in edges
    )
