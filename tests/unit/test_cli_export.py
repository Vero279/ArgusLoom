import json

from typer.testing import CliRunner

from argusloom.cli import app


def test_export_openapi_creates_schema(tmp_path) -> None:
    output_file = tmp_path / "openapi.json"
    runner = CliRunner()

    result = runner.invoke(app, ["export-openapi", "--out", str(output_file)])

    assert result.exit_code == 0
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert "openapi" in payload
    assert "paths" in payload
    assert len(payload["paths"]) >= 8
