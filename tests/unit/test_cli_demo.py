from typer.testing import CliRunner

from argusloom.cli import app


def test_demo_command_reports_summary() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["demo", "--no-regenerate", "--no-serve"])

    assert result.exit_code == 0
    assert "ArgusLoom Demo" in result.output
    assert "Nodes:" in result.output
    assert "Edges:" in result.output
    assert "Top 3 by risk:" in result.output
