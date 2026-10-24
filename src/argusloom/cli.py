"""Command line interface for ArgusLoom."""

from __future__ import annotations

import json

import typer

from argusloom import __version__
from argusloom.config import get_settings
from argusloom.logging import get_logger, setup_logging

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Interactive Knowledge Graph for Dynamic Threat Modeling.",
)

logger = get_logger("argusloom.cli")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logs."),
) -> None:
    """Configure the application entry point."""

    settings = get_settings()
    setup_logging(settings.log_level if not verbose else "DEBUG")
    logger.info("cli.start", app_name=settings.app_name)


@app.command()
def version() -> None:
    """Print the application version."""

    typer.echo(__version__)


@app.command()
def health() -> None:
    """Return a simple health payload for local checks."""

    typer.echo(json.dumps({"status": "ok", "version": __version__}))


if __name__ == "__main__":
    app()
