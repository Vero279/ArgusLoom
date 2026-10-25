"""Command line interface for ArgusLoom."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from argusloom import __version__
from argusloom.analysis.threat_model import analyze_graph
from argusloom.config import get_settings
from argusloom.cti.enrich import CTIEnricher
from argusloom.cti.mitre_loader import MITRELoader
from argusloom.cti.nvd_client import MockNVDClient
from argusloom.graph.pathfinding import find_attack_paths
from argusloom.graph.store import GraphStore
from argusloom.ingestion.graph_builder import build_graph
from argusloom.logging import get_logger, setup_logging

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Interactive Knowledge Graph for Dynamic Threat Modeling.",
)

logger = get_logger("argusloom.cli")


def _build_enriched_graph() -> object:
    root = Path.cwd()
    graph = build_graph(
        terraform_path=root / "data/fixtures/terraform",
        k8s_path=root / "data/fixtures/k8s",
        output_path=None,
    )
    nvd_client = MockNVDClient(root / "data/fixtures/cves.json")
    mitre_loader = MITRELoader(
        root / "data/mitre/attack.json",
        root / "data/mitre/atlas.json",
    )
    enriched = CTIEnricher(nvd=nvd_client, mitre=mitre_loader).enrich(graph)
    GraphStore(root / "data/graph.json").save(enriched)
    return enriched


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


@app.command()
def demo(
    regenerate: bool = typer.Option(
        True,
        "--regenerate/--no-regenerate",
        help="Regenerate graph.json from fixtures before summarizing.",
    ),
    serve: bool = typer.Option(
        False,
        "--serve/--no-serve",
        help="Start the API after printing the security summary.",
    ),
) -> None:
    """One-shot demo: ingest fixtures, enrich CTI, report summary."""
    if serve:
        import uvicorn

        uvicorn.run("argusloom.api.app:app", host="127.0.0.1", port=8000, reload=False)
        return

    graph = (
        _build_enriched_graph()
        if regenerate
        else GraphStore(Path("data/graph.json")).load()
    )
    findings = analyze_graph(graph)
    nodes = len(graph.nodes)
    edges = len(graph.edges)
    mitre_count = sum(1 for node in graph.nodes if node.mitre_techniques)
    cve_count = sum(1 for node in graph.nodes if node.cves)
    cvss_count = sum(1 for node in graph.nodes if node.cvss_max > 0)

    network_node = next(
        (node.id for node in graph.nodes if node.kind.value == "network"), None
    )
    data_node = next(
        (node.id for node in graph.nodes if node.kind.value == "data"), None
    )
    path_text = "No path available"
    if network_node and data_node:
        path = find_attack_paths(graph, network_node, data_node, top_k=1)
        if path:
            nodes_on_path = " -> ".join(path[0].nodes)
            path_text = (
                f"{nodes_on_path} (score {path[0].score:.2f}, {path[0].length} hops)"
            )

    typer.echo("=== ArgusLoom Demo ===")
    typer.echo(f"Nodes: {nodes}")
    typer.echo(f"Edges: {edges}")
    typer.echo(f"Nodes with MITRE techniques: {mitre_count}/{nodes}")
    typer.echo(f"Nodes with CVEs: {cve_count}/{nodes}")
    typer.echo(f"Nodes with cvss_max > 0: {cvss_count}/{nodes}")
    typer.echo("Top 3 by risk:")
    for index, finding in enumerate(findings[:3], start=1):
        typer.echo(f"  {index}. {finding.node_id} — score {finding.risk_score:.2f}")
    typer.echo(
        "Attack paths sample (top 1 from first network node to first data node):"
    )
    typer.echo(f"  {path_text}")
    typer.echo("===")


@app.command()
def serve() -> None:
    """Start the local FastAPI service."""
    import uvicorn

    uvicorn.run("argusloom.api.app:app", host="127.0.0.1", port=8000, reload=False)


@app.command("export-openapi")
def export_openapi(
    output: Annotated[Path, typer.Option("--out", "-o")] = Path(
        "data/fixtures/openapi.json"
    ),
) -> None:
    """Export the OpenAPI schema for frontend consumption."""
    import json

    from argusloom.api.app import create_app

    schema = create_app().openapi()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    typer.echo(f"OpenAPI exported to {output}")


if __name__ == "__main__":
    app()
