"""Generate deterministic, CTI-enriched graphs from demo scenarios.

Usage:
  python ingest.py --scenario A
  python ingest.py --scenario B
  python ingest.py --scenario C
  python ingest.py --scenario C --out data/graph.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

from argusloom.cti.enrich import CTIEnricher
from argusloom.cti.mitre_loader import MITRELoader
from argusloom.cti.nvd_client import MockNVDClient
from argusloom.domain.graph import Graph
from argusloom.ingestion.graph_builder import build_graph

ROOT = Path(__file__).resolve().parent
SCENARIOS = {
    "A": ROOT / "data/fixtures/scenarios/A_terraform_only",
    "B": ROOT / "data/fixtures/scenarios/B_k8s_only",
    "C": ROOT / "data/fixtures/scenarios/C_hybrid",
}


def _empty_directory(stack: ExitStack) -> Path:
    return Path(stack.enter_context(tempfile.TemporaryDirectory()))


def _build_scenario_graph(scenario: str) -> Graph:
    scenario_dir = SCENARIOS[scenario]
    terraform_path = scenario_dir if (scenario_dir / "main.tf").is_file() else None
    k8s_path = scenario_dir if (scenario_dir / "app.yaml").is_file() else None

    with ExitStack() as stack:
        graph = build_graph(
            terraform_path=terraform_path or _empty_directory(stack),
            k8s_path=k8s_path or _empty_directory(stack),
        )

    enricher = CTIEnricher(
        nvd=MockNVDClient(ROOT / "data/fixtures/cves.json"),
        mitre=MITRELoader(
            ROOT / "data/mitre/attack.json",
            ROOT / "data/mitre/atlas.json",
        ),
    )
    return enricher.enrich(graph)


def _summary(scenario: str, graph: Graph, output_path: Path) -> str:
    node_count = len(graph.nodes)
    edge_count = len(graph.edges)
    mitre_count = sum(bool(node.mitre_techniques) for node in graph.nodes)
    cve_count = sum(bool(node.cves) for node in graph.nodes)
    cvss_count = sum(node.cvss_max > 0 for node in graph.nodes)

    def percent(count: int) -> str:
        return f"{count / node_count * 100:.1f}%"

    edge_list = "; ".join(
        f"{edge.source} -> {edge.target} ({edge.relation})" for edge in graph.edges
    )
    return (
        f"Scenario {scenario} | nodes={node_count} | edges={edge_count} | "
        f"MITRE={mitre_count}/{node_count} ({percent(mitre_count)}) | "
        f"CVE={cve_count}/{node_count} ({percent(cve_count)}) | "
        f"cvss>0={cvss_count}/{node_count} ({percent(cvss_count)}) | "
        f"output={output_path.relative_to(ROOT) if output_path.is_relative_to(ROOT) else output_path} | "
        f"edge list: {edge_list}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument(
        "--out", type=Path, help="Output path (default: data/graph_<scenario>.json)"
    )
    args = parser.parse_args()

    graph = _build_scenario_graph(args.scenario)
    output_path = args.out or ROOT / f"data/graph_{args.scenario}.json"
    if not output_path.is_absolute():
        output_path = ROOT / output_path

    if not graph.nodes or not graph.edges:
        print(
            f"Scenario {args.scenario} failed: parser produced "
            f"{len(graph.nodes)} nodes and {len(graph.edges)} edges.",
            file=sys.stderr,
        )
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(graph.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(_summary(args.scenario, graph, output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
