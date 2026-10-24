"""FastAPI application exposing the graph and risk analysis endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from argusloom import __version__
from argusloom.analysis.threat_model import analyze_graph
from argusloom.domain.enums import Criticality, NodeKind, StrideCategory
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.workflow.remediation import build_remediation_plan


def _parse_stride(value: Any) -> StrideCategory | None:
    if value is None:
        return None
    text = str(value).strip()
    try:
        return StrideCategory(text)
    except ValueError:
        normalized = text.replace("-", "_").replace(" ", "_")
        try:
            return StrideCategory(normalized)
        except ValueError:
            return None


def _graph_from_payload(payload: dict[str, Any]) -> Graph:
    nodes: list[GraphNode] = []
    for item in payload.get("nodes", []):
        kind = NodeKind(str(item.get("kind", "compute")).strip().lower())
        criticality = Criticality(str(item.get("criticality", "low")).strip().lower())
        stride = []
        for raw_stride in item.get("stride", []):
            parsed = _parse_stride(raw_stride)
            if parsed is not None:
                stride.append(parsed)

        nodes.append(
            GraphNode(
                id=str(item["id"]),
                kind=kind,
                name=str(item.get("name", item["id"])),
                source=str(item.get("source", "manual")),
                criticality=criticality,
                exposure=float(item.get("exposure", 0.0)),
                metadata=dict(item.get("metadata", {}) or {}),
                stride=stride,
            )
        )

    edges: list[GraphEdge] = []
    for item in payload.get("edges", []):
        edges.append(
            GraphEdge(
                source=str(item["source"]),
                target=str(item["target"]),
                relation=str(item.get("relation", "depends_on")),
                confidence=float(item.get("confidence", 1.0)),
                metadata=dict(item.get("metadata", {}) or {}),
            )
        )

    return Graph(nodes=nodes, edges=edges)


def create_app() -> FastAPI:
    app = FastAPI(title="ArgusLoom", version=__version__)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "phase": 4}

    @app.get("/")
    def root() -> dict[str, str]:
        return {"service": "argusloom", "version": __version__}

    @app.post("/graph/analyze")
    def analyze_graph_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        graph = _graph_from_payload(payload)
        findings = analyze_graph(graph)
        return {
            "findings": [
                {
                    "node_id": item.node_id,
                    "risk_score": round(item.risk_score, 2),
                    "threats": item.threats,
                    "rationale": item.rationale,
                }
                for item in findings
            ]
        }

    @app.post("/graph/remediation")
    def remediation_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        graph = _graph_from_payload(payload)
        plan = build_remediation_plan(graph)
        return {"plan": plan}

    return app


app = create_app()
