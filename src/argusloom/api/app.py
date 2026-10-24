"""FastAPI application exposing the graph and risk analysis endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from argusloom import __version__
from argusloom.analysis.threat_model import analyze_graph
from argusloom.api.routes.analysis import (
    AttackPathResponse,
    AttackPathsRequest,
    BlastRadiusResponse,
)
from argusloom.api.routes.rag import router as rag_router
from argusloom.domain.enums import Criticality, NodeKind, StrideCategory
from argusloom.domain.errors import NodeNotFound
from argusloom.domain.graph import Graph, GraphEdge, GraphNode
from argusloom.graph.blast_radius import compute_blast_radius
from argusloom.graph.pathfinding import find_attack_paths
from argusloom.graph.store import GraphStore
from argusloom.workflow.remediation import build_remediation_plan

logger = structlog.get_logger()


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
                cves=list(item.get("cves", []) or []),
                mitre_techniques=list(item.get("mitre_techniques", []) or []),
                cvss_max=float(item.get("cvss_max", 0.0)),
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


def _load_graph_from_store() -> Graph:
    fixture_path = Path("data/graph.json")
    if not fixture_path.exists():
        raise FileNotFoundError(f"Graph fixture not found at {fixture_path}")
    logger.info("graph_store.load", path=str(fixture_path))
    return GraphStore(fixture_path).load()


def create_app() -> FastAPI:
    app = FastAPI(title="ArgusLoom", version=__version__)
    app.include_router(rag_router)

    @app.exception_handler(NodeNotFound)
    async def node_not_found_handler(request: Any, exc: NodeNotFound) -> JSONResponse:
        logger.info("node_not_found", node_id=exc.node_id)
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "phase": 6}

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

    @app.get("/nodes/{node_id}/blast-radius")
    def blast_radius_endpoint(
        node_id: str,
        max_depth: int = Query(default=3, ge=0, le=10),
        weighted: bool = True,
    ) -> BlastRadiusResponse:
        graph = _load_graph_from_store()
        result = compute_blast_radius(
            graph, analyze_graph(graph), node_id, max_depth=max_depth, weighted=weighted
        )
        logger.info(
            "blast_radius.computed",
            node_id=node_id,
            n_nodes=len(result.nodes),
            weighted=weighted,
        )
        return BlastRadiusResponse(
            root_id=result.root_id,
            nodes=[node.to_dict() for node in result.nodes],
            edges=[edge.to_dict() for edge in result.edges],
            depth_map=result.depth_map,
            risk_score=result.risk_score,
            max_depth=result.max_depth,
        )

    @app.post("/attack-paths")
    def attack_paths_endpoint(payload: AttackPathsRequest) -> AttackPathResponse:
        graph = _load_graph_from_store()
        paths = find_attack_paths(
            graph,
            payload.source_id,
            payload.target_id,
            strategy=payload.strategy,
            top_k=payload.top_k,
        )
        logger.info(
            "attack_paths.computed",
            source_id=payload.source_id,
            target_id=payload.target_id,
            count=len(paths),
        )
        return AttackPathResponse(
            source_id=payload.source_id,
            target_id=payload.target_id,
            strategy=payload.strategy,
            paths=[
                {
                    "nodes": path.nodes,
                    "edges": [edge.to_dict() for edge in path.edges],
                    "score": path.score,
                    "mitre_chain": path.mitre_chain,
                    "length": path.length,
                }
                for path in paths
            ],
        )

    return app


app = create_app()
