"""Pydantic models and serializers for graph analysis endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class BlastRadiusResponse(BaseModel):
    root_id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    depth_map: dict[str, int]
    risk_score: float
    max_depth: int


class AttackPathsRequest(BaseModel):
    source_id: str
    target_id: str
    strategy: Literal["dijkstra", "bfs"] = "dijkstra"
    top_k: int = Field(default=3, ge=1, le=10)


class AttackPathResponse(BaseModel):
    source_id: str
    target_id: str
    strategy: str
    paths: list[dict[str, Any]]
