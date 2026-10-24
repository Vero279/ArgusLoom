"""Domain-specific exceptions for ArgusLoom."""

from __future__ import annotations


class ArgusLoomError(Exception):
    """Base exception for all domain-level ArgusLoom failures."""


class NodeNotFound(ArgusLoomError):
    """Raised when a graph node cannot be resolved by identifier."""

    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        super().__init__(f"Node '{node_id}' not found")


class IngestionError(ArgusLoomError):
    """Raised when ingestion fails to parse or normalize input data."""
