"""Chroma-backed vector store wrapper for semantic retrieval."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import chromadb


@dataclass(slots=True)
class VectorHit:
    id: str
    text: str
    metadata: dict
    score: float


class VectorStore:
    """Persisted collection wrapper for ChromaDB with minimal retrieval helpers."""

    def __init__(self, persist_dir: Path, collection_name: str = "argusloom") -> None:
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=str(self.persist_dir))
        self.collection_name = collection_name
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add(
        self,
        ids: Sequence[str],
        texts: Sequence[str],
        metadatas: Sequence[dict],
        embeddings: Sequence[Sequence[float]],
    ) -> None:
        if not ids:
            return
        self.collection.add(
            ids=list(ids),
            documents=list(texts),
            metadatas=list(metadatas),
            embeddings=[list(map(float, embedding)) for embedding in embeddings],
        )

    def query(
        self, query_embedding: Sequence[float], top_k: int = 5
    ) -> list[VectorHit]:
        result = self.collection.query(
            query_embeddings=[list(map(float, query_embedding))],
            n_results=max(1, int(top_k)),
            include=["distances", "documents", "metadatas"],
        )

        hits: list[VectorHit] = []
        ids = result.get("ids", [[]])[0]
        documents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        for index, document_id in enumerate(ids):
            distance = float(distances[index]) if index < len(distances) else 0.0
            score = max(0.0, 1.0 - distance)
            hits.append(
                VectorHit(
                    id=str(document_id),
                    text=str(documents[index]),
                    metadata=dict(metadatas[index] or {}),
                    score=score,
                )
            )
        return hits

    def reset(self) -> None:
        existing = [
            collection
            for collection in self.client.list_collections()
            if collection.name == self.collection_name
        ]
        if existing:
            self.client.delete_collection(name=self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def count(self) -> int:
        return int(self.collection.count())
