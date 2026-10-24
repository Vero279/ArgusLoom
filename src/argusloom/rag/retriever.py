"""Vector-based CTI retriever built on the graph and document store."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from argusloom.domain.graph import Graph
from argusloom.rag.embeddings import EmbeddingModel
from argusloom.rag.vector_store import VectorHit, VectorStore


@dataclass(slots=True)
class CTIDocument:
    id: str
    text: str
    metadata: dict[str, Any]


class CTIRetriever:
    def __init__(self, embeddings: EmbeddingModel, store: VectorStore) -> None:
        self.embeddings = embeddings
        self.store = store

    def index_documents(self, docs: list[CTIDocument]) -> None:
        if not docs:
            return
        texts = [document.text for document in docs]
        embeddings = self.embeddings.embed(texts)
        self.store.add(
            ids=[document.id for document in docs],
            texts=texts,
            metadatas=[document.metadata for document in docs],
            embeddings=embeddings,
        )

    def index_graph(self, graph: Graph) -> None:
        docs: list[CTIDocument] = []
        for node in graph.nodes:
            tags = (
                ", ".join(node.mitre_techniques)
                if node.mitre_techniques
                else "no att&ck tags"
            )
            docs.append(
                CTIDocument(
                    id=node.id,
                    text=f"{node.name} ({node.kind.value}) — {tags}",
                    metadata={"source": "node", "kind": node.kind.value},
                )
            )
        if docs:
            self.store.reset()
        self.index_documents(docs)

    def query(self, text: str, top_k: int = 5) -> list[VectorHit]:
        if not text or not str(text).strip():
            return []
        embedding = self.embeddings.embed_one(str(text))
        return self.store.query(embedding, top_k=top_k)
