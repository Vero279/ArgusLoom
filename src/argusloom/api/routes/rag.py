"""Semantic retrieval route for the ArgusLoom RAG layer."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel, Field

from argusloom.config import get_settings
from argusloom.graph.store import GraphStore
from argusloom.rag.embeddings import EmbeddingModel
from argusloom.rag.llm import get_llm_provider
from argusloom.rag.retriever import CTIRetriever
from argusloom.rag.vector_store import VectorStore

router = APIRouter(prefix="/rag", tags=["rag"])


class RagQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    top_k: int = Field(default=5, ge=1, le=20)
    include_llm_answer: bool = False


class RagHit(BaseModel):
    id: str
    text: str
    metadata: dict
    score: float


class RagQueryResponse(BaseModel):
    query: str
    hits: list[RagHit]
    llm_answer: str | None = None


@router.post("/query", response_model=RagQueryResponse)
def rag_query(request: RagQueryRequest) -> RagQueryResponse:
    graph = GraphStore(Path("data/graph.json")).load()
    vector_store = VectorStore(Path("data/chroma"), collection_name="argusloom-rag")
    vector_store.reset()
    retriever = CTIRetriever(EmbeddingModel(), vector_store)
    retriever.index_graph(graph)
    hits = retriever.query(request.query, top_k=request.top_k)

    llm_answer: str | None = None
    if request.include_llm_answer:
        provider = get_llm_provider(get_settings())
        llm_answer = provider.complete(
            request.query,
            system="You are ArgusLoom security analyst.",
            few_shot=[
                (
                    "network exposure",
                    "Prioritize ingress hardening and network segmentation.",
                ),
                (
                    "iam privilege",
                    "Reduce privilege scope and enforce least privilege.",
                ),
            ],
        )

    return RagQueryResponse(
        query=request.query,
        hits=[
            RagHit(
                id=hit.id,
                text=hit.text,
                metadata=hit.metadata,
                score=float(hit.score),
            )
            for hit in hits
        ],
        llm_answer=llm_answer,
    )
