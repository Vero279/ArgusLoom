"""Embedding abstraction for semantic retrieval with lazy model loading."""

from __future__ import annotations

import math
from collections.abc import Sequence


class EmbeddingModel:
    """Thin wrapper around sentence-transformers with lazy model loading."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        self._model = None

    @property
    def dimension(self) -> int:
        self._ensure_model()
        return self._model.get_sentence_embedding_dimension()

    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self.model_name)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self._ensure_model()
        embeddings = self._model.encode(list(texts), convert_to_numpy=False)
        return [list(map(float, embedded)) for embedded in embeddings]

    def embed_one(self, text: str) -> list[float]:
        values = self.embed([text])
        return values[0]

    def cosine_similarity(self, left: Sequence[float], right: Sequence[float]) -> float:
        if len(left) != len(right):
            raise ValueError("Vectors must have the same length for cosine similarity.")

        dot_product = sum(float(a) * float(b) for a, b in zip(left, right))
        left_norm = math.sqrt(sum(float(value) * float(value) for value in left))
        right_norm = math.sqrt(sum(float(value) * float(value) for value in right))
        if left_norm == 0.0 or right_norm == 0.0:
            return 0.0
        return float(dot_product / (left_norm * right_norm))
