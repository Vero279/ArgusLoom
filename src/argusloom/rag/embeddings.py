"""Embedding abstraction for semantic retrieval with lazy model loading."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence


class EmbeddingModel:
    """Thin wrapper around sentence-transformers with a deterministic fallback."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        self._model = None
        self._fallback_vocabulary = [
            "network",
            "ingress",
            "exposure",
            "tls",
            "iam",
            "privilege",
            "escalation",
            "database",
            "data",
            "encryption",
            "service",
            "hardening",
            "public",
            "controls",
            "attack",
            "risk",
            "mitre",
            "cve",
            "identity",
            "access",
            "storage",
            "trust",
            "monitoring",
            "logging",
            "firewall",
            "role",
            "resource",
            "security",
            "gateway",
            "api",
            "backend",
            "compute",
        ]

    @property
    def dimension(self) -> int:
        return len(self._fallback_vocabulary)

    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
        except (ImportError, OSError, RuntimeError, ValueError):
            self._model = None

    def _normalize_tokens(self, text: str) -> list[str]:
        tokens = re.findall(r"[a-z0-9_]+", text.lower())
        return [token for token in tokens if token]

    def _fallback_embed_one(self, text: str) -> list[float]:
        counts: dict[str, float] = {}
        for token in self._normalize_tokens(text):
            counts[token] = counts.get(token, 0.0) + 1.0

        vector = [0.0 for _ in self._fallback_vocabulary]
        for index, term in enumerate(self._fallback_vocabulary):
            vector[index] = counts.get(term, 0.0)

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return [0.0 for _ in vector]
        return [value / norm for value in vector]

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self._ensure_model()
        if self._model is not None:
            try:
                embeddings = self._model.encode(list(texts), convert_to_numpy=False)
                return [list(map(float, embedded)) for embedded in embeddings]
            except (OSError, RuntimeError, ValueError):
                self._model = None

        return [self._fallback_embed_one(str(text)) for text in texts]

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
