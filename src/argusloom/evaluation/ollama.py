"""Local-only Ollama generation client for experiment workloads."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from typing import Any


@dataclass(frozen=True, slots=True)
class Generation:
    text: str
    eval_count: int
    eval_duration_ns: int
    prompt_eval_count: int


class OllamaClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 300.0,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("experiment Ollama client must use a local endpoint")
        if parsed.port != 11434 or parsed.path not in {"", "/"}:
            raise ValueError("experiment Ollama client requires local port 11434")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system: str,
        temperature: float,
        seed: int,
        num_ctx: int,
    ) -> Generation:
        if not model or not prompt or not system:
            raise ValueError("model, prompt, and system must be non-empty")
        if temperature < 0 or num_ctx < 1:
            raise ValueError("temperature must be non-negative and num_ctx positive")

        payload = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "seed": seed,
                "num_ctx": num_ctx,
            },
        }
        request = Request(
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama returned HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Unable to reach local Ollama: {exc.reason}") from exc
        if not isinstance(body, dict) or not isinstance(body.get("response"), str):
            raise ValueError("Ollama response is missing its generated text")

        def nonnegative_integer(field: str) -> int:
            value: Any = body.get(field, 0)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"Ollama response field {field} must be non-negative")
            return value

        return Generation(
            text=body["response"],
            eval_count=nonnegative_integer("eval_count"),
            eval_duration_ns=nonnegative_integer("eval_duration"),
            prompt_eval_count=nonnegative_integer("prompt_eval_count"),
        )


def format_retrieved_context(hits: list[dict[str, Any]]) -> str:
    """Format retrieved evidence with explicit document provenance."""

    blocks: list[str] = []
    for hit in hits:
        document_id = hit.get("id")
        text = hit.get("text")
        metadata = hit.get("metadata") or {}
        if not isinstance(document_id, str) or not isinstance(text, str):
            raise ValueError("each retrieval hit needs string id and text fields")
        if not isinstance(metadata, dict):
            raise ValueError("retrieval hit metadata must be an object")
        source = str(metadata.get("source", "unknown"))
        snapshot = str(metadata.get("snapshot_hash", "unknown"))
        blocks.append(
            f"[document_id={document_id} source={source} snapshot={snapshot}]\n{text}"
        )
    return "\n\n".join(blocks)
