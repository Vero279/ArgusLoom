"""Reusable single-cell runner; production API routes do not import this module."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from string import Formatter
from typing import Any

from argusloom.evaluation.cache import CacheIdentity, ResultCache
from argusloom.evaluation.ollama import OllamaClient, format_retrieved_context
from argusloom.evaluation.scoring import (
    REQUIRED_ANSWER_FIELDS,
    score_json_answer,
)
from argusloom.evaluation.uncertainty import LMPolygraphAdapter

_GREEDY_METHODS = {"verbalized_uncertainty_1s", "msp", "mte"}
_METHOD_RUN_TYPES = {
    **{method: "greedy" for method in _GREEDY_METHODS},
    "lexsim": "stochastic",
}


def _hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class PromptBundle:
    system_prompt: str
    template: str
    approved: bool
    version: str
    expected_system_hash: str
    expected_template_hash: str

    def __post_init__(self) -> None:
        if not self.approved:
            raise ValueError("experiment prompt must be approved before running")
        if not self.version:
            raise ValueError("approved prompt needs a version")
        if hashlib.sha256(self.system_prompt.encode("utf-8")).hexdigest() != (
            self.expected_system_hash
        ):
            raise ValueError("system prompt hash does not match the approved hash")
        if hashlib.sha256(self.template.encode("utf-8")).hexdigest() != (
            self.expected_template_hash
        ):
            raise ValueError("prompt template hash does not match the approved hash")
        fields = {
            field_name
            for _, field_name, _, _ in Formatter().parse(self.template)
            if field_name is not None
        }
        if fields != {"question", "retrieved_context"}:
            raise ValueError(
                "prompt template must use only {question} and {retrieved_context}"
            )

    @property
    def combined_hash(self) -> str:
        return _hash(
            {
                "version": self.version,
                "system_prompt": self.expected_system_hash,
                "template": self.expected_template_hash,
            }
        )


class ResultLedger:
    """Append-only scenario records with duplicate protection for resume."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    key = self._key(record)
                    if key in self._records:
                        raise ValueError(f"Duplicate result record on line {line_number}")
                    self._records[key] = record

    @staticmethod
    def _key(record: dict[str, Any]) -> str:
        return _hash(
            {
                field: record[field]
                for field in (
                    "model_digest",
                    "scenario",
                    "question_id",
                    "method",
                    "run_type",
                    "sample_index",
                )
            }
        )

    def append(self, record: dict[str, Any]) -> bool:
        key = self._key(record)
        existing = self._records.get(key)
        if existing is not None:
            if existing != record:
                raise ValueError("result key already exists with different content")
            return False
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._records[key] = record
        return True


class ExperimentRunner:
    def __init__(
        self,
        *,
        client: OllamaClient,
        cache: ResultCache,
        prompt: PromptBundle,
        num_ctx: int,
        seed: int,
    ) -> None:
        if num_ctx < 1:
            raise ValueError("num_ctx must be positive")
        self.client = client
        self.cache = cache
        self.prompt = prompt
        self.num_ctx = num_ctx
        self.seed = seed

    def run_cell(
        self,
        *,
        model_id: str,
        model_digest: str,
        scenario: str,
        question_id: str,
        question: str,
        expected: dict[str, Any],
        forged_values: dict[str, Any] | None,
        corpus_hash: str,
        retrieval_config: dict[str, Any],
        hits: list[dict[str, Any]],
        method: str,
        temperature: float,
        sample_index: int = 0,
        lm_polygraph_stats: dict[str, Any] | None = None,
        lm_polygraph_adapter: LMPolygraphAdapter | None = None,
    ) -> tuple[dict[str, Any], bool]:
        run_type = _METHOD_RUN_TYPES.get(method)
        if run_type is None:
            raise ValueError(f"Unsupported LM-Polygraph method '{method}'")
        if (run_type == "greedy" and temperature != 0) or (
            run_type == "stochastic" and temperature <= 0
        ):
            raise ValueError(f"Invalid temperature for {run_type} run")
        if not question_id or not question:
            raise ValueError("question_id and question must be non-empty")
        if run_type == "greedy" and sample_index != 0:
            raise ValueError("greedy runs use sample_index=0")
        if run_type == "stochastic" and sample_index < 0:
            raise ValueError("stochastic sample_index must be non-negative")

        context = format_retrieved_context(hits)
        prompt_text = self.prompt.template.format(
            question=question,
            retrieved_context=context,
        )
        prompt_hash = self.prompt.combined_hash
        retrieval_hash = _hash(
            {
                "config": retrieval_config,
                "hits": hits,
            }
        )
        actual_seed = self.seed + sample_index if run_type == "stochastic" else self.seed
        decoding = {
            "temperature": temperature,
            "seed": actual_seed,
            "num_ctx": self.num_ctx,
            "run_type": run_type,
            "sample_index": sample_index,
        }
        identity = CacheIdentity(
            model_id=model_id,
            model_digest=model_digest,
            question_id=question_id,
            question_hash=_hash(question),
            corpus_hash=corpus_hash,
            prompt_hash=prompt_hash,
            retrieval_hash=retrieval_hash,
            decoding_hash=_hash(decoding),
            seed=actual_seed,
            run_type=run_type,
            sample_index=sample_index,
        )

        def generate() -> dict[str, Any]:
            started = time.perf_counter()
            result = self.client.generate(
                model=model_id,
                prompt=prompt_text,
                system=self.prompt.system_prompt,
                temperature=temperature,
                seed=actual_seed,
                num_ctx=self.num_ctx,
            )
            return {
                "question": question,
                "retrieved_context": hits,
                "answer": result.text,
                "eval_count": result.eval_count,
                "eval_duration_ns": result.eval_duration_ns,
                "prompt_eval_count": result.prompt_eval_count,
                "latency_seconds": time.perf_counter() - started,
            }

        result, reused = self.cache.get_or_generate(identity, scenario, generate)
        uncertainty: float | None = None
        uncertainty_error: str | None = None
        if method == "verbalized_uncertainty_1s":
            adapter = lm_polygraph_adapter or LMPolygraphAdapter()
            value, error = adapter.score(
                method,
                lm_polygraph_stats,
                greedy_text=result["answer"],
            )
            uncertainty = value
            uncertainty_error = error
        elif lm_polygraph_adapter is None or lm_polygraph_stats is None:
            uncertainty_error = "LM-Polygraph statistics or adapter not supplied"
        else:
            value, error = lm_polygraph_adapter.score(
                method,
                lm_polygraph_stats,
                greedy_text=result["answer"] if run_type == "greedy" else None,
            )
            uncertainty = value
            uncertainty_error = error
        score = score_json_answer(
            result["answer"],
            expected,
            forged_values,
            required_fields=REQUIRED_ANSWER_FIELDS,
        )
        record = {
            "model_id": model_id,
            "model_digest": model_digest,
            "scenario": scenario,
            "question_id": question_id,
            "method": method,
            "run_type": run_type,
            "sample_index": sample_index,
            "seed": actual_seed,
            "input": {
                "question": question,
                "system_prompt_hash": _hash(self.prompt.system_prompt),
                "template_version": self.prompt.version,
            },
            "retrieved_context": [
                {
                    "document_id": hit["id"],
                    "text": hit["text"],
                    "source": str((hit.get("metadata") or {}).get("source", "unknown")),
                    "snapshot_hash": str(
                        (hit.get("metadata") or {}).get("snapshot_hash", "unknown")
                    ),
                }
                for hit in hits
            ],
            "output": result["answer"],
            "score": {
                "valid_json": score.valid_json,
                "correct": score.correct,
                "poisoned": score.poisoned,
                "mismatched_fields": list(score.mismatched_fields),
            },
            "latency_seconds": None if reused else result["latency_seconds"],
            "model_eval_seconds": result["eval_duration_ns"] / 1_000_000_000,
            "uncertainty": uncertainty,
            "uncertainty_error": uncertainty_error,
            "hashes": {
                "corpus": corpus_hash,
                "prompt": prompt_hash,
                "retrieval": retrieval_hash,
                "decoding": _hash(decoding),
            },
            "cache_reused": reused,
        }
        return record, reused
