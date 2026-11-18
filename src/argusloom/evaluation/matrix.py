"""Call-count and cache-validation helpers for the fixed experiment matrix."""

from __future__ import annotations

import json
from typing import Any


def estimate_generation_calls(
    *,
    model_count: int = 5,
    question_count: int = 30,
    lexsim_samples: int = 5,
    control_validation_questions_per_model: int = 3,
) -> dict[str, int]:
    if model_count < 1 or question_count < 1 or lexsim_samples < 1:
        raise ValueError("model_count, question_count, and lexsim_samples must be positive")
    if not 0 <= control_validation_questions_per_model <= question_count:
        raise ValueError("control validation count must be between zero and N")

    baseline_and_attack_questions = model_count * question_count * 2
    validation_questions = model_count * control_validation_questions_per_model
    control_questions = model_count * question_count
    return {
        "greedy_without_control_reuse": model_count * question_count * 3,
        "lexsim_without_control_reuse": model_count * question_count * 3 * lexsim_samples,
        "greedy_baseline_and_attack": baseline_and_attack_questions,
        "lexsim_baseline_and_attack": baseline_and_attack_questions * lexsim_samples,
        "greedy_control_validation": validation_questions,
        "lexsim_control_validation": validation_questions * lexsim_samples,
        "cached_control_total_including_validation": (
            baseline_and_attack_questions
            + baseline_and_attack_questions * lexsim_samples
            + validation_questions * (1 + lexsim_samples)
        ),
        "full_control_fallback_total": (
            baseline_and_attack_questions * (1 + lexsim_samples)
            + control_questions * (1 + lexsim_samples)
        ),
    }


def control_matches_baseline(
    baseline_result: dict[str, Any],
    regenerated_control_result: dict[str, Any],
) -> bool:
    """Require exact equality of generated answer and retrieved context record."""

    return json.dumps(
        baseline_result, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ) == json.dumps(
        regenerated_control_result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def select_shared_num_ctx(
    measurements: list[dict[str, object]],
    *,
    candidates: tuple[int, ...] = (2048, 4096),
    model_count: int = 5,
) -> int:
    """Select the smallest tested context fitting every model without truncation."""

    if not candidates or any(candidate < 1 for candidate in candidates):
        raise ValueError("num_ctx candidates must be positive")
    candidate_set = set(candidates)
    valid: set[int] = set()
    for measurement in measurements:
        model_id = measurement.get("model_id")
        num_ctx = measurement.get("num_ctx")
        prompt_tokens = measurement.get("full_prompt_tokens")
        truncated = measurement.get("retrieved_context_truncated")
        if not isinstance(model_id, str) or not isinstance(num_ctx, int):
            raise ValueError("pilot measurements need model_id and integer num_ctx")
        if num_ctx not in candidate_set:
            raise ValueError(f"Unexpected num_ctx candidate: {num_ctx}")
        if not isinstance(prompt_tokens, int) or prompt_tokens < 0:
            raise ValueError("pilot measurements need full_prompt_tokens")
        if not isinstance(truncated, bool):
            raise ValueError("pilot measurements need a truncation result")
        if prompt_tokens <= num_ctx and not truncated:
            valid.add(num_ctx)

    model_ids = {
        measurement["model_id"]
        for measurement in measurements
        if isinstance(measurement.get("model_id"), str)
    }
    if len(model_ids) != model_count:
        raise ValueError(f"pilot must include all {model_count} configured models")
    for candidate in sorted(candidate_set):
        rows = [item for item in measurements if item["num_ctx"] == candidate]
        row_model_ids = {item["model_id"] for item in rows}
        if (
            len(rows) == model_count
            and row_model_ids == model_ids
            and candidate in valid
        ):
            if all(
                item["full_prompt_tokens"] <= candidate
                and item["retrieved_context_truncated"] is False
                for item in rows
            ):
                return candidate
    raise ValueError("No candidate num_ctx fits all models without truncation")
