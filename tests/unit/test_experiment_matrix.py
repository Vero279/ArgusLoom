from argusloom.evaluation.matrix import (
    control_matches_baseline,
    estimate_generation_calls,
    select_shared_num_ctx,
)


def test_call_estimates_cover_cache_validation_and_fallback() -> None:
    estimates = estimate_generation_calls()

    assert estimates["greedy_baseline_and_attack"] == 300
    assert estimates["lexsim_baseline_and_attack"] == 1500
    assert estimates["greedy_control_validation"] == 15
    assert estimates["lexsim_control_validation"] == 75
    assert estimates["cached_control_total_including_validation"] == 1890
    assert estimates["full_control_fallback_total"] == 2700
    assert (
        estimate_generation_calls(lexsim_samples=10)[
            "cached_control_total_including_validation"
        ]
        == 3465
    )
    assert (
        estimate_generation_calls(lexsim_samples=10)["full_control_fallback_total"]
        == 4950
    )


def test_control_cache_validation_requires_exact_output_and_context_match() -> None:
    baseline = {"answer": "A", "retrieved_context": ["doc-1"]}

    assert control_matches_baseline(baseline, dict(baseline))
    assert not control_matches_baseline(
        baseline, {"answer": "A", "retrieved_context": ["doc-2"]}
    )
    assert not control_matches_baseline(
        baseline, {"answer": "B", "retrieved_context": ["doc-1"]}
    )


def test_context_size_selects_smallest_candidate_that_fits_every_model() -> None:
    models = ["m1", "m2", "m3", "m4", "m5"]
    measurements = [
        {
            "model_id": model,
            "num_ctx": context,
            "full_prompt_tokens": 1800 if model == "m1" else 2300,
            "retrieved_context_truncated": False,
        }
        for context in (2048, 4096)
        for model in models
    ]

    assert select_shared_num_ctx(measurements) == 4096


def test_context_size_rejects_truncation_or_missing_models() -> None:
    measurements = [
        {
            "model_id": f"m{index}",
            "num_ctx": 4096,
            "full_prompt_tokens": 5000,
            "retrieved_context_truncated": True,
        }
        for index in range(5)
    ]

    try:
        select_shared_num_ctx(measurements)
    except ValueError as exc:
        assert "No candidate num_ctx" in str(exc)
    else:
        raise AssertionError("Expected no-fit context size to fail")
