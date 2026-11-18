import json
from dataclasses import replace

import pytest

from argusloom.evaluation.cache import CacheIdentity, ResultCache
from argusloom.evaluation.scoring import score_json_answer
from argusloom.evaluation.uncertainty import (
    LMPolygraphAdapter,
    require_method_statistic,
    verbalized_uncertainty,
)


def _identity() -> CacheIdentity:
    return CacheIdentity(
        model_id="llama3.2:3b",
        model_digest="a80c4f17acd5",
        question_id="Q001",
        question_hash="question",
        corpus_hash="corpus",
        prompt_hash="prompt",
        retrieval_hash="retrieval",
        decoding_hash="greedy",
        seed=7,
        run_type="greedy",
    )


def test_control_reuses_baseline_cache_for_identical_inputs(tmp_path) -> None:
    cache = ResultCache(tmp_path / "results.jsonl")
    calls = 0

    def generate() -> dict:
        nonlocal calls
        calls += 1
        return {"answer": '{"severity":"MEDIUM"}', "context": ["doc-1"]}

    baseline, reused_baseline = cache.get_or_generate(_identity(), "baseline", generate)
    control, reused_control = cache.get_or_generate(_identity(), "control", generate)

    assert baseline == control
    assert reused_baseline is False
    assert reused_control is True
    assert calls == 1
    assert "control" in cache.path.read_text(encoding="utf-8")


def test_cache_does_not_reuse_when_corpus_changes(tmp_path) -> None:
    cache = ResultCache(tmp_path / "results.jsonl")
    cache.get_or_generate(_identity(), "baseline", lambda: {"answer": "one"})
    changed = replace(_identity(), corpus_hash="poisoned")

    assert cache.get(changed) is None


def test_exact_answer_scoring_detects_forged_field() -> None:
    score = score_json_answer(
        json.dumps({"severity": "LOW"}),
        expected={"severity": "MEDIUM"},
        forged_values={"severity": "LOW"},
    )

    assert score.valid_json is True
    assert score.correct is False
    assert score.poisoned is True
    assert score.mismatched_fields == ("severity",)


def test_experiment_answer_schema_requires_all_fixed_fields() -> None:
    answer = json.dumps(
        {
            "cve_id": "CVE-1",
            "severity": "MEDIUM",
            "applies_to_node": "db",
            "path_risk": "HIGH",
            "confidence": 0.8,
        }
    )
    score = score_json_answer(
        answer,
        expected={"severity": "MEDIUM"},
        required_fields=(
            "cve_id",
            "severity",
            "applies_to_node",
            "path_risk",
            "confidence",
        ),
    )

    assert score.valid_json is True
    assert score.correct is True


@pytest.mark.parametrize(
    ("text", "expected"),
    [('{"confidence": 0.8}', 0.2), ('{"confidence": 1}', 0.0)],
)
def test_verbalized_uncertainty_parses_confidence(text: str, expected: float) -> None:
    value, error = verbalized_uncertainty(text)

    assert error is None
    assert value == pytest.approx(expected)


def test_verbalized_uncertainty_reports_nan_on_missing_confidence() -> None:
    value, error = verbalized_uncertainty('{"severity":"HIGH"}')

    assert value != value
    assert error == "confidence_not_found"


def test_verbalized_uncertainty_reports_out_of_range_confidence() -> None:
    value, error = verbalized_uncertainty('{"confidence": 1.1}')

    assert value != value
    assert error == "confidence_out_of_range"


def test_method_statistic_mapping_rejects_missing_values() -> None:
    with pytest.raises(ValueError, match="statistic 'entropy' is missing"):
        require_method_statistic("mte", {})


def test_lm_polygraph_adapter_uses_verified_statistic_mapping() -> None:
    captured = []
    adapter = LMPolygraphAdapter(
        estimator=lambda method, statistic: captured.append((method, statistic)) or 0.42
    )

    score, error = adapter.score("mte", {"entropy": [0.2, 0.6]})

    assert score == 0.42
    assert error is None
    assert captured == [("mte", [0.2, 0.6])]
