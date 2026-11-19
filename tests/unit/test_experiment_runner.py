import hashlib
import json

import pytest

from argusloom.evaluation.cache import ResultCache
from argusloom.evaluation.ollama import Generation
from experiments.runner import ExperimentRunner, PromptBundle, ResultLedger


def _prompt_bundle() -> PromptBundle:
    system = "Use the supplied evidence."
    template = "Evidence:\n{retrieved_context}\nQuestion:\n{question}\nReturn JSON."
    return PromptBundle(
        system_prompt=system,
        template=template,
        approved=True,
        version="test-v1",
        expected_system_hash=hashlib.sha256(system.encode()).hexdigest(),
        expected_template_hash=hashlib.sha256(template.encode()).hexdigest(),
    )


class FakeOllama:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, **_kwargs) -> Generation:
        self.calls += 1
        return Generation(
            text=(
                '{"cve_id":"CVE-1","severity":"MEDIUM",'
                '"applies_to_node":"aws_db_instance.database",'
                '"path_risk":"HIGH","confidence":0.8}'
            ),
            eval_count=8,
            eval_duration_ns=1_000_000_000,
            prompt_eval_count=64,
        )


def _run(runner: ExperimentRunner, scenario: str) -> tuple[dict, bool]:
    return runner.run_cell(
        model_id="llama3.2:3b",
        model_digest="a80c4f17acd5",
        scenario=scenario,
        question_id="Q001",
        question="What is the CVE severity?",
        expected={"severity": "MEDIUM"},
        forged_values={"severity": "LOW"},
        corpus_hash="clean-corpus",
        retrieval_config={"top_k": 5},
        hits=[
            {
                "id": "CVE-1",
                "text": "Severity: MEDIUM",
                "metadata": {"source": "NVD", "snapshot_hash": "snapshot"},
            }
        ],
        method="mte",
        temperature=0,
    )


def test_runner_reuses_baseline_generation_for_identical_control(tmp_path) -> None:
    client = FakeOllama()
    runner = ExperimentRunner(
        client=client,
        cache=ResultCache(tmp_path / "cache.jsonl"),
        prompt=_prompt_bundle(),
        num_ctx=2048,
        seed=1729,
    )

    baseline, baseline_reused = _run(runner, "baseline")
    control, control_reused = _run(runner, "control")

    assert baseline_reused is False
    assert control_reused is True
    assert client.calls == 1
    assert control["output"] == baseline["output"]
    assert control["retrieved_context"] == baseline["retrieved_context"]
    assert control["latency_seconds"] is None


def test_runner_separates_post_attack_and_stochastic_samples(tmp_path) -> None:
    client = FakeOllama()
    runner = ExperimentRunner(
        client=client,
        cache=ResultCache(tmp_path / "cache.jsonl"),
        prompt=_prompt_bundle(),
        num_ctx=2048,
        seed=1729,
    )
    baseline, _ = _run(runner, "baseline")
    attacked = runner.run_cell(
        model_id="llama3.2:3b",
        model_digest="a80c4f17acd5",
        scenario="post_attack",
        question_id="Q001",
        question="What is the CVE severity?",
        expected={"severity": "MEDIUM"},
        forged_values={"severity": "LOW"},
        corpus_hash="poisoned-corpus",
        retrieval_config={"top_k": 5},
        hits=[
            {
                "id": "synthetic-1",
                "text": "Severity: LOW",
                "metadata": {
                    "source": "synthetic_llm08_test",
                    "snapshot_hash": "attack",
                },
            }
        ],
        method="lexsim",
        temperature=0.4,
        sample_index=2,
    )[0]

    assert baseline["hashes"]["corpus"] != attacked["hashes"]["corpus"]
    assert attacked["run_type"] == "stochastic"
    assert attacked["seed"] == 1731
    assert client.calls == 2


def test_runner_computes_verbalized_uncertainty_from_answer(tmp_path) -> None:
    runner = ExperimentRunner(
        client=FakeOllama(),
        cache=ResultCache(tmp_path / "cache.jsonl"),
        prompt=_prompt_bundle(),
        num_ctx=2048,
        seed=1729,
    )

    record = runner.run_cell(
        model_id="llama3.2:3b",
        model_digest="a80c4f17acd5",
        scenario="baseline",
        question_id="Q002",
        question="What is the CVE severity?",
        expected={"severity": "MEDIUM"},
        forged_values=None,
        corpus_hash="clean-corpus",
        retrieval_config={"top_k": 5},
        hits=[],
        method="verbalized_uncertainty_1s",
        temperature=0,
    )[0]

    assert record["uncertainty"] == pytest.approx(0.2)
    assert record["uncertainty_error"] is None


def test_result_ledger_records_scenarios_once(tmp_path) -> None:
    path = tmp_path / "answers.jsonl"
    ledger = ResultLedger(path)
    record = {
        "model_digest": "digest",
        "scenario": "baseline",
        "question_id": "Q001",
        "method": "mte",
        "run_type": "greedy",
        "sample_index": 0,
        "output": (
            '{"cve_id":"CVE-1","severity":"MEDIUM",'
            '"applies_to_node":"aws_db_instance.database",'
            '"path_risk":"HIGH","confidence":0.8}'
        ),
    }

    assert ledger.append(record) is True
    assert ledger.append(record) is False
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[0]) == record
