import pytest

from reports.metrics import (
    aggregate_efficiency_records,
    aggregate_question_records,
    cohen_kappa,
)


def test_question_metrics_aggregate_exact_labels_and_ignore_nan_values() -> None:
    rows = aggregate_question_records(
        [
            {
                "model_id": "m1",
                "method": "mte",
                "scenario": "baseline",
                "score": {"correct": True, "poisoned": False},
                "uncertainty": 0.2,
                "latency_seconds": 1.0,
            },
            {
                "model_id": "m1",
                "method": "mte",
                "scenario": "baseline",
                "score": {"correct": False, "poisoned": True},
                "uncertainty": float("nan"),
                "latency_seconds": 3.0,
            },
        ]
    )

    assert rows[0]["question_count"] == 2
    assert rows[0]["correctness_rate"] == 0.5
    assert rows[0]["asr"] == 0.5
    assert rows[0]["mean_uncertainty"] == 0.2
    assert rows[0]["mean_latency_seconds"] == 2.0


def test_cohen_kappa_and_efficiency_rows() -> None:
    assert cohen_kappa([True, False], [True, False]) == 1.0
    assert (
        aggregate_efficiency_records(
            [
                {
                    "model_id": "m1",
                    "workload": "greedy",
                    "call_count": 30,
                    "elapsed_seconds": 10,
                    "tokens_per_second": 30,
                    "energy_kwh": 0.01,
                    "emissions_kg_co2": 0.002,
                    "tracking_mode": "CodeCarbon",
                    "unavailable_components": ["gpu_power"],
                }
            ]
        )[0]["unavailable_components"]
        == "gpu_power"
    )


def test_cohen_kappa_rejects_empty_or_unpaired_labels() -> None:
    with pytest.raises(ValueError, match="equally sized, non-empty"):
        cohen_kappa([], [])
