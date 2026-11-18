from pathlib import Path

import pytest

from argusloom.telemetry.codecarbon import measure_model_workload


def test_model_efficiency_rejects_non_inference_phase(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="workload must"):
        measure_model_workload(
            model_id="llama3.2:3b",
            workload="indexing",
            call_count=1,
            generate=lambda _index: {},
            output_dir=tmp_path,
        )


def test_model_efficiency_rejects_empty_workload(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="call_count must be positive"):
        measure_model_workload(
            model_id="llama3.2:3b",
            workload="greedy",
            call_count=0,
            generate=lambda _index: {},
            output_dir=tmp_path,
        )
