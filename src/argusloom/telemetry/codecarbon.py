"""CodeCarbon measurement for comparable model-inference workloads only."""

from __future__ import annotations

import csv
import re
from statistics import median
import time
from pathlib import Path
from typing import Any, Callable


def measure_model_workload(
    *,
    model_id: str,
    workload: str,
    call_count: int,
    generate: Callable[[int], dict[str, Any]],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Measure one model on one fixed inference workload.

    The caller must pass the same prompts, corpus, decoding settings, and
    sample count for each compared model. Indexing and attack orchestration are
    deliberately outside this measurement.
    """

    if workload not in {"greedy", "lexsim"}:
        raise ValueError("workload must be 'greedy' or 'lexsim'")
    if call_count < 1:
        raise ValueError("call_count must be positive")

    try:
        from codecarbon import EmissionsTracker
    except ImportError as exc:
        raise ImportError(
            "CodeCarbon is optional; install the 'evaluation' extra to measure model efficiency."
        ) from exc

    safe_model = re.sub(r"[^A-Za-z0-9_.-]+", "_", model_id)
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    output_file = f"{safe_model}-{workload}.csv"
    tracker = EmissionsTracker(
        project_name=f"argusloom-{safe_model}-{workload}",
        output_dir=str(directory),
        output_file=output_file,
        measure_power_secs=1,
        log_level="error",
    )

    durations: list[float] = []
    generated_tokens = 0
    tracker.start()
    try:
        for index in range(call_count):
            started = time.perf_counter()
            result = generate(index)
            durations.append(time.perf_counter() - started)
            token_count = result.get("eval_count", 0)
            if isinstance(token_count, int) and token_count >= 0:
                generated_tokens += token_count
    except Exception:
        tracker.stop()
        raise
    emissions_kg = tracker.stop()

    csv_path = directory / output_file
    energy_kwh: float | None = None
    unavailable_reason: str | None = None
    latest_row: dict[str, str] = {}
    if csv_path.is_file():
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        if rows:
            latest_row = rows[-1]
        if latest_row.get("energy_consumed"):
            energy_kwh = float(latest_row["energy_consumed"])
        else:
            unavailable_reason = "CodeCarbon did not report energy_consumed"
    else:
        unavailable_reason = "CodeCarbon output file was not created"

    elapsed = sum(durations)
    energy_fields = (
        "cpu_energy",
        "gpu_energy",
        "ram_energy",
        "cpu_power",
        "gpu_power",
        "ram_power",
    )
    component_measurements: dict[str, float | None] = {}
    unavailable_components: list[str] = []
    for field in energy_fields:
        value = latest_row.get(field)
        if value:
            component_measurements[field] = float(value)
        else:
            component_measurements[field] = None
            unavailable_components.append(field)
    return {
        "model_id": model_id,
        "workload": workload,
        "call_count": call_count,
        "elapsed_seconds": elapsed,
        "median_call_seconds": median(durations),
        "generated_tokens": generated_tokens,
        "tokens_per_second": generated_tokens / elapsed if elapsed else 0.0,
        "energy_kwh": energy_kwh,
        "component_measurements": component_measurements,
        "unavailable_components": unavailable_components,
        "emissions_kg_co2": float(emissions_kg),
        "tracking_mode": latest_row.get("tracking_mode", "CodeCarbon (mode unreported)"),
        "energy_unavailable_reason": unavailable_reason,
        "indexing_or_attack_included": False,
    }
