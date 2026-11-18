"""Aggregate versionable question-level JSONL results into CSV tables."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Iterable


def cohen_kappa(labels_a: list[bool], labels_b: list[bool]) -> float:
    if len(labels_a) != len(labels_b) or not labels_a:
        raise ValueError("Cohen's kappa requires equally sized, non-empty labels")
    observed = sum(first == second for first, second in zip(labels_a, labels_b)) / len(labels_a)
    a_true = sum(labels_a) / len(labels_a)
    b_true = sum(labels_b) / len(labels_b)
    expected = a_true * b_true + (1 - a_true) * (1 - b_true)
    if expected == 1:
        return 1.0 if observed == 1 else 0.0
    return (observed - expected) / (1 - expected)


def aggregate_question_records(
    records: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = (
            str(record["model_id"]),
            str(record["method"]),
            str(record["scenario"]),
        )
        grouped[key].append(record)

    rows: list[dict[str, Any]] = []
    for (model_id, method, scenario), group in sorted(grouped.items()):
        scores = [record.get("score", {}) for record in group]
        correctness = [bool(score.get("correct")) for score in scores]
        poisoned = [bool(score.get("poisoned")) for score in scores]
        uncertainty_values = [
            float(record["uncertainty"])
            for record in group
            if isinstance(record.get("uncertainty"), (int, float))
            and math.isfinite(float(record["uncertainty"]))
        ]
        latencies = [
            float(record["latency_seconds"])
            for record in group
            if isinstance(record.get("latency_seconds"), (int, float))
        ]
        rows.append(
            {
                "model_id": model_id,
                "method": method,
                "scenario": scenario,
                "question_count": len(group),
                "correctness_rate": mean(correctness),
                "asr": mean(poisoned),
                "mean_uncertainty": (
                    mean(uncertainty_values) if uncertainty_values else None
                ),
                "uncertainty_count": len(uncertainty_values),
                "mean_latency_seconds": mean(latencies) if latencies else None,
            }
        )
    return rows


def aggregate_efficiency_records(
    records: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in sorted(
        records,
        key=lambda item: (str(item["model_id"]), str(item["workload"])),
    ):
        rows.append(
            {
                "model_id": record["model_id"],
                "workload": record["workload"],
                "call_count": record["call_count"],
                "elapsed_seconds": record["elapsed_seconds"],
                "tokens_per_second": record.get("tokens_per_second"),
                "energy_kwh": record.get("energy_kwh"),
                "emissions_kg_co2": record.get("emissions_kg_co2"),
                "tracking_mode": record.get("tracking_mode"),
                "unavailable_components": "|".join(
                    record.get("unavailable_components", [])
                ),
                "indexing_or_attack_included": record.get(
                    "indexing_or_attack_included", False
                ),
            }
        )
    return rows


def write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError("cannot write an empty metrics table")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Result line {line_number} must be a JSON object")
            records.append(value)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Question-level JSONL results")
    parser.add_argument("--output", type=Path, required=True, help="Aggregate CSV path")
    args = parser.parse_args()
    write_csv(args.output, aggregate_question_records(_read_jsonl(args.input)))


if __name__ == "__main__":
    main()
