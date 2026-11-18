"""Fail-closed checks before executing the versioned experiment matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from argusloom.cti.snapshots import verify_snapshot_manifest


def collect_preflight_blockers(repository_root: str | Path) -> list[str]:
    root = Path(repository_root).resolve()
    matrix_path = root / "experiments" / "matrix.yaml"
    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    blockers: list[str] = []

    if matrix.get("questions", {}).get("total") != 30:
        blockers.append("matrix must retain N=30")
    if matrix.get("methods", {}).get("lexsim_samples") != 5:
        blockers.append("LexSim must default to S=5")
    if matrix.get("prompt", {}).get("approved") is not True:
        blockers.append("shared system prompt and template are not approved")
    if not isinstance(matrix.get("context", {}).get("frozen_num_ctx"), int):
        blockers.append("shared num_ctx has not been selected and frozen by the pilot")

    manifest_path = root / "data" / "cti_snapshot_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        verify_snapshot_manifest(root, manifest_path)
        if manifest.get("status") != "ready":
            blockers.append("CTI snapshot manifest is not marked ready")
        if any(not entry.get("experiment_eligible", False) for entry in manifest["snapshots"]):
            blockers.append("one or more CTI snapshots are not experiment-eligible")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        blockers.append(f"CTI snapshot verification failed: {exc}")

    questions_path = root / "experiments" / "questions.json"
    if not questions_path.is_file():
        blockers.append("source-derived 30-question gold set is missing")
    else:
        questions: Any = json.loads(questions_path.read_text(encoding="utf-8"))
        if not isinstance(questions, list) or len(questions) != 30:
            blockers.append("gold question file must contain exactly 30 questions")
        elif any(
            not isinstance(item, dict)
            or not item.get("expected")
            or not item.get("source_refs")
            for item in questions
        ):
            blockers.append("every question needs source-derived expected facts and references")

    return blockers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    blockers = collect_preflight_blockers(args.root)
    if blockers:
        print("Experiment blocked:")
        for blocker in blockers:
            print(f"- {blocker}")
        raise SystemExit(2)
    print("Experiment preflight passed.")


if __name__ == "__main__":
    main()
