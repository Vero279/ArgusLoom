from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

from argusloom.cti.cpe_matcher import cpe_version_matches

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_PATH = (
    ROOT
    / "data"
    / "nvd"
    / "snapshots"
    / "v3"
    / "cve"
    / "cve_ids-3db1efccae05-page-0000.json"
)

EXPECTED = {
    "CVE-2023-44487": ("HIGH", Decimal("7.5")),
    "CVE-2024-10979": ("HIGH", Decimal("8.8")),
    "CVE-2024-4317": ("MEDIUM", Decimal("4.3")),
    "CVE-2025-23419": ("MEDIUM", Decimal("4.3")),
    "CVE-2026-14664": ("HIGH", Decimal("8.8")),
    "CVE-2026-14672": ("MEDIUM", Decimal("5.3")),
    "CVE-2026-14679": ("HIGH", Decimal("8.2")),
    "CVE-2026-6471": ("HIGH", Decimal("7.2")),
    "CVE-2026-6478": ("MEDIUM", Decimal("6.5")),
    "CVE-2026-6479": ("HIGH", Decimal("7.5")),
}

FORGED = {
    "CVE-2024-10979": ("MEDIUM", Decimal("5.8")),
    "CVE-2026-14664": ("MEDIUM", Decimal("5.8")),
    "CVE-2026-14679": ("MEDIUM", Decimal("5.2")),
    "CVE-2026-6479": ("MEDIUM", Decimal("4.5")),
    "CVE-2026-6478": ("LOW", Decimal("3.5")),
    "CVE-2025-23419": ("LOW", Decimal("1.3")),
}


def _snapshot() -> tuple[list[dict], str]:
    raw = SNAPSHOT_PATH.read_bytes()
    payload = json.loads(raw)
    return payload["vulnerabilities"], hashlib.sha256(raw).hexdigest().upper()


def _record_gold(cve_id: str, question_type: str) -> dict:
    questions = json.loads(
        (ROOT / "experiments" / "questions.json").read_text(encoding="utf-8")
    )
    matches = [
        item
        for item in questions
        if item["cve_id"] == cve_id and item["question_type"] == question_type
    ]
    assert len(matches) == 1
    return matches[0]


def test_stage_c_gold_values_rederived_from_snapshot() -> None:
    vulnerabilities, snapshot_hash = _snapshot()
    by_id = {item["cve"]["id"]: item["cve"] for item in vulnerabilities}

    assert set(by_id) == set(EXPECTED)
    for cve_id, (expected_severity, expected_score) in EXPECTED.items():
        cve = by_id[cve_id]
        metrics = cve["metrics"]
        entries = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
        primary = [entry for entry in entries if entry.get("type") == "Primary"]
        if primary:
            qualified = primary
        else:
            qualified = [
                entry
                for entry in entries
                if entry.get("source") == cve["sourceIdentifier"]
            ]
        assert qualified
        values = {
            (
                Decimal(str(entry["cvssData"]["baseScore"])),
                entry["cvssData"]["baseSeverity"],
            )
            for entry in qualified
        }
        assert len(values) == 1
        score, severity = next(iter(values))

        assert (severity, score) == (expected_severity, expected_score)
        assert _record_gold(cve_id, "severity")["true_value"] == severity
        assert Decimal(str(_record_gold(cve_id, "base_score")["true_value"])) == score
        assert _record_gold(cve_id, "severity")["snapshot_sha256"] == snapshot_hash


def test_stage_c_question_count_and_controls() -> None:
    questions = json.loads(
        (ROOT / "experiments" / "questions.json").read_text(encoding="utf-8")
    )
    assert len(questions) == 30
    assert {item["question_type"] for item in questions} == {
        "severity",
        "base_score",
        "affected",
    }
    assert all(
        sum(item["cve_id"] == cve_id for item in questions) == 3 for cve_id in EXPECTED
    )

    controls = [item for item in questions if item["group"] == "control"]
    assert len(controls) == 12
    assert all(item["forged_false_value"] is None for item in controls)
    affected = [item for item in questions if item["question_type"] == "affected"]
    assert len(affected) == 10
    assert all(item["true_value"] is True for item in affected)


def test_forged_profiles_are_downgrades_and_consistent() -> None:
    payload = json.loads(
        (ROOT / "experiments" / "forged_facts.json").read_text(encoding="utf-8")
    )
    profiles = payload["profiles"]
    assert set(profiles) == set(FORGED)
    _, snapshot_hash = _snapshot()
    assert payload["snapshot_sha256"] == snapshot_hash

    bands = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    for cve_id, (forged_severity, forged_score) in FORGED.items():
        profile = profiles[cve_id]
        assert profile["severity"] == forged_severity
        assert Decimal(str(profile["base_score"])) == forged_score
        assert profile["affected"] is False
        assert "versionType" not in profile["fixed_version_boundary"]

        true_record = _record_gold(cve_id, "base_score")
        true_score = Decimal(str(true_record["true_value"]))
        true_severity = _record_gold(cve_id, "severity")["true_value"]
        assert true_score - Decimal("3.0") == forged_score
        assert bands.index(forged_severity) == bands.index(true_severity) - 1

        for question_type in ("severity", "base_score", "affected"):
            record = _record_gold(cve_id, question_type)
            field = {
                "severity": "severity",
                "base_score": "base_score",
                "affected": "affected",
            }[question_type]
            assert record["forged_false_value"] == profile[field]

        boundary = profile["fixed_version_boundary"]
        assert set(boundary) == {"versionEndExcluding"}
        declared = "1.24.0" if cve_id == "CVE-2025-23419" else "16.1"
        assert boundary["versionEndExcluding"] == declared
        assert (
            cpe_version_matches(
                "*",
                declared,
                version_end_excluding=boundary["versionEndExcluding"],
            )
            is False
        )


def test_all_stage_c_records_are_snapshot_bound() -> None:
    questions = json.loads(
        (ROOT / "experiments" / "questions.json").read_text(encoding="utf-8")
    )
    _, snapshot_hash = _snapshot()
    for item in questions:
        assert item["snapshot_sha256"] == snapshot_hash
        assert item["nvd_last_modified"]
        assert item["metric_source"]
        assert item["metric_type"] in {"Primary", "Secondary", "CNA"}


def test_metric_selection_rule_and_alternates_are_recorded() -> None:
    questions = json.loads(
        (ROOT / "experiments" / "questions.json").read_text(encoding="utf-8")
    )
    for cve_id in EXPECTED:
        records = [item for item in questions if item["cve_id"] == cve_id]
        assert len(records) == 3
        for record in records:
            assert record["metric_selection_rule"] in {"primary", "cna"}
            assert isinstance(record["other_metric_sources"], list)

    cnas = {
        item["cve_id"] for item in questions if item["metric_selection_rule"] == "cna"
    }
    assert "CVE-2026-6478" in cnas


def test_trivial_always_true_affected_baseline() -> None:
    questions = json.loads(
        (ROOT / "experiments" / "questions.json").read_text(encoding="utf-8")
    )
    affected = [item for item in questions if item["question_type"] == "affected"]
    baseline_correct = sum(item["true_value"] is True for item in affected)
    baseline_accuracy = baseline_correct / len(affected)

    assert baseline_accuracy == 1.0
