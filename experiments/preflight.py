"""Fail-closed checks before executing the versioned experiment matrix."""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argusloom.cti.snapshots import verify_snapshot_manifest
from argusloom.cti.cpe_matcher import (
    CPEProductMapping,
    SoftwareIdentity,
    match_cve_to_inventory,
)

BANDS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _severity_band(score: Decimal) -> str:
    if score == Decimal("0"):
        return "NONE"
    if score < Decimal("4.0"):
        return "LOW"
    if score < Decimal("7.0"):
        return "MEDIUM"
    if score < Decimal("9.0"):
        return "HIGH"
    return "CRITICAL"


def _selected_metric(cve: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"{cve.get('id')} has no CVSS metrics")
    entries = metrics.get("cvssMetricV31")
    version = "3.1"
    if not isinstance(entries, list) or not entries:
        entries = metrics.get("cvssMetricV30")
        version = "3.0"
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{cve.get('id')} has no CVSS v3 metric")

    primary = [entry for entry in entries if isinstance(entry, dict) and entry.get("type") == "Primary"]
    if primary:
        qualified = primary
        rule = "primary"
    else:
        qualified = [
            entry for entry in entries
            if isinstance(entry, dict) and entry.get("source") == cve.get("sourceIdentifier")
        ]
        rule = "cna"
    if not qualified:
        raise ValueError(f"{cve.get('id')} has no qualifying CVSS metric")

    normalized = []
    for entry in qualified:
        data = entry.get("cvssData")
        if not isinstance(data, dict):
            raise ValueError(f"{cve.get('id')} qualifying metric lacks cvssData")
        normalized.append((
            entry,
            Decimal(str(data.get("baseScore"))).quantize(Decimal("0.1")),
            data.get("baseSeverity"),
        ))
    first = (normalized[0][1], normalized[0][2])
    if any((score, severity) != first for _, score, severity in normalized[1:]):
        raise ValueError(f"{cve.get('id')} has ambiguous qualifying CVSS metrics")
    return normalized[0][0], rule, version


def collect_preflight_blockers(repository_root: str | Path) -> list[str]:
    root = Path(repository_root).resolve()
    matrix_path = root / "experiments" / "matrix.yaml"
    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    blockers: list[str] = []

    if matrix.get("questions", {}).get("total") != 30:
        blockers.append("matrix must retain N=30")
    if matrix.get("methods", {}).get("lexsim_samples") != 5:
        blockers.append("LexSim must default to S=5")
    reserved_scenarios = matrix.get("retrieval", {}).get("reserved_scenarios")
    if reserved_scenarios != ["no_retrieval"]:
        blockers.append("matrix retrieval compatibility must reserve no_retrieval")
    if matrix.get("prompt", {}).get("approved") is not True:
        blockers.append("shared system prompt and template are not approved")
    if not isinstance(matrix.get("context", {}).get("frozen_num_ctx"), int):
        blockers.append("shared num_ctx has not been selected and frozen by the pilot")

    manifest_path = root / "data" / "cti_snapshot_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") != "ready":
            blockers.append("CTI snapshot manifest is not marked ready")
        verify_snapshot_manifest(root, manifest_path)
        if any(
            not entry.get("experiment_eligible", False)
            for entry in manifest["snapshots"]
        ):
            blockers.append("one or more CTI snapshots are not experiment-eligible")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        blockers.append(f"CTI snapshot verification failed: {exc}")

    mapping_path = root / "data" / "cpe_product_mappings.json"
    try:
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        entries = mapping.get("entries")
        if not isinstance(entries, list):
            blockers.append("CPE product mapping table must contain an entries list")
        elif mapping.get("status") != "verified":
            blockers.append("CPE product mappings have not been verified")
        elif any(
            not isinstance(item, dict)
            or item.get("verification_status") != "verified"
            or not item.get("source_snapshot")
            or not item.get("source_sha256")
            for item in entries
        ):
            blockers.append("CPE product mappings need verified source snapshots")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        blockers.append(f"CPE product mapping verification failed: {exc}")

    questions_path = root / "experiments" / "questions.json"
    if not questions_path.is_file():
        blockers.append("source-derived 30-question gold set is missing")
    else:
        try:
            questions: Any = json.loads(questions_path.read_text(encoding="utf-8"))
            if not isinstance(questions, list) or len(questions) != 30:
                blockers.append("gold question file must contain exactly 30 questions")
            else:
                required_question_fields = {
                    "question_id", "cve_id", "question_type", "question", "true_value",
                    "source_field_path", "metric_source", "metric_version",
                    "metric_type", "metric_selection_rule", "other_metric_sources",
                    "affected_node", "group", "forged_false_value",
                    "snapshot_sha256", "nvd_last_modified",
                }
                valid_types = {"severity", "base_score", "affected"}
                if any(
                    not isinstance(item, dict)
                    or not required_question_fields.issubset(item)
                    or item["question_type"] not in valid_types
                    or item["metric_selection_rule"] not in {"primary", "cna"}
                    or not isinstance(item["other_metric_sources"], list)
                    for item in questions
                ):
                    blockers.append("gold questions use an invalid Stage C record schema")
                counts = Counter(
                    item["cve_id"] for item in questions if isinstance(item, dict)
                )
                if set(counts.values()) != {3}:
                    blockers.append("gold questions must contain exactly 3 records per CVE")
                poison = {item["cve_id"] for item in questions if item.get("group") == "poisoned"}
                control = {item["cve_id"] for item in questions if item.get("group") == "control"}
                if sum(item.get("group") == "poisoned" for item in questions) != 18:
                    blockers.append("gold questions must contain 18 poisoned records")
                if sum(item.get("group") == "control" for item in questions) != 12:
                    blockers.append("gold questions must contain 12 control records")
                if len(poison) != 6 or len(control) != 4:
                    blockers.append("gold questions have invalid poisoned/control CVE coverage")

                selection_path = root / "experiments" / "cve_selection.json"
                snapshot_path = root / "data" / "nvd" / "snapshots" / "v3" / "cve" / "cve_ids-3db1efccae05-page-0000.json"
                selection = json.loads(selection_path.read_text(encoding="utf-8"))
                snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
                snapshot_hash = __import__("hashlib").sha256(snapshot_path.read_bytes()).hexdigest().upper()
                cves = {
                    item["cve"]["id"]: item["cve"]
                    for item in snapshot.get("vulnerabilities", [])
                    if isinstance(item, dict) and isinstance(item.get("cve"), dict)
                }
                selected_ids = {
                    item["cve"] for item in selection["poisoned"] + selection["controls"]
                }
                if set(counts) != selected_ids:
                    blockers.append("gold questions do not match the CVE selection")

                graph = json.loads((root / "data" / "graph_C.json").read_text(encoding="utf-8"))
                nodes = {node["id"]: node for node in graph.get("nodes", []) if isinstance(node, dict)}
                node_map = {"nginx": "aws_instance.web", "postgresql": "aws_db_instance.database"}
                mapping_payload = json.loads((root / "data" / "cpe_product_mappings.json").read_text(encoding="utf-8"))
                mappings = [
                    CPEProductMapping(
                        software_key=item["software_key"],
                        part=item["part"],
                        vendor=item["vendor"],
                        product=item["product"],
                        verified=True,
                        required_version_components=mapping_payload["required_version_components"].get(item["software_key"], 0),
                    )
                    for item in mapping_payload["entries"]
                    if isinstance(item, dict) and item.get("verification_status") == "verified"
                ]

                for item in questions:
                    cve_id = item["cve_id"]
                    cve = cves.get(cve_id)
                    if cve is None:
                        blockers.append(f"{cve_id}: snapshot CVE is missing")
                        continue
                    if item["snapshot_sha256"] != snapshot_hash:
                        blockers.append(f"{cve_id}: snapshot hash is inconsistent")
                    try:
                        selected, rule, version = _selected_metric(cve)
                        data = selected["cvssData"]
                        score = Decimal(str(data["baseScore"])).quantize(Decimal("0.1"))
                        severity = data["baseSeverity"]
                        if item["metric_selection_rule"] != rule or item["metric_version"] != version:
                            blockers.append(f"{cve_id}: metric selection metadata is inconsistent")
                        if item["metric_source"] != selected.get("source"):
                            blockers.append(f"{cve_id}: selected metric source is inconsistent")
                        if item["question_type"] == "severity" and item["true_value"] != severity:
                            blockers.append(f"{cve_id}: severity gold value is inconsistent")
                        if item["question_type"] == "base_score" and Decimal(str(item["true_value"])) != score:
                            blockers.append(f"{cve_id}: base score gold value is inconsistent")
                        if item["question_type"] == "affected":
                            entry = next(
                                (candidate for candidate in selection["poisoned"] + selection["controls"]
                                 if candidate["cve"] == cve_id),
                                None,
                            )
                            node_id = node_map[entry["node"]] if entry else item["affected_node"]
                            inventory = [
                                SoftwareIdentity(identity["software_key"], identity["version"])
                                for identity in nodes[node_id].get("metadata", {}).get("software_inventory", [])
                                if isinstance(identity, dict)
                            ]
                            affected = match_cve_to_inventory(cve, inventory, mappings)
                            if item["true_value"] != affected:
                                blockers.append(f"{cve_id}: affected gold value is inconsistent")
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        blockers.append(f"{cve_id}: gold re-validation failed: {exc}")
        except json.JSONDecodeError as exc:
            blockers.append(f"gold question file is invalid JSON: {exc}")
        except (OSError, TypeError) as exc:
            blockers.append(f"gold question validation failed: {exc}")

    forged_path = root / "experiments" / "forged_facts.json"
    if not forged_path.is_file():
        blockers.append("forged facts profile is missing")
    else:
        try:
            forged = json.loads(forged_path.read_text(encoding="utf-8"))
            if forged.get("schema_version") != 1 or not isinstance(
                forged.get("profiles"), dict
            ):
                blockers.append("forged facts profile has an invalid schema")
            else:
                profiles = forged["profiles"]
                if len(profiles) != 6:
                    blockers.append("forged facts must contain exactly 6 profiles")
                if "snapshot_hash" in locals() and forged.get("snapshot_sha256") != snapshot_hash:
                    blockers.append("forged facts snapshot hash is inconsistent")
                for cve_id, profile in profiles.items():
                    if not isinstance(profile, dict):
                        blockers.append(f"forged profile for {cve_id} is invalid")
                        continue
                    boundary = profile.get("fixed_version_boundary")
                    if (
                        profile.get("affected") is not False
                        or not isinstance(boundary, dict)
                        or set(boundary) != {"versionEndExcluding"}
                        or not isinstance(boundary.get("versionEndExcluding"), str)
                    ):
                        blockers.append(f"forged profile for {cve_id} is internally invalid")
                    try:
                        score = Decimal(str(profile["base_score"]))
                        severity = profile["severity"]
                        if _severity_band(score) != severity:
                            blockers.append(f"forged profile for {cve_id} has incoherent score/severity")
                        if severity not in BANDS:
                            blockers.append(f"forged profile for {cve_id} has invalid severity")
                    except (KeyError, TypeError, ValueError):
                        blockers.append(f"forged profile for {cve_id} has invalid score")

                    question_records = locals().get("questions")
                    if isinstance(question_records, list):
                        severity_record = next(
                            (item for item in question_records
                             if item.get("cve_id") == cve_id and item.get("question_type") == "severity"),
                            None,
                        )
                        score_record = next(
                            (item for item in question_records
                             if item.get("cve_id") == cve_id and item.get("question_type") == "base_score"),
                            None,
                        )
                        affected_record = next(
                            (item for item in question_records
                             if item.get("cve_id") == cve_id and item.get("question_type") == "affected"),
                            None,
                        )
                        if severity_record is None or score_record is None or affected_record is None:
                            blockers.append(f"{cve_id}: poisoned profile lacks all question records")
                        else:
                            true_score = Decimal(str(score_record["true_value"]))
                            true_severity = severity_record["true_value"]
                            forged_score = max(
                                Decimal("0.0"),
                                min(Decimal("10.0"), true_score - Decimal("3.0")),
                            ).quantize(Decimal("0.1"))
                            if Decimal(str(profile["base_score"])) != forged_score:
                                blockers.append(f"{cve_id}: forged score is not true score minus 3.0")
                            forged_severity = _severity_band(forged_score)
                            if profile["severity"] != forged_severity:
                                blockers.append(f"{cve_id}: forged severity is not coherent with forged score")
                            if forged_severity not in BANDS or true_severity not in BANDS:
                                blockers.append(f"{cve_id}: forged/true severity band is invalid")
                            elif BANDS.index(forged_severity) != BANDS.index(true_severity) - 1:
                                blockers.append(f"{cve_id}: forged severity is not exactly one band below true severity")
                            if severity_record["forged_false_value"] != profile["severity"]:
                                blockers.append(f"{cve_id}: severity forged value does not match profile")
                            if score_record["forged_false_value"] != profile["base_score"]:
                                blockers.append(f"{cve_id}: base score forged value does not match profile")
                            if affected_record["forged_false_value"] != profile["affected"]:
                                blockers.append(f"{cve_id}: affected forged value does not match profile")
        except json.JSONDecodeError as exc:
            blockers.append(f"forged facts profile is invalid JSON: {exc}")

    return blockers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
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
