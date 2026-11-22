"""Build the deterministic Stage C question and forged-fact datasets."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from argusloom.cti.cpe_matcher import (
    CPEProductMapping,
    SoftwareIdentity,
    match_cve_to_inventory,
)

ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "experiments" / "cve_selection.json"
SNAPSHOT_PATH = (
    ROOT
    / "data"
    / "nvd"
    / "snapshots"
    / "v3"
    / "cve"
    / "cve_ids-3db1efccae05-page-0000.json"
)
GRAPH_PATH = ROOT / "data" / "graph_C.json"
MAPPING_PATH = ROOT / "data" / "cpe_product_mappings.json"
QUESTIONS_PATH = ROOT / "experiments" / "questions.json"
FORGED_PATH = ROOT / "experiments" / "forged_facts.json"

BANDS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def decimal_score(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("CVSS baseScore must be numeric")
    score = Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    if score < 0 or score > 10:
        raise ValueError(f"CVSS baseScore outside 0.0-10.0: {score}")
    return score


def severity_band(score: Decimal) -> str:
    if score == 0:
        return "NONE"
    if score < Decimal("4.0"):
        return "LOW"
    if score < Decimal("7.0"):
        return "MEDIUM"
    if score < Decimal("9.0"):
        return "HIGH"
    return "CRITICAL"


def snapshot_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def cvss_metric(cve: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"{cve.get('id')} has no CVSS metrics")

    entries = metrics.get("cvssMetricV31")
    version = "3.1"
    if not isinstance(entries, list) or not entries:
        entries = metrics.get("cvssMetricV30")
        version = "3.0"
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{cve.get('id')} has no cvssMetricV31 or cvssMetricV30")

    primary = [entry for entry in entries if isinstance(entry, dict) and entry.get("type") == "Primary"]
    if primary:
        qualified = primary
        rule = "primary"
    else:
        source_identifier = cve.get("sourceIdentifier")
        qualified = [
            entry
            for entry in entries
            if isinstance(entry, dict) and entry.get("source") == source_identifier
        ]
        rule = "cna"

    if not qualified:
        raise ValueError(
            f"{cve.get('id')} has no qualifying CVSS metric entry "
            "(no Primary or sourceIdentifier match)"
        )

    normalized: list[tuple[dict[str, Any], Decimal, str]] = []
    for entry in qualified:
        cvss_data = entry.get("cvssData")
        if not isinstance(cvss_data, dict):
            raise ValueError(f"{cve.get('id')} qualifying metric lacks cvssData")
        score = decimal_score(cvss_data.get("baseScore"))
        severity = cvss_data.get("baseSeverity")
        if not isinstance(severity, str):
            raise ValueError(f"{cve.get('id')} qualifying metric lacks baseSeverity")
        normalized.append((entry, score, severity))

    first_value = (normalized[0][1], normalized[0][2])
    if any((score, severity) != first_value for _, score, severity in normalized[1:]):
        raise ValueError(
            f"{cve.get('id')} has multiple qualifying metrics with different values"
        )

    selected = normalized[0][0]
    return selected, rule, version


def cpe_mappings() -> list[CPEProductMapping]:
    payload = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    required = payload.get("required_version_components", {})
    mappings: list[CPEProductMapping] = []
    for item in payload.get("entries", []):
        if not isinstance(item, dict) or item.get("verification_status") != "verified":
            continue
        if not all(
            isinstance(item.get(field), str) and item[field]
            for field in ("software_key", "part", "vendor", "product")
        ):
            continue
        count = required.get(item["software_key"], 0)
        mappings.append(
            CPEProductMapping(
                software_key=item["software_key"],
                part=item["part"],
                vendor=item["vendor"],
                product=item["product"],
                verified=True,
                required_version_components=max(count if isinstance(count, int) else 0, 0),
            )
        )
    return mappings


def software_identity(metadata: dict[str, Any]) -> list[SoftwareIdentity]:
    inventory = metadata.get("software_inventory")
    if not isinstance(inventory, list):
        return []
    identities: list[SoftwareIdentity] = []
    for item in inventory:
        if not isinstance(item, dict):
            continue
        software_key = item.get("software_key")
        version = item.get("version")
        if isinstance(software_key, str) and isinstance(version, str):
            identities.append(SoftwareIdentity(software_key, version))
    return identities


def main() -> None:
    selection = json.loads(SELECTION_PATH.read_text(encoding="utf-8"))
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    snapshot_hash = snapshot_sha256(SNAPSHOT_PATH)

    cves: dict[str, dict[str, Any]] = {}
    for item in snapshot.get("vulnerabilities", []):
        cve = item.get("cve") if isinstance(item, dict) else None
        if isinstance(cve, dict) and isinstance(cve.get("id"), str):
            cves[cve["id"]] = cve

    nodes = {node["id"]: node for node in graph.get("nodes", []) if isinstance(node, dict)}
    node_map = {
        "nginx": "aws_instance.web",
        "postgresql": "aws_db_instance.database",
    }
    node_versions = {
        node_id: node["metadata"]["software_inventory"][0]["version"]
        for node_id, node in nodes.items()
        if node_id in node_map.values()
    }
    mappings = cpe_mappings()

    profiles: dict[str, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    sequence = 1

    all_entries = [
        ("poisoned", entry)
        for entry in selection["poisoned"]
    ] + [
        ("control", entry)
        for entry in selection["controls"]
    ]
    for group, entry in all_entries:
        cve_id = entry["cve"]
        software_key = entry["node"]
        node_id = node_map[software_key]
        cve = cves.get(cve_id)
        if cve is None:
            raise ValueError(f"Snapshot does not contain selected CVE {cve_id}")

        selected, selection_rule, metric_version = cvss_metric(cve)
        cvss_data = selected["cvssData"]
        true_score = decimal_score(cvss_data["baseScore"])
        true_severity = str(cvss_data["baseSeverity"])
        if severity_band(true_score) != true_severity:
            raise ValueError(
                f"{cve_id}: true severity {true_severity} is incoherent with "
                f"true score {true_score}"
            )
        source_field = (
            f"vulnerabilities[].cve.metrics.cvssMetricV{metric_version.replace('.', '')}"
            f"[].cvssData"
        )

        metric_entries = (
            cve["metrics"].get("cvssMetricV31")
            if metric_version == "3.1"
            else cve["metrics"].get("cvssMetricV30")
        )
        other_sources: list[dict[str, Any]] = []
        for entry_metric in metric_entries:
            if entry_metric is selected:
                continue
            data = entry_metric.get("cvssData", {})
            other_sources.append(
                {
                    "source": entry_metric.get("source"),
                    "score": decimal_score(data.get("baseScore")),
                }
            )

        identities = software_identity(nodes[node_id].get("metadata", {}))
        affected = match_cve_to_inventory(cve, identities, mappings)
        profile: dict[str, Any] | None = None
        if group == "poisoned":
            forged_score = min(
                Decimal("10.0"),
                max(
                    Decimal("0.0"),
                    (true_score - Decimal("3.0")).quantize(
                        Decimal("0.1"), rounding=ROUND_HALF_UP
                    ),
                ),
            )
            forged_severity = severity_band(forged_score)
            true_index = BANDS.index(true_severity)
            forged_index = BANDS.index(forged_severity)
            if forged_index != true_index - 1:
                raise ValueError(
                    f"{cve_id}: forged band {forged_severity} is not exactly one "
                    f"band below true band {true_severity}"
                )
            boundary = {"versionEndExcluding": node_versions[node_id]}
            profile = {
                "severity": forged_severity,
                "base_score": float(forged_score),
                "affected": False,
                "fixed_version_boundary": boundary,
            }
            profiles[cve_id] = profile

        question_specs = (
            ("severity", true_severity, f"{source_field}.baseSeverity"),
            ("base_score", float(true_score), f"{source_field}.baseScore"),
            ("affected", affected, "vulnerabilities[].cve.configurations"),
        )
        for question_type, true_value, field_path in question_specs:
            if question_type == "affected":
                question = (
                    f"Is {node_versions[node_id]} of {software_key} on {node_id} "
                    f"affected by {cve_id}?"
                )
                forged_value = (
                    profile["affected"] if profile is not None else None
                )
            elif question_type == "severity":
                question = f"What is the CVSS v3.x baseSeverity for {cve_id}?"
                forged_value = profile["severity"] if profile is not None else None
            else:
                question = f"What is the CVSS v3.x baseScore for {cve_id}?"
                forged_value = profile["base_score"] if profile is not None else None

            record = {
                "question_id": f"Q{sequence:03d}",
                "cve_id": cve_id,
                "question_type": question_type,
                "question": question,
                "true_value": true_value,
                "source_field_path": field_path,
                "metric_source": selected.get("source"),
                "metric_type": selected.get("type"),
                "metric_selection_rule": selection_rule,
                "metric_version": metric_version,
                "other_metric_sources": [
                    {**item, "score": float(item["score"])}
                    for item in other_sources
                ],
                "affected_node": node_id,
                "group": group,
                "forged_false_value": forged_value,
                "snapshot_sha256": snapshot_hash,
                "nvd_last_modified": cve.get("lastModified"),
                "expected": {question_type: true_value},
                "source_refs": [field_path],
            }
            records.append(record)
            sequence += 1

    if len(records) != 30:
        raise ValueError(f"Expected 30 records, generated {len(records)}")
    if len(profiles) != 6:
        raise ValueError(f"Expected 6 poisoned profiles, generated {len(profiles)}")

    QUESTIONS_PATH.write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    FORGED_PATH.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_sha256": snapshot_hash,
                "profiles": profiles,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
