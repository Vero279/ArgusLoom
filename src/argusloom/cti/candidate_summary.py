"""Offline summaries of exact-CPE NVD snapshots for candidate software versions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from argusloom.cti.cpe_matcher import (
    cpe_name_for_version,
    cpe_name_matches_cve_configuration,
    parse_cpe23_name,
)
from argusloom.cti.snapshots import verify_snapshot_manifest

SEVERITY_BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NO_V3")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"expected a JSON object in {path}")
    return value


def _cpe_dictionary_names(
    root: Path, snapshots: list[dict[str, Any]]
) -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    for snapshot in snapshots:
        if snapshot.get("format") != "nvd-cpe-api-2.0":
            continue
        payload = _read_json(root / snapshot["path"])
        records = payload.get("products", [])
        if not isinstance(records, list):
            continue
        source_names: set[str] = set()
        for record in records:
            cpe = record.get("cpe") if isinstance(record, dict) else None
            cpe_name = cpe.get("cpeName") if isinstance(cpe, dict) else None
            if isinstance(cpe_name, str):
                source_names.add(cpe_name)
        names[snapshot["path"]] = source_names
    return names


def _candidate_mappings(
    mapping_file: Path,
    verified_snapshots: list[dict[str, Any]],
    dictionary_names: dict[str, set[str]],
) -> list[dict[str, str]]:
    mapping_payload = _read_json(mapping_file)
    entries = mapping_payload.get("entries")
    if not isinstance(entries, list):
        raise TypeError("CPE product mapping table must contain an entries list")
    snapshots_by_path = {snapshot["path"]: snapshot for snapshot in verified_snapshots}
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            continue
        source_path = item.get("source_snapshot")
        source_hash = item.get("source_sha256")
        source_cpe_name = item.get("source_cpe_name")
        software_key = item.get("software_key")
        part = item.get("part")
        vendor = item.get("vendor")
        product = item.get("product")
        source = (
            snapshots_by_path.get(source_path) if isinstance(source_path, str) else None
        )
        if (
            source is None
            or source.get("format") != "nvd-cpe-api-2.0"
            or source.get("verified_sha256", "").casefold()
            != str(source_hash).casefold()
            or not isinstance(source_cpe_name, str)
            or source_cpe_name not in dictionary_names.get(source_path, set())
            or not all(
                isinstance(value, str) and value
                for value in (software_key, part, vendor, product)
            )
        ):
            continue
        parsed = parse_cpe23_name(source_cpe_name)
        if (parsed.part, parsed.vendor, parsed.product) != (part, vendor, product):
            continue
        key = (software_key.casefold(), part, vendor, product)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "software_key": software_key.casefold(),
                "part": part,
                "vendor": vendor,
                "product": product,
                "verification_status": (
                    "VERIFIED"
                    if item.get("verification_status") == "verified"
                    else "PENDING_USER_VERIFICATION"
                ),
                "source_snapshot": source_path,
                "source_cpe_name": source_cpe_name,
            }
        )
    return candidates


def _v3_severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for metric_name in sorted(
        (name for name in metrics if name.startswith("cvssMetricV3")),
        reverse=True,
    ):
        metric_list = metrics[metric_name]
        if not isinstance(metric_list, list):
            continue
        for metric in metric_list:
            cvss_data = metric.get("cvssData") if isinstance(metric, dict) else None
            if not isinstance(cvss_data, dict):
                continue
            severity = cvss_data.get("baseSeverity")
            score = cvss_data.get("baseScore")
            if isinstance(severity, str) and isinstance(score, (float, int)):
                normalized = severity.upper()
                if normalized in SEVERITY_BUCKETS[:-1]:
                    return normalized
    return None


def _record_summary(cves: dict[str, dict[str, Any]]) -> tuple[int, dict[str, int], str]:
    distribution = {severity: 0 for severity in SEVERITY_BUCKETS}
    years: list[int] = []
    v3_count = 0
    for cve in cves.values():
        severity = _v3_severity(cve)
        if severity is None:
            distribution["NO_V3"] += 1
        else:
            distribution[severity] += 1
            v3_count += 1
        published = cve.get("published")
        if isinstance(published, str):
            match = re.match(r"^(\d{4})", published)
            if match:
                years.append(int(match.group(1)))
    year_range = f"{min(years)}-{max(years)}" if years else "NOT AVAILABLE"
    return v3_count, distribution, year_range


def summarize_candidate_versions(
    repository_root: str | Path,
    manifest_path: str | Path,
    mapping_path: str | Path,
    candidate_versions_path: str | Path,
) -> list[dict[str, Any]]:
    """Summarize CVEs only from hash-verified exact-CPE NVD query snapshots."""

    root = Path(repository_root).resolve()
    verified = verify_snapshot_manifest(root, manifest_path)
    dictionary_names = _cpe_dictionary_names(root, verified)
    mapping_file = Path(mapping_path)
    if not mapping_file.is_absolute():
        mapping_file = root / mapping_file
    mappings = _candidate_mappings(mapping_file, verified, dictionary_names)
    versions_file = Path(candidate_versions_path)
    if not versions_file.is_absolute():
        versions_file = root / versions_file
    version_payload = _read_json(versions_file)
    version_sets = version_payload.get("candidates")
    if not isinstance(version_sets, dict):
        raise TypeError("candidate versions file must contain a candidates object")

    query_snapshots: dict[str, list[dict[str, Any]]] = {}
    for snapshot in verified:
        if snapshot.get("query_mode") != "cpe_name":
            continue
        query = snapshot.get("query")
        cpe_name = query.get("cpeName") if isinstance(query, dict) else None
        if isinstance(cpe_name, str):
            query_snapshots.setdefault(cpe_name, []).append(snapshot)

    rows: list[dict[str, Any]] = []
    for mapping in mappings:
        software_key = mapping["software_key"]
        versions = version_sets.get(software_key, [])
        if not isinstance(versions, list):
            raise TypeError(f"candidate versions for {software_key} must be a list")
        source_name = mapping["source_cpe_name"]
        if not isinstance(source_name, str):
            continue
        base_name = parse_cpe23_name(source_name)
        for version in versions:
            if not isinstance(version, str) or not version:
                raise ValueError(f"invalid candidate version for {software_key}")
            exact_name = cpe_name_for_version(base_name, version)
            matching_snapshots = query_snapshots.get(exact_name, [])
            if not matching_snapshots:
                rows.append(
                    {
                        **mapping,
                        "version": version,
                        "cpe_name": exact_name,
                        "status": "NOT_FETCHED",
                        "total_cves": None,
                        "cvss_v3x_cves": None,
                        "severity_distribution": None,
                        "publication_year_range": None,
                    }
                )
                continue
            latest_version = max(
                int(snapshot.get("manifest_version", 1))
                for snapshot in matching_snapshots
            )
            latest_snapshots = [
                snapshot
                for snapshot in matching_snapshots
                if int(snapshot.get("manifest_version", 1)) == latest_version
            ]
            cves: dict[str, dict[str, Any]] = {}
            for snapshot in latest_snapshots:
                payload = _read_json(root / snapshot["path"])
                vulnerabilities = payload.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    continue
                for vulnerability in vulnerabilities:
                    cve = (
                        vulnerability.get("cve")
                        if isinstance(vulnerability, dict)
                        else None
                    )
                    identifier = cve.get("id") if isinstance(cve, dict) else None
                    if isinstance(
                        identifier, str
                    ) and cpe_name_matches_cve_configuration(cve, exact_name):
                        cves[identifier] = cve
            v3_count, distribution, year_range = _record_summary(cves)
            rows.append(
                {
                    **mapping,
                    "version": version,
                    "cpe_name": exact_name,
                    "status": (
                        "FETCHED_MAPPING_VERIFIED"
                        if mapping["verification_status"] == "VERIFIED"
                        else "FETCHED_PENDING_MAPPING_VERIFICATION"
                    ),
                    "total_cves": len(cves),
                    "cvss_v3x_cves": v3_count,
                    "severity_distribution": distribution,
                    "publication_year_range": year_range,
                }
            )
    if not rows:
        raise ValueError(
            "no source-backed CPE product candidates found; run NVD CPE dictionary discovery first"
        )
    return rows
