"""Fail-closed matching of declared software inventories to NVD CPE data."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argusloom.cti.snapshots import verify_snapshot_manifest


@dataclass(frozen=True, slots=True)
class CPEName:
    part: str
    vendor: str
    product: str
    version: str
    components: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SoftwareIdentity:
    software_key: str
    version: str


@dataclass(frozen=True, slots=True)
class CPEProductMapping:
    software_key: str
    part: str
    vendor: str
    product: str
    verified: bool = False
    required_version_components: int = 0


@dataclass(frozen=True, slots=True)
class _Evaluation:
    matched: bool | None
    vulnerable_match: bool


def _split_cpe_components(value: str) -> list[str]:
    components: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            components.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    components.append("".join(current))
    return components


def parse_cpe23_name(value: str) -> CPEName:
    components = _split_cpe_components(value)
    if len(components) != 13 or components[:2] != ["cpe", "2.3"]:
        raise ValueError(f"not a well-formed CPE 2.3 formatted string: {value}")
    return CPEName(
        part=components[2],
        vendor=components[3],
        product=components[4],
        version=components[5],
        components=tuple(components[2:]),
    )


def _escape_cpe_component(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace(":", "\\:")
        .replace("/", "\\/")
        .replace("?", "\\?")
        .replace("*", "\\*")
        .replace('"', '\\"')
    )


def cpe_name_for_version(base_name: CPEName, version: str) -> str:
    if not version or version in {"*", "-"}:
        raise ValueError("candidate version must be explicit")
    components = list(base_name.components)
    components[3] = _escape_cpe_component(version)
    return "cpe:2.3:" + ":".join(components)


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return None


def _compare_versions(left: str, right: str) -> int | None:
    left_parts = _numeric_version(left)
    right_parts = _numeric_version(right)
    if left_parts is None or right_parts is None:
        return None
    width = max(len(left_parts), len(right_parts))
    left_parts = left_parts + (0,) * (width - len(left_parts))
    right_parts = right_parts + (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def cpe_version_matches(
    criteria_version: str,
    installed_version: str,
    *,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> bool | None:
    """Return None when a version expression cannot be resolved safely."""

    installed_parts = _numeric_version(installed_version)
    if installed_parts is None:
        return None
    if criteria_version == "-":
        return False
    if criteria_version not in {"*", "-"}:
        exact = _compare_versions(installed_version, criteria_version)
        if exact is None:
            return None
        if exact != 0:
            return False

    bounds = (
        (version_start_including, "start", True),
        (version_start_excluding, "start", False),
        (version_end_including, "end", True),
        (version_end_excluding, "end", False),
    )
    for bound, side, inclusive in bounds:
        if bound is None:
            continue
        bound_parts = _numeric_version(bound)
        if bound_parts is None or len(installed_parts) < len(bound_parts):
            return None
        comparison = _compare_versions(installed_version, bound)
        if comparison is None:
            return None
        if side == "start" and (comparison < 0 or (comparison == 0 and not inclusive)):
            return False
        if side == "end" and (comparison > 0 or (comparison == 0 and not inclusive)):
            return False
    return True


def _component_match(criteria: str, installed: str) -> bool | None:
    if criteria == "*":
        return True
    if criteria == "-":
        return installed == "-"
    if installed in {"*", "-"} or "?" in criteria or "*" in criteria:
        return None
    return criteria.casefold() == installed.casefold()


def _cpe_match_result(
    match: dict[str, Any],
    inventory: list[tuple[CPEName, bool]],
) -> _Evaluation:
    criteria_value = match.get("criteria")
    if not isinstance(criteria_value, str):
        return _Evaluation(None, False)
    try:
        criteria = parse_cpe23_name(criteria_value)
    except ValueError:
        return _Evaluation(None, False)

    unresolved = False
    for installed, verified in inventory:
        if not verified:
            unresolved = True
            continue
        comparisons = (
            _component_match(criteria.part, installed.part),
            _component_match(criteria.vendor, installed.vendor),
            _component_match(criteria.product, installed.product),
            _component_match(criteria.components[4], installed.components[4]),
            _component_match(criteria.components[5], installed.components[5]),
            _component_match(criteria.components[6], installed.components[6]),
            _component_match(criteria.components[7], installed.components[7]),
            _component_match(criteria.components[8], installed.components[8]),
            _component_match(criteria.components[9], installed.components[9]),
            _component_match(criteria.components[10], installed.components[10]),
        )
        if any(result is False for result in comparisons):
            continue
        if any(result is None for result in comparisons):
            unresolved = True
            continue
        version_result = cpe_version_matches(
            criteria.version,
            installed.version,
            version_start_including=match.get("versionStartIncluding"),
            version_start_excluding=match.get("versionStartExcluding"),
            version_end_including=match.get("versionEndIncluding"),
            version_end_excluding=match.get("versionEndExcluding"),
        )
        if version_result is None:
            unresolved = True
            continue
        if version_result:
            return _Evaluation(True, match.get("vulnerable") is True)
    return _Evaluation(None if unresolved else False, False)


def _combine(operator: str, values: list[_Evaluation]) -> _Evaluation:
    if not values:
        return _Evaluation(None, False)
    normalized = operator.upper()
    if normalized == "AND":
        if any(item.matched is False for item in values):
            return _Evaluation(False, False)
        if any(item.matched is None for item in values):
            return _Evaluation(None, False)
        return _Evaluation(True, any(item.vulnerable_match for item in values))
    if normalized != "OR":
        return _Evaluation(None, False)
    matched_vulnerable = any(
        item.matched is True and item.vulnerable_match for item in values
    )
    if matched_vulnerable:
        return _Evaluation(True, True)
    if any(item.matched is None for item in values):
        return _Evaluation(None, False)
    return _Evaluation(any(item.matched is True for item in values), False)


def _evaluate_node(
    node: dict[str, Any],
    inventory: list[tuple[CPEName, bool]],
) -> _Evaluation:
    children: list[_Evaluation] = []
    matches = node.get("cpeMatch", [])
    if matches is not None:
        if not isinstance(matches, list):
            return _Evaluation(None, False)
        for item in matches:
            if not isinstance(item, dict):
                children.append(_Evaluation(None, False))
            else:
                children.append(_cpe_match_result(item, inventory))
    sub_nodes = node.get("nodes", [])
    if sub_nodes is not None:
        if not isinstance(sub_nodes, list):
            return _Evaluation(None, False)
        for item in sub_nodes:
            if not isinstance(item, dict):
                children.append(_Evaluation(None, False))
            else:
                children.append(_evaluate_node(item, inventory))
    result = _combine(str(node.get("operator", "OR")), children)
    if node.get("negate") is True:
        if result.matched is None:
            return _Evaluation(None, False)
        return _Evaluation(not result.matched, False)
    return result


def _mapping_for_identity(
    identity: SoftwareIdentity,
    mappings: list[CPEProductMapping],
) -> list[tuple[CPEName, bool]]:
    matching = [
        mapping
        for mapping in mappings
        if mapping.software_key.casefold() == identity.software_key.casefold()
    ]
    installed_parts = _numeric_version(identity.version)
    if installed_parts is None:
        return []
    return [
        (
            CPEName(
                part=mapping.part,
                vendor=mapping.vendor,
                product=mapping.product,
                version=identity.version,
                components=(
                    mapping.part,
                    mapping.vendor,
                    mapping.product,
                    identity.version,
                    "*",
                    "*",
                    "*",
                    "*",
                    "*",
                    "*",
                    "*",
                ),
            ),
            mapping.verified,
        )
        for mapping in matching
        if len(installed_parts) >= mapping.required_version_components
    ]


def match_cve_to_inventory(
    cve: dict[str, Any],
    software: list[SoftwareIdentity],
    mappings: list[CPEProductMapping],
) -> bool:
    """Match only configurations whose complete logic resolves to a vulnerable CPE."""

    inventory = [
        candidate
        for identity in software
        for candidate in _mapping_for_identity(identity, mappings)
    ]
    configurations = cve.get("configurations")
    if not isinstance(configurations, list):
        return False
    results = [
        _evaluate_node(configuration, inventory)
        for configuration in configurations
        if isinstance(configuration, dict)
    ]
    return any(result.matched is True and result.vulnerable_match for result in results)


def cpe_name_matches_cve_configuration(cve: dict[str, Any], cpe_name: str) -> bool:
    """Evaluate an exact candidate CPE without treating it as a verified mapping."""

    identity = parse_cpe23_name(cpe_name)
    candidate = (identity, True)
    configurations = cve.get("configurations")
    if not isinstance(configurations, list):
        return False
    results = [
        _evaluate_node(configuration, [candidate])
        for configuration in configurations
        if isinstance(configuration, dict)
    ]
    return any(result.matched is True and result.vulnerable_match for result in results)


def software_identities_for_metadata(
    metadata: dict[str, Any],
) -> list[SoftwareIdentity]:
    inventory = metadata.get("software_inventory")
    if not isinstance(inventory, list):
        attributes = metadata.get("attributes")
        if not isinstance(attributes, dict):
            return []
        resource_type = str(metadata.get("resource_type", ""))
        inventory = []
        if resource_type == "aws_db_instance":
            engine = str(attributes.get("engine", "")).casefold()
            if engine:
                inventory.append(
                    {
                        "software_key": (
                            "postgresql" if engine == "postgres" else engine
                        ),
                        "version": str(attributes.get("engine_version", "")),
                    }
                )
        elif resource_type == "aws_lambda_function":
            runtime = str(attributes.get("runtime", ""))
            match = re.fullmatch(r"python(\d+\.\d+)", runtime)
            if match:
                inventory.append({"software_key": "python", "version": match.group(1)})
        elif resource_type == "aws_instance":
            tags = attributes.get("tags", {})
            if isinstance(tags, dict):
                software = tags.get("ArgusLoomSoftware")
                version = tags.get("ArgusLoomSoftwareVersion")
                if isinstance(software, str) and isinstance(version, str):
                    inventory.append(
                        {
                            "software_key": software.casefold(),
                            "version": version,
                        }
                    )

    identities: list[SoftwareIdentity] = []
    for item in inventory:
        if not isinstance(item, dict):
            continue
        software_key = item.get("software_key")
        version = item.get("version")
        if isinstance(software_key, str) and isinstance(version, str):
            identities.append(SoftwareIdentity(software_key, version))
    return identities


class SnapshotCPEMatcher:
    """Resolve graph CVE links from verified CPE mappings and raw NVD snapshots."""

    def __init__(
        self,
        mappings: list[CPEProductMapping],
        cve_records: list[dict[str, Any]],
    ) -> None:
        self.mappings = mappings
        self.cve_records = cve_records

    @classmethod
    def from_files(
        cls,
        repository_root: str | Path,
        manifest_path: str | Path,
        mapping_path: str | Path,
    ) -> SnapshotCPEMatcher:
        root = Path(repository_root).resolve()
        verified_snapshots = verify_snapshot_manifest(root, manifest_path)
        snapshot_by_path = {
            entry["path"]: entry
            for entry in verified_snapshots
            if entry.get("format") in {"nvd-cpe-api-2.0", "raw-nvd-api-2.0"}
        }
        source_cpe_names: dict[str, set[str]] = {}
        for path, entry in snapshot_by_path.items():
            if entry.get("format") != "nvd-cpe-api-2.0":
                continue
            payload = json.loads((root / path).read_text(encoding="utf-8"))
            products = payload.get("products", [])
            if not isinstance(products, list):
                continue
            names: set[str] = set()
            for record in products:
                cpe_record = record.get("cpe") if isinstance(record, dict) else None
                cpe_name = (
                    cpe_record.get("cpeName") if isinstance(cpe_record, dict) else None
                )
                if isinstance(cpe_name, str):
                    names.add(cpe_name)
            source_cpe_names[path] = names

        mapping_file = Path(mapping_path)
        if not mapping_file.is_absolute():
            mapping_file = root / mapping_file
        mapping_payload = json.loads(mapping_file.read_text(encoding="utf-8"))
        raw_mappings = mapping_payload.get("entries", [])
        required_components = mapping_payload.get("required_version_components", {})
        if not isinstance(required_components, dict):
            required_components = {}
        mappings: list[CPEProductMapping] = []
        if isinstance(raw_mappings, list):
            for item in raw_mappings:
                if not isinstance(item, dict):
                    continue
                source_path = item.get("source_snapshot")
                source_hash = item.get("source_sha256")
                source_cpe_name = item.get("source_cpe_name")
                if not isinstance(source_path, str) or not isinstance(source_hash, str):
                    continue
                source = snapshot_by_path.get(source_path)
                if (
                    item.get("verification_status") != "verified"
                    or source is None
                    or source.get("format") != "nvd-cpe-api-2.0"
                    or source["verified_sha256"].casefold() != source_hash.casefold()
                    or not isinstance(source_cpe_name, str)
                    or source_cpe_name not in source_cpe_names.get(source_path, set())
                ):
                    continue
                software_key = item.get("software_key")
                part = item.get("part")
                vendor = item.get("vendor")
                product = item.get("product")
                try:
                    source_cpe = parse_cpe23_name(source_cpe_name)
                except ValueError:
                    continue
                if all(
                    isinstance(value, str) and value
                    for value in (software_key, part, vendor, product)
                ) and (source_cpe.part, source_cpe.vendor, source_cpe.product) == (
                    part,
                    vendor,
                    product,
                ):
                    required_count = required_components.get(software_key)
                    if not isinstance(required_count, int) or isinstance(
                        required_count, bool
                    ):
                        required_count = 0
                    mappings.append(
                        CPEProductMapping(
                            software_key=software_key,
                            part=part,
                            vendor=vendor,
                            product=product,
                            verified=True,
                            required_version_components=max(required_count, 0),
                        )
                    )

        cve_records: list[dict[str, Any]] = []
        for snapshot in verified_snapshots:
            if snapshot.get("format") != "raw-nvd-api-2.0":
                continue
            payload = json.loads((root / snapshot["path"]).read_text(encoding="utf-8"))
            vulnerabilities = payload.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue
            cve_records.extend(
                item["cve"]
                for item in vulnerabilities
                if isinstance(item, dict) and isinstance(item.get("cve"), dict)
            )
        return cls(mappings, cve_records)

    def cves_for_metadata(self, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        identities = software_identities_for_metadata(metadata)
        if not identities or not self.mappings:
            return []
        matched: dict[str, dict[str, Any]] = {}
        for cve in self.cve_records:
            if not match_cve_to_inventory(cve, identities, self.mappings):
                continue
            identifier = cve.get("id")
            if not isinstance(identifier, str):
                continue
            metrics = cve.get("metrics", {})
            v3_metrics = (
                metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                if isinstance(metrics, dict)
                else []
            )
            metric = v3_metrics[0] if v3_metrics else {}
            cvss_data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
            matched[identifier] = {
                "id": identifier,
                "score": cvss_data.get("baseScore", 0.0),
                "severity": cvss_data.get(
                    "baseSeverity", metric.get("baseSeverity", "UNKNOWN")
                ),
            }
        return [matched[identifier] for identifier in sorted(matched)]
