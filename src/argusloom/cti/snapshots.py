"""Verify committed CTI snapshots before they enter the experiment corpus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def verify_snapshot_manifest(
    repository_root: str | Path,
    manifest_path: str | Path,
) -> list[dict[str, Any]]:
    root = Path(repository_root).resolve()
    manifest_file = Path(manifest_path)
    if not manifest_file.is_absolute():
        manifest_file = root / manifest_file
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, list):
        raise TypeError("CTI snapshot manifest must contain a snapshots list")

    verified: list[dict[str, Any]] = []
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            raise TypeError("CTI snapshot entries must be objects")
        relative_path = snapshot.get("path")
        expected_hash = snapshot.get("sha256")
        if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
            raise TypeError("Each CTI snapshot needs path and sha256 strings")
        file_path = (root / relative_path).resolve()
        try:
            file_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("CTI snapshot path escapes the repository") from exc
        if not file_path.is_file():
            if relative_path in {
                "data/mitre/official/enterprise-attack-20.1.json",
                "data/mitre/official/ATLAS-2026.10.yaml",
            }:
                raise FileNotFoundError(
                    f"Missing official MITRE data; run scripts/fetch_mitre_official.py "
                    f"locally. Missing source: {relative_path}"
                )
            raise FileNotFoundError(f"CTI snapshot not found: {relative_path}")
        if expected_hash == "PENDING_FIRST_DERIVATION":
            metadata_file = root / "data" / "mitre" / "derived_metadata.json"
            if not metadata_file.is_file():
                raise FileNotFoundError(
                    "Missing MITRE derived metadata: data/mitre/derived_metadata.json"
                )
            metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            record = metadata.get(Path(relative_path).name)
            if not isinstance(record, dict):
                raise ValueError(
                    f"Missing MITRE derived metadata entry: {Path(relative_path).name}"
                )
            expected_hash = str(record.get("derived_sha256", ""))
            if expected_hash == "PENDING_FIRST_DERIVATION":
                raise FileNotFoundError(
                    "MITRE derived data has not completed its first derivation"
                )
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest().upper()
        if digest != expected_hash.upper():
            raise ValueError(f"CTI snapshot hash mismatch: {relative_path}")
        verified.append({**snapshot, "verified_sha256": digest})
    return verified


def require_experiment_ready_manifest(manifest_path: str | Path) -> dict[str, Any]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("status") != "ready":
        raise ValueError(
            "CTI snapshots are not experiment-ready; require raw source snapshots "
            "with release/version provenance and verified hashes"
        )
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, list) or not snapshots:
        raise TypeError("experiment-ready manifest must include snapshots")
    if any(not item.get("experiment_eligible", False) for item in snapshots):
        raise ValueError("all snapshots must be marked experiment_eligible")
    return manifest


def verify_derived_mitre_metadata(
    repository_root: str | Path,
    metadata_path: str | Path = "data/mitre/derived_metadata.json",
) -> list[dict[str, Any]]:
    """Verify derived MITRE arrays and record metadata against local metadata."""
    root = Path(repository_root).resolve()
    metadata_file = Path(metadata_path)
    if not metadata_file.is_absolute():
        metadata_file = root / metadata_file
    if not metadata_file.is_file():
        raise FileNotFoundError(
            f"Missing MITRE derived metadata: {metadata_file.relative_to(root)}"
        )
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    verified: list[dict[str, Any]] = []
    for relative_path, record in metadata.items():
        if not isinstance(record, dict):
            raise TypeError("MITRE derived metadata entries must be objects")
        derived_path = root / "data" / "mitre" / relative_path
        if not derived_path.is_file():
            raise FileNotFoundError(
                f"MITRE derived file not found: data/mitre/{relative_path}"
            )
        payload = json.loads(derived_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise TypeError(f"MITRE derived file must contain a list: {relative_path}")
        count = len(payload)
        if count != record.get("record_count"):
            raise ValueError(
                f"MITRE derived count mismatch: {relative_path} "
                f"expected {record.get('record_count')}, got {count}"
            )
        expected_hash = record.get("derived_sha256")
        actual_hash = hashlib.sha256(derived_path.read_bytes()).hexdigest().upper()
        if not isinstance(expected_hash, str) or actual_hash != expected_hash.upper():
            raise ValueError(f"MITRE derived hash mismatch: {relative_path}")
        verified.append(
            {
                "path": f"data/mitre/{relative_path}",
                "record_count": count,
                "verified_sha256": actual_hash,
            }
        )
    return verified
