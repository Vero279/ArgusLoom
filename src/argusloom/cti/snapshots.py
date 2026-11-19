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
            raise FileNotFoundError(f"CTI snapshot not found: {relative_path}")
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
