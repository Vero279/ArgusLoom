"""Derive the experiment MITRE subsets from verified official source bundles."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_DIR = ROOT / "data" / "mitre" / "official"
OUTPUT_DIR = ROOT / "data" / "mitre"
ATTACK_SOURCE = OFFICIAL_DIR / "enterprise-attack-20.1.json"
ATLAS_SOURCE = OFFICIAL_DIR / "ATLAS-2026.10.yaml"
ATTACK_HASH = "539A843A7B53ED9749740B2123DDDAE3726B1A4831841C32ACA740B011B910B5"
ATLAS_HASH = "AC41EE9F99A47084BA5FDFC77AE83A28687E12390240FFFEB37DF7914FFE142D"

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-20.1.json"
)
ATLAS_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/"
    "ATLAS-2026.10.yaml"
)

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def verify_source(path: Path, expected: str) -> None:
    if not path.is_file():
        raise SystemExit(
            f"Missing official MITRE data; run scripts/fetch_mitre_official.py "
            f"locally. Missing source: {path.relative_to(ROOT)}"
        )
    actual = sha256(path)
    if actual != expected:
        raise SystemExit(
            f"Hash mismatch for {path.relative_to(ROOT)}: expected {expected}, got {actual}"
        )


def external_id(item: dict[str, Any]) -> str | None:
    for reference in item.get("external_references", []):
        if isinstance(reference, dict) and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def tactic_names(item: dict[str, Any]) -> list[str]:
    values = []
    for phase in item.get("kill_chain_phases", []):
        if not isinstance(phase, dict):
            continue
        slug = str(phase.get("phase_name", "")).strip()
        if slug:
            value = TACTIC_NAMES.get(slug, slug.replace("-", " ").title())
            if value not in values:
                values.append(value)
    return values


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    if b"\r" in payload:
        raise RuntimeError("LF-only output invariant violated")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def write_json(path: Path, records: list[dict[str, Any]]) -> str:
    payload = json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload)
    return hashlib.sha256(payload).hexdigest().upper()


def derive_attack() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    payload = json.loads(ATTACK_SOURCE.read_text(encoding="utf-8"))
    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise SystemExit("ATT&CK STIX bundle has no objects list")

    relationships = [item for item in objects if item.get("type") == "relationship"]
    revoked_by: dict[str, str] = {}
    for relationship in relationships:
        if relationship.get("relationship_type") == "revoked-by":
            revoked_by[str(relationship.get("source_ref", ""))] = str(
                relationship.get("target_ref", "")
            )

    attack_objects = {
        item_id: item
        for item in objects
        if item.get("type") == "attack-pattern"
        for item_id in [external_id(item)]
        if item_id
    }
    replacement = []
    for old_id, target_ref in revoked_by.items():
        old_external = next(
            (eid for eid, item in attack_objects.items() if item.get("id") == old_id),
            None,
        )
        new_external = next(
            (eid for eid, item in attack_objects.items() if item.get("id") == target_ref),
            None,
        )
        if old_external == "T1562":
            if new_external == "T1685":
                replacement.append(
                    {
                        "from": "T1562",
                        "to": "T1685",
                        "relationship": "revoked-by",
                        "status": "resolved",
                        "note": "T1685 is narrower than T1562 and is not equivalent",
                    }
                )
            else:
                replacement.append(
                    {
                        "from": "T1562",
                        "to": new_external,
                        "relationship": "revoked-by",
                        "status": "unresolved",
                        "note": "Official replacement target is not T1685; T1562 was not substituted.",
                    }
                )
    if not any(record["from"] == "T1562" for record in replacement):
        replacement.append(
            {
                "from": "T1562",
                "to": None,
                "relationship": "revoked-by",
                "status": "unresolved",
                "note": "No T1562 revoked-by relationship was resolved; T1562 was not substituted.",
            }
        )

    explicit = {"T1565.001", "T1530", "T1195"}
    records = []
    for technique_id, item in sorted(attack_objects.items()):
        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        selected = "IaaS" in item.get("x_mitre_platforms", [])
        justification = None
        if technique_id in explicit:
            selected = True
            justification = {
                "T1565.001": "Explicitly added cloud-relevant data manipulation case.",
                "T1530": "Explicitly added for cloud storage data exposure.",
                "T1195": "Explicitly added supply-chain attack coverage.",
            }[technique_id]
        if not selected:
            continue
        record = {
            "id": technique_id,
            "name": str(item.get("name", "")),
            "tactic": ", ".join(tactic_names(item)),
            "description": str(item.get("description", "")),
        }
        if justification:
            record["justification"] = justification
        records.append(record)
    return records, replacement, []


def atlas_tactic(record: dict[str, Any]) -> str:
    for key in ("tactics", "tactic"):
        value = record.get(key)
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        if isinstance(value, str):
            return value
    return ""


def derive_atlas() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payload = yaml.safe_load(ATLAS_SOURCE.read_text(encoding="utf-8"))
    techniques = payload.get("techniques") if isinstance(payload, dict) else None
    if isinstance(techniques, dict):
        technique_items = list(techniques.items())
    elif isinstance(techniques, list):
        technique_items = [
            (str(item.get("id", item.get("external_id", ""))), item)
            for item in techniques
            if isinstance(item, dict)
        ]
    else:
        raise SystemExit("ATLAS YAML has no techniques dictionary or list")

    explicit = {"AML.T0064", "AML.T0066", "AML.T0070", "AML.T0071"}
    records = []
    for technique_id, item in sorted(technique_items, key=lambda pair: pair[0]):
        if not isinstance(item, dict):
            continue
        platforms = item.get("platforms", [])
        if isinstance(platforms, str):
            platforms = [platforms]
        selected = bool(set(platforms) & {"Generative AI", "Agentic AI"})
        justification = None
        if technique_id in explicit:
            selected = True
            justification = "Explicitly added by the Stage D ATLAS selection rule."
        if not selected:
            continue
        record = {
            "id": str(item.get("id", technique_id)),
            "name": str(item.get("name", "")),
            "tactic": atlas_tactic(item),
            "description": str(item.get("description", "")),
        }
        if justification:
            record["justification"] = justification
        records.append(record)
    return records, []


def main() -> int:
    verify_source(ATTACK_SOURCE, ATTACK_HASH)
    verify_source(ATLAS_SOURCE, ATLAS_HASH)

    attack, replacements, _attack_rejections = derive_attack()
    atlas, atlas_rejections = derive_atlas()
    if not attack:
        raise SystemExit("ATT&CK derivation produced zero records")
    if len({record["id"] for record in attack}) != len(attack):
        raise SystemExit("ATT&CK derivation contains duplicate IDs")
    if not (10 <= len(atlas) <= 150):
        raise SystemExit(
            f"ATLAS derivation count is outside the expected 10-150 range: {len(atlas)}"
        )
    if len({record["id"] for record in atlas}) != len(atlas):
        raise SystemExit("ATLAS derivation contains duplicate IDs")
    print(f"ATT&CK derived count: {len(attack)}")
    print(f"ATLAS derived count: {len(atlas)}")

    attack_hash = write_json(OUTPUT_DIR / "attack.json", attack)
    atlas_hash = write_json(OUTPUT_DIR / "atlas.json", atlas)
    metadata = {
        "attack.json": {
            "source_name": "Enterprise ATT&CK",
            "source_version": "20.1",
            "source_url": ATTACK_URL,
            "source_sha256": ATTACK_HASH,
            "selection_rules": [
                "Active techniques (not revoked and not deprecated) with x_mitre_platforms containing IaaS",
                "Explicit additions: T1565.001, T1530, T1195",
                "T1562 is replaced by the official revoked-by target; T1685 is narrower than T1562, not equivalent",
            ],
            "record_count": len(attack),
            "derived_sha256": attack_hash,
            "replacement_records": replacements,
            "rejected_documents": [],
        },
        "atlas.json": {
            "source_name": "MITRE ATLAS",
            "source_version": "2026.10",
            "source_url": ATLAS_URL,
            "source_sha256": ATLAS_HASH,
            "selection_rules": [
                "Techniques whose platforms include Generative AI or Agentic AI",
                "Explicit additions: AML.T0064, AML.T0066, AML.T0070, AML.T0071",
            ],
            "record_count": len(atlas),
            "derived_sha256": atlas_hash,
            "rejected_documents": atlas_rejections,
            "corpus_prompt_injection_policy": {
                "rule": "prompt-injection explicit-model-instruction rule",
                "description": "Reject only explicit instructions addressed to the model; topic descriptions are preserved.",
            },
        },
    }
    metadata_bytes = (
        json.dumps(
            metadata,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    atomic_write_bytes(OUTPUT_DIR / "derived_metadata.json", metadata_bytes)

    manifest_path = ROOT / "data" / "cti_snapshot_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for snapshot in manifest["snapshots"]:
        if snapshot.get("path") == "data/mitre/attack.json":
            snapshot["sha256"] = attack_hash
        if snapshot.get("path") == "data/mitre/atlas.json":
            snapshot["sha256"] = atlas_hash
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    atomic_write_bytes(manifest_path, manifest_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
