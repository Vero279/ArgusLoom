import json
from pathlib import Path

import pytest

from argusloom.cti.snapshots import (
    require_experiment_ready_manifest,
    verify_snapshot_manifest,
)

ROOT = Path(__file__).resolve().parents[2]


def test_committed_cti_snapshot_hashes_verify() -> None:
    verified = verify_snapshot_manifest(ROOT, "data/cti_snapshot_manifest.json")

    required = {
        "data/fixtures/cves.json",
        "data/mitre/attack.json",
        "data/mitre/atlas.json",
        "data/nvd/CVE-2018-16603.json",
        "data/nvd/snapshots/v3/cve/cve_ids-3db1efccae05-page-0000.json",
    }
    assert required <= {item["path"] for item in verified}
    assert all(item["verified_sha256"] == item["sha256"].upper() for item in verified)


def test_snapshot_manifest_blocks_unverified_fixtures_from_experiments() -> None:
    with pytest.raises(ValueError, match="not experiment-ready"):
        require_experiment_ready_manifest(ROOT / "data/cti_snapshot_manifest.json")


def test_nvd_snapshot_does_not_claim_database_applicability() -> None:
    raw_snapshot = json.loads(
        (ROOT / "data/nvd/CVE-2018-16603.json").read_text(encoding="utf-8")
    )
    cve = raw_snapshot["vulnerabilities"][0]["cve"]
    description = next(
        item["value"] for item in cve["descriptions"] if item["lang"] == "en"
    )

    assert cve["id"] == "CVE-2018-16603"
    assert "FreeRTOS" in description
    assert "aws_db_instance" not in description
