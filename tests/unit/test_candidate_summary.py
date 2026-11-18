import hashlib
import json
from pathlib import Path

from argusloom.cti.candidate_summary import summarize_candidate_versions


def _write_snapshot(root: Path, relative_path: str, payload: dict) -> str:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    target.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest().upper()


def test_candidate_summary_uses_verified_exact_cpe_snapshots(tmp_path: Path) -> None:
    dictionary_path = "data/nvd/snapshots/v1/cpe/nginx.json"
    dictionary_cpe = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    dictionary_hash = _write_snapshot(
        tmp_path,
        dictionary_path,
        {
            "products": [
                {
                    "cpe": {
                        "cpeName": dictionary_cpe,
                        "titles": [{"lang": "en", "title": "nginx"}],
                    }
                }
            ]
        },
    )
    exact_name = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    cve = {
        "id": "CVE-2021-12345",
        "published": "2021-06-01T00:00:00.000",
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": dictionary_cpe,
                                "versionStartIncluding": "1.20.0",
                                "versionEndExcluding": "1.25.0",
                            }
                        ],
                    }
                ]
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
    }
    query_path = "data/nvd/snapshots/v1/cve/nginx-124.json"
    query_hash = _write_snapshot(
        tmp_path,
        query_path,
        {
            "totalResults": 1,
            "startIndex": 0,
            "resultsPerPage": 2000,
            "vulnerabilities": [{"cve": cve}],
        },
    )
    manifest = {
        "manifest_version": 1,
        "status": "incomplete",
        "snapshots": [
            {
                "path": dictionary_path,
                "format": "nvd-cpe-api-2.0",
                "sha256": dictionary_hash,
            },
            {
                "path": query_path,
                "format": "raw-nvd-api-2.0",
                "sha256": query_hash,
                "query_mode": "cpe_name",
                "query": {"cpeName": exact_name},
                "manifest_version": 1,
            },
        ],
    }
    manifest_path = tmp_path / "data" / "cti_snapshot_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    mapping_path = tmp_path / "data" / "cpe_product_mappings.json"
    mapping_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "pending_user_verification",
                "entries": [
                    {
                        "software_key": "nginx",
                        "part": "a",
                        "vendor": "nginx",
                        "product": "nginx",
                        "verification_status": "pending",
                        "source_snapshot": dictionary_path,
                        "source_sha256": dictionary_hash,
                        "source_cpe_name": dictionary_cpe,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    versions_path = tmp_path / "data" / "cpe_version_candidates.json"
    versions_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "candidates": {"nginx": ["1.24.0", "1.26.0"]},
            }
        ),
        encoding="utf-8",
    )

    rows = summarize_candidate_versions(
        tmp_path,
        manifest_path,
        mapping_path,
        versions_path,
    )

    fetched = next(row for row in rows if row["version"] == "1.24.0")
    not_fetched = next(row for row in rows if row["version"] == "1.26.0")
    assert fetched["total_cves"] == 1
    assert fetched["cvss_v3x_cves"] == 1
    assert fetched["severity_distribution"]["HIGH"] == 1
    assert fetched["publication_year_range"] == "2021-2021"
    assert fetched["status"] == "FETCHED_PENDING_MAPPING_VERIFICATION"
    assert not_fetched["status"] == "NOT_FETCHED"
