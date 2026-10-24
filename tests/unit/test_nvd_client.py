import json

import httpx
import pytest

from argusloom.cti.nvd_client import CVE, MockNVDClient, RealNVDClient
from argusloom.domain.errors import CTIError


def _write_fixture(tmp_path, records):
    fixture = tmp_path / "cves.json"
    fixture.write_text(json.dumps(records), encoding="utf-8")
    return fixture


def test_mock_nvd_client_matches_s3_keyword(tmp_path) -> None:
    client = MockNVDClient(
        _write_fixture(
            tmp_path,
            [
                {
                    "id": "CVE-2024-0001",
                    "description": "S3 bucket public access control issue",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                }
            ],
        )
    )

    assert client.fetch_cves_for_keyword("s3")[0].id == "CVE-2024-0001"


def test_mock_nvd_client_respects_limit(tmp_path) -> None:
    records = [
        {
            "id": f"CVE-2024-{index:04d}",
            "description": f"S3 bucket finding {index}",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
        }
        for index in range(3)
    ]
    client = MockNVDClient(_write_fixture(tmp_path, records))

    assert len(client.fetch_cves_for_keyword("s3", limit=2)) == 2


def test_mock_nvd_client_returns_empty_for_no_match(tmp_path) -> None:
    client = MockNVDClient(
        _write_fixture(
            tmp_path,
            [
                {
                    "id": "CVE-2024-0001",
                    "description": "S3 bucket access issue",
                    "cvss_score": 5.0,
                    "severity": "MEDIUM",
                }
            ],
        )
    )

    assert client.fetch_cves_for_keyword("unmatched") == []


def test_mock_nvd_client_uses_complete_keyword_tokens(tmp_path) -> None:
    client = MockNVDClient(
        _write_fixture(
            tmp_path,
            [
                {
                    "id": "CVE-2024-0001",
                    "description": "S3 bucket access issue",
                    "cvss_score": 5.0,
                    "severity": "MEDIUM",
                }
            ],
        )
    )

    assert client.fetch_cves_for_keyword("d") == []


def test_real_nvd_client_parse_response_extracts_v31_fields(tmp_path) -> None:
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-12345",
                    "published": "2023-05-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "fr", "value": "Texte français"},
                        {"lang": "en", "value": "English description"},
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
            }
        ]
    }

    parsed = RealNVDClient._parse_response(response)

    assert len(parsed) == 1
    assert parsed[0].id == "CVE-2023-12345"
    assert parsed[0].description == "English description"
    assert parsed[0].cvss_score == 8.1
    assert parsed[0].severity == "HIGH"
    assert parsed[0].published == "2023-05-01T00:00:00.000"


def test_real_nvd_client_returns_fresh_sqlite_cache_without_network(
    tmp_path, monkeypatch
) -> None:
    client = RealNVDClient(tmp_path / "cache.db")
    cached = CVE(
        id="CVE-2024-0001",
        description="S3 bucket access issue",
        cvss_score=7.5,
        severity="HIGH",
        published="2024-01-01",
    )
    client._write_cache("s3", [cached])

    def fail_if_called(*args, **kwargs):
        raise AssertionError("Fresh cache lookup must not issue a network request")

    monkeypatch.setattr("argusloom.cti.nvd_client.httpx.get", fail_if_called)

    assert client.fetch_cves_for_keyword("s3") == [cached]


def test_real_nvd_client_falls_back_to_cvss_v2() -> None:
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "descriptions": [{"lang": "en", "value": "Legacy CVE description"}],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "cvssData": {"baseScore": 6.5},
                                "baseSeverity": "MEDIUM",
                            }
                        ]
                    },
                }
            }
        ]
    }

    parsed = RealNVDClient._parse_response(response)

    assert parsed[0].cvss_score == 6.5
    assert parsed[0].severity == "MEDIUM"


def test_real_nvd_client_wraps_network_errors_as_cti_error(
    tmp_path, monkeypatch
) -> None:
    client = RealNVDClient(tmp_path / "cache.db")

    def fail_request(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr("argusloom.cti.nvd_client.httpx.get", fail_request)

    with pytest.raises(CTIError, match="NVD request failed"):
        client.fetch_cves_for_keyword("s3")
