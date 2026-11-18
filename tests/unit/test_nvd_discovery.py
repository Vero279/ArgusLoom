import json
from pathlib import Path

import pytest

from argusloom.cti.nvd_discovery import (
    NVDAPIClient,
    persist_cpe_product_candidates,
    persist_discovery,
)


class FakeResponse:
    def __init__(
        self,
        payload: dict,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.content = json.dumps(payload).encode("utf-8")

    def json(self) -> dict:
        return json.loads(self.content)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_cve_id_and_cpe_name_queries_use_separate_parameters() -> None:
    requests: list[tuple[str, dict, dict]] = []

    def request(url: str, *, params: dict, headers: dict, timeout: int):
        requests.append((url, params, headers))
        return FakeResponse(
            {
                "totalResults": 0,
                "startIndex": 0,
                "resultsPerPage": 2000,
                "vulnerabilities": [],
            }
        )

    client = NVDAPIClient(
        request_get=request,
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    )
    client.fetch_cves_by_ids(["CVE-2025-1234"])
    client.fetch_cves_by_cpe(["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"])

    assert "cveIds" in requests[0][1]
    assert "cpeName" not in requests[0][1]
    assert "cpeName" in requests[1][1]
    assert "cveIds" not in requests[1][1]
    assert requests[0][1]["resultsPerPage"] == 2000
    assert requests[1][1]["resultsPerPage"] == 2000


def test_cve_query_paginates_to_the_official_maximum() -> None:
    requests: list[dict] = []

    def request(_url: str, *, params: dict, headers: dict, timeout: int):
        requests.append(params)
        if params["startIndex"] == 0:
            return FakeResponse(
                {
                    "totalResults": 2001,
                    "startIndex": 0,
                    "resultsPerPage": 2000,
                    "vulnerabilities": [],
                }
            )
        return FakeResponse(
            {
                "totalResults": 2001,
                "startIndex": 2000,
                "resultsPerPage": 2000,
                "vulnerabilities": [],
            }
        )

    client = NVDAPIClient(
        request_get=request,
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    )
    result = client.fetch_cves_by_cpe(["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"])

    assert len(result[0].pages) == 2
    assert [item["startIndex"] for item in requests] == [0, 2000]


def test_cpe_dictionary_discovery_uses_10000_page_limit() -> None:
    requests: list[tuple[str, dict]] = []

    def request(url: str, *, params: dict, headers: dict, timeout: int):
        requests.append((url, params))
        return FakeResponse(
            {
                "totalResults": 0,
                "startIndex": 0,
                "resultsPerPage": 10000,
                "products": [],
            }
        )

    client = NVDAPIClient(
        request_get=request,
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    )
    client.discover_cpe_products("nginx")

    assert "/cpes/2.0" in requests[0][0]
    assert requests[0][1]["keywordSearch"] == "nginx"
    assert requests[0][1]["resultsPerPage"] == 10000


def test_throttling_retries_honor_retry_after() -> None:
    responses = [
        FakeResponse({}, status_code=429, headers={"Retry-After": "7"}),
        FakeResponse(
            {
                "totalResults": 0,
                "startIndex": 0,
                "resultsPerPage": 2000,
                "vulnerabilities": [],
            }
        ),
    ]
    delays: list[float] = []

    def request(_url: str, *, params: dict, headers: dict, timeout: int):
        return responses.pop(0)

    client = NVDAPIClient(
        request_get=request,
        sleep=delays.append,
        min_interval_seconds=0,
    )
    client.fetch_cves_by_ids(["CVE-2025-1234"])

    assert 7.0 in delays


def test_missing_nvd_result_list_is_not_treated_as_an_empty_result() -> None:
    client = NVDAPIClient(
        request_get=lambda *_args, **_kwargs: FakeResponse(
            {"totalResults": 0, "startIndex": 0, "resultsPerPage": 2000}
        ),
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    )

    with pytest.raises(TypeError, match="vulnerabilities list"):
        client.fetch_cves_by_ids(["CVE-2025-1234"])


def test_snapshot_requery_requires_new_manifest_version(tmp_path: Path) -> None:
    result = NVDAPIClient(
        request_get=lambda *_args, **_kwargs: FakeResponse(
            {
                "totalResults": 1,
                "startIndex": 0,
                "resultsPerPage": 2000,
                "vulnerabilities": [{"cve": {"id": "CVE-2025-1234"}}],
            }
        ),
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    ).fetch_cves_by_ids(["CVE-2025-1234"])[0]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"manifest_version": 1, "status": "incomplete", "snapshots": []}),
        encoding="utf-8",
    )

    persist_discovery(result, tmp_path, manifest_path)
    with pytest.raises(ValueError, match="already frozen"):
        persist_discovery(result, tmp_path, manifest_path)
    with pytest.raises(ValueError, match="new manifest version"):
        persist_discovery(
            result,
            tmp_path,
            manifest_path,
            refetch=True,
            new_manifest_version=1,
        )


def test_refetch_writes_a_new_manifest_version(tmp_path: Path) -> None:
    result = NVDAPIClient(
        request_get=lambda *_args, **_kwargs: FakeResponse(
            {
                "totalResults": 0,
                "startIndex": 0,
                "resultsPerPage": 2000,
                "vulnerabilities": [],
            }
        ),
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    ).fetch_cves_by_ids(["CVE-2025-1234"])[0]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"manifest_version": 1, "status": "incomplete", "snapshots": []}),
        encoding="utf-8",
    )

    first = persist_discovery(result, tmp_path, manifest_path)
    second = persist_discovery(
        result,
        tmp_path,
        manifest_path,
        refetch=True,
        new_manifest_version=2,
    )

    assert first[0]["manifest_version"] == 1
    assert second[0]["manifest_version"] == 2
    assert first[0]["path"] != second[0]["path"]


def test_multiple_snapshots_can_be_refetched_into_one_new_manifest_version(
    tmp_path: Path,
) -> None:
    client = NVDAPIClient(
        request_get=lambda *_args, **_kwargs: FakeResponse(
            {
                "totalResults": 0,
                "startIndex": 0,
                "resultsPerPage": 2000,
                "vulnerabilities": [],
            }
        ),
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    )
    results = [
        client.fetch_cves_by_ids([f"CVE-2025-{number:04d}"])[0]
        for number in (1234, 1235)
    ]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"manifest_version": 1, "status": "incomplete", "snapshots": []}),
        encoding="utf-8",
    )

    for result in results:
        persist_discovery(result, tmp_path, manifest_path)
    refreshed = [
        persist_discovery(
            result,
            tmp_path,
            manifest_path,
            refetch=True,
            new_manifest_version=2,
        )
        for result in results
    ]

    assert all(entries[0]["manifest_version"] == 2 for entries in refreshed)


def test_exact_cpe_query_rejects_wildcard_version() -> None:
    client = NVDAPIClient(
        request_get=lambda *_args, **_kwargs: pytest.fail("unexpected request"),
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    )

    with pytest.raises(ValueError, match="explicit"):
        client.fetch_cves_by_cpe(["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"])


@pytest.mark.parametrize(
    ("api_key", "limit"),
    [("", 5), ("test-key", 50)],
)
def test_request_window_limit_is_selected_by_api_key(
    api_key: str,
    limit: int,
) -> None:
    now = [0.0]
    request_times: list[float] = []
    request_headers: list[dict[str, str]] = []

    def sleep(delay: float) -> None:
        now[0] += delay

    def request(_url: str, *, params: dict, headers: dict, timeout: int):
        request_times.append(now[0])
        request_headers.append(headers)
        return FakeResponse(
            {
                "totalResults": 0,
                "startIndex": 0,
                "resultsPerPage": 2000,
                "vulnerabilities": [],
            }
        )

    client = NVDAPIClient(
        api_key=api_key,
        request_get=request,
        sleep=sleep,
        monotonic=lambda: now[0],
        min_interval_seconds=0,
    )
    ids = [f"CVE-2025-{index:04d}" for index in range(1, limit + 2)]
    for cve_id in ids:
        client.fetch_cves_by_ids([cve_id])

    assert sum(request_time < 30 for request_time in request_times) == limit
    if api_key:
        assert all(header.get("apiKey") == api_key for header in request_headers)
    else:
        assert all("apiKey" not in header for header in request_headers)


def test_cpe_dictionary_candidates_are_source_linked_and_pending(
    tmp_path: Path,
) -> None:
    products = [
        {
            "cpe": {
                "cpeName": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                "titles": [{"lang": "en", "title": "nginx"}],
            }
        },
        {
            "cpe": {
                "cpeName": "cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*",
                "titles": [{"lang": "en", "title": "NGINX Plus"}],
            }
        },
    ]
    result = NVDAPIClient(
        request_get=lambda *_args, **_kwargs: FakeResponse(
            {
                "totalResults": len(products),
                "startIndex": 0,
                "resultsPerPage": 10000,
                "products": products,
            }
        ),
        sleep=lambda _delay: None,
        min_interval_seconds=0,
    ).discover_cpe_products("nginx")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"manifest_version": 1, "status": "incomplete", "snapshots": []}),
        encoding="utf-8",
    )
    snapshots = persist_discovery(result, tmp_path, manifest_path)
    versions_path = tmp_path / "versions.json"
    versions_path.write_text(
        json.dumps({"candidates": {"nginx": ["1.22.1", "1.24.0", "1.26.0"]}}),
        encoding="utf-8",
    )
    mappings_path = tmp_path / "mappings.json"
    cpe_names_path = tmp_path / "candidate_cpes.txt"

    candidates = persist_cpe_product_candidates(
        result,
        snapshots,
        mappings_path,
        versions_path,
        cpe_names_path,
    )

    assert {(item["vendor"], item["product"]) for item in candidates} == {
        ("nginx", "nginx"),
        ("f5", "nginx_plus"),
    }
    assert all(item["verification_status"] == "pending" for item in candidates)
    assert all(item["source_sha256"] == snapshots[0]["sha256"] for item in candidates)
    assert len(cpe_names_path.read_text(encoding="utf-8").splitlines()) == 6
