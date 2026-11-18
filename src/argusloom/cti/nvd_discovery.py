"""Local, rate-limited NVD API discovery and immutable snapshot persistence."""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from argusloom.cti.cpe_matcher import CPEName, cpe_name_for_version, parse_cpe23_name

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
MAX_CVE_PAGE_SIZE = 2000
MAX_CPE_PAGE_SIZE = 10000
MAX_CVE_IDS_PER_REQUEST = 100
RATE_WINDOW_SECONDS = 30.0
PUBLIC_REQUESTS_PER_WINDOW = 5
KEYED_REQUESTS_PER_WINDOW = 50


@dataclass(frozen=True, slots=True)
class NVDPage:
    start_index: int
    total_results: int
    results_per_page: int
    payload: dict[str, Any]
    raw: bytes


@dataclass(frozen=True, slots=True)
class NVDQueryResult:
    mode: str
    query: dict[str, str]
    endpoint: str
    pages: tuple[NVDPage, ...]


class NVDAPIClient:
    def __init__(
        self,
        *,
        api_key: str = "",
        timeout_seconds: int = 30,
        request_get: Callable[..., Any] = httpx.get,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        min_interval_seconds: float | None = None,
        max_retries: int = 5,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        if min_interval_seconds is None:
            min_interval_seconds = 0.6 if api_key else 6.0
        if min_interval_seconds < 0:
            raise ValueError("min_interval_seconds must be non-negative")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.request_get = request_get
        self.sleep = sleep
        self.monotonic = monotonic
        self.min_interval_seconds = min_interval_seconds
        self.max_retries = max_retries
        self._request_times: deque[float] = deque()
        self._last_request_at: float | None = None

    def fetch_cves_by_ids(self, cve_ids: list[str]) -> list[NVDQueryResult]:
        normalized = [value.strip().upper() for value in cve_ids if value.strip()]
        if not normalized:
            raise ValueError("at least one CVE ID is required")
        if len(set(normalized)) != len(normalized):
            raise ValueError("CVE ID list must not contain duplicates")
        results: list[NVDQueryResult] = []
        for offset in range(0, len(normalized), MAX_CVE_IDS_PER_REQUEST):
            batch = normalized[offset : offset + MAX_CVE_IDS_PER_REQUEST]
            results.append(
                self._fetch_pages(
                    endpoint=NVD_CVE_API,
                    mode="cve_ids",
                    query={"cveIds": ",".join(batch)},
                    page_size=MAX_CVE_PAGE_SIZE,
                    response_key="vulnerabilities",
                )
            )
        return results

    def fetch_cves_by_cpe(self, cpe_names: list[str]) -> list[NVDQueryResult]:
        if not cpe_names:
            raise ValueError("at least one exact CPE 2.3 name is required")
        if len(set(cpe_names)) != len(cpe_names):
            raise ValueError("CPE name list must not contain duplicates")
        results: list[NVDQueryResult] = []
        for cpe_name in cpe_names:
            parsed = parse_cpe23_name(cpe_name)
            if any(
                component in {"*", "-"}
                for component in (
                    parsed.part,
                    parsed.vendor,
                    parsed.product,
                    parsed.version,
                )
            ):
                raise ValueError(
                    "cpeName requires explicit part, vendor, product, and version"
                )
            results.append(
                self._fetch_pages(
                    endpoint=NVD_CVE_API,
                    mode="cpe_name",
                    query={"cpeName": cpe_name},
                    page_size=MAX_CVE_PAGE_SIZE,
                    response_key="vulnerabilities",
                )
            )
        return results

    def discover_cpe_products(self, keyword: str) -> NVDQueryResult:
        term = keyword.strip()
        if not term:
            raise ValueError("CPE dictionary search keyword must not be empty")
        return self._fetch_pages(
            endpoint=NVD_CPE_API,
            mode="cpe_dictionary_keyword",
            query={"keywordSearch": term},
            page_size=MAX_CPE_PAGE_SIZE,
            response_key="products",
        )

    def _wait_for_request_slot(self) -> None:
        request_limit = (
            KEYED_REQUESTS_PER_WINDOW if self.api_key else PUBLIC_REQUESTS_PER_WINDOW
        )
        while True:
            now = self.monotonic()
            while self._request_times and (
                now - self._request_times[0] >= RATE_WINDOW_SECONDS
            ):
                self._request_times.popleft()
            delay = 0.0
            if len(self._request_times) >= request_limit:
                delay = max(
                    delay,
                    RATE_WINDOW_SECONDS - (now - self._request_times[0]),
                )
            if self._last_request_at is not None:
                delay = max(
                    delay,
                    self.min_interval_seconds - (now - self._last_request_at),
                )
            if delay <= 0:
                break
            self.sleep(delay)
        request_at = self.monotonic()
        self._request_times.append(request_at)
        self._last_request_at = request_at

    def _retry_delay(self, response: Any, retry_number: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                try:
                    retry_date = parsedate_to_datetime(retry_after)
                    if retry_date.tzinfo is None:
                        retry_date = retry_date.replace(tzinfo=UTC)
                    return max(
                        0.0,
                        (retry_date - datetime.now(UTC)).total_seconds(),
                    )
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(2.0**retry_number, 60.0)

    def _get_json(
        self, endpoint: str, params: dict[str, Any]
    ) -> tuple[dict[str, Any], bytes]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for retry_number in range(self.max_retries + 1):
            self._wait_for_request_slot()
            response = self.request_get(
                endpoint,
                params=params,
                headers=headers,
                timeout=self.timeout_seconds,
            )
            if response.status_code in {403, 429}:
                if retry_number >= self.max_retries:
                    response.raise_for_status()
                    raise RuntimeError(
                        f"NVD throttled request with HTTP {response.status_code}"
                    )
                self.sleep(self._retry_delay(response, retry_number))
                continue
            response.raise_for_status()
            try:
                payload = response.json()
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError("NVD returned a non-JSON response") from exc
            if not isinstance(payload, dict):
                raise TypeError("NVD response must be a JSON object")
            return payload, bytes(response.content)
        raise RuntimeError("NVD retry loop ended unexpectedly")

    def _fetch_pages(
        self,
        *,
        endpoint: str,
        mode: str,
        query: dict[str, str],
        page_size: int,
        response_key: str,
    ) -> NVDQueryResult:
        pages: list[NVDPage] = []
        start_index = 0
        while True:
            params: dict[str, Any] = {
                **query,
                "resultsPerPage": page_size,
                "startIndex": start_index,
            }
            payload, raw = self._get_json(endpoint, params)
            total_results = payload.get("totalResults")
            page_start = payload.get("startIndex")
            page_limit = payload.get("resultsPerPage")
            if not all(
                isinstance(value, int) and value >= 0
                for value in (total_results, page_start, page_limit)
            ):
                raise ValueError("NVD response has invalid pagination metadata")
            if response_key not in payload or not isinstance(
                payload[response_key], list
            ):
                raise TypeError(f"NVD response is missing its {response_key} list")
            pages.append(
                NVDPage(
                    start_index=page_start,
                    total_results=total_results,
                    results_per_page=page_limit,
                    payload=payload,
                    raw=raw,
                )
            )
            next_index = page_start + page_limit
            if next_index >= total_results:
                break
            if next_index <= start_index:
                raise ValueError("NVD pagination made no forward progress")
            start_index = next_index
        return NVDQueryResult(mode, query, endpoint, tuple(pages))


def _query_key(result: NVDQueryResult) -> str:
    payload = {"mode": result.mode, "query": result.query}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _manifest_path(root: Path, manifest_file: Path) -> Path:
    return manifest_file if manifest_file.is_absolute() else root / manifest_file


def persist_discovery(
    result: NVDQueryResult,
    repository_root: str | Path,
    manifest_path: str | Path,
    *,
    refetch: bool = False,
    new_manifest_version: int | None = None,
) -> list[dict[str, Any]]:
    root = Path(repository_root).resolve()
    manifest_file = _manifest_path(root, Path(manifest_path))
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    current_version = manifest.get("manifest_version")
    if not isinstance(current_version, int) or current_version < 1:
        raise ValueError("manifest_version must be a positive integer")
    key = _query_key(result)
    existing = [
        item
        for item in manifest.get("snapshots", [])
        if isinstance(item, dict) and item.get("query_key") == key
    ]
    if result.mode == "cve_ids":
        requested_ids = set(result.query["cveIds"].split(","))
        for item in manifest.get("snapshots", []):
            if (
                not isinstance(item, dict)
                or item.get("format") != "raw-nvd-api-2.0"
                or item.get("query_key")
            ):
                continue
            source = item.get("source")
            if not isinstance(source, str):
                continue
            legacy_query = parse_qs(urlparse(source).query)
            legacy_ids = set()
            for parameter in ("cveIds", "cveId"):
                legacy_ids.update(
                    identifier.upper()
                    for value in legacy_query.get(parameter, [])
                    for identifier in value.split(",")
                )
            if requested_ids.intersection(legacy_ids):
                existing.append(item)
    if existing and not refetch:
        raise ValueError(
            "this query snapshot is already frozen; re-fetch requires "
            "--refetch and a new manifest version"
        )
    if refetch:
        if not existing:
            raise ValueError(
                "re-fetch is only valid for a previously snapshotted query"
            )
        previous_versions = []
        for item in existing:
            snapshot_version = item.get("manifest_version", 1)
            if not isinstance(snapshot_version, int) or snapshot_version < 1:
                raise ValueError("snapshot manifest entries need a positive version")
            previous_versions.append(snapshot_version)
        if (
            not isinstance(new_manifest_version, int)
            or new_manifest_version < current_version
            or new_manifest_version <= max(previous_versions)
        ):
            raise ValueError("re-fetch requires a new manifest version")
        version = new_manifest_version
    else:
        if new_manifest_version is not None:
            raise ValueError("--manifest-version is only valid with --refetch")
        version = current_version

    query_hash = key[:12]
    relative_directory = Path("data/nvd/snapshots") / f"v{version}"
    if result.mode == "cpe_dictionary_keyword":
        relative_directory /= "cpe"
        format_name = "nvd-cpe-api-2.0"
        collection_type = "nvd-cpe-api"
    else:
        relative_directory /= "cve"
        format_name = "raw-nvd-api-2.0"
        collection_type = "nvd-cve-api"
    saved: list[dict[str, Any]] = []
    for page_number, page in enumerate(result.pages):
        relative_path = (
            relative_directory
            / f"{result.mode}-{query_hash}-page-{page_number:04d}.json"
        )
        target = root / relative_path
        if target.exists():
            raise FileExistsError(
                f"snapshot file already exists and is frozen: {relative_path}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(page.raw)
        entry = {
            "path": str(relative_path).replace("\\", "/"),
            "source": f"{result.endpoint}?{urlencode(result.query)}",
            "format": format_name,
            "sha256": hashlib.sha256(page.raw).hexdigest().upper(),
            "collection_type": collection_type,
            "query_mode": result.mode,
            "query": result.query,
            "query_key": key,
            "manifest_version": version,
            "page_start_index": page.start_index,
            "total_results": page.total_results,
            "results_per_page": page.results_per_page,
            "experiment_eligible": False,
        }
        saved.append(entry)
    manifest["manifest_version"] = version
    manifest["status"] = "incomplete"
    manifest.setdefault("snapshots", []).extend(saved)
    temporary = manifest_file.with_suffix(manifest_file.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(manifest_file)
    return saved


def persist_cpe_product_candidates(
    result: NVDQueryResult,
    snapshot_entries: list[dict[str, Any]],
    mapping_path: str | Path,
    candidate_versions_path: str | Path,
    cpe_name_output: str | Path,
) -> list[dict[str, Any]]:
    if result.mode != "cpe_dictionary_keyword":
        raise ValueError("CPE product candidates require a CPE dictionary query")
    mapping_file = Path(mapping_path)
    mapping_payload: dict[str, Any] = {
        "schema_version": 1,
        "status": "pending_user_verification",
        "entries": [],
    }
    if mapping_file.exists():
        loaded = json.loads(mapping_file.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict) or not isinstance(loaded.get("entries"), list):
            raise ValueError("CPE product mapping table has an invalid shape")
        mapping_payload = loaded

    page_by_start = {entry["page_start_index"]: entry for entry in snapshot_entries}
    existing_keys = {
        (
            item.get("software_key"),
            item.get("part"),
            item.get("vendor"),
            item.get("product"),
        )
        for item in mapping_payload["entries"]
        if isinstance(item, dict)
    }
    candidates: list[dict[str, Any]] = []
    for page in result.pages:
        source_entry = page_by_start[page.start_index]
        for record in page.payload.get("products", []):
            cpe_record = record.get("cpe") if isinstance(record, dict) else None
            cpe_value = (
                cpe_record.get("cpeName") if isinstance(cpe_record, dict) else None
            )
            if not isinstance(cpe_value, str):
                continue
            cpe = parse_cpe23_name(cpe_value)
            title = ""
            titles = cpe_record.get("titles", [])
            if isinstance(titles, list):
                title = next(
                    (
                        str(item.get("title", ""))
                        for item in titles
                        if isinstance(item, dict) and item.get("lang") == "en"
                    ),
                    "",
                )
            entry = {
                "software_key": result.query["keywordSearch"].casefold(),
                "part": cpe.part,
                "vendor": cpe.vendor,
                "product": cpe.product,
                "verification_status": "pending",
                "source_snapshot": source_entry["path"],
                "source_sha256": source_entry["sha256"],
                "source_query": result.query,
                "source_cpe_name": cpe_value,
                "title": title,
            }
            key = (
                entry["software_key"],
                entry["part"],
                entry["vendor"],
                entry["product"],
            )
            if key in existing_keys:
                continue
            existing_keys.add(key)
            candidates.append(entry)
    mapping_payload["status"] = (
        "pending_user_verification"
        if any(
            item.get("verification_status") != "verified"
            for item in mapping_payload["entries"] + candidates
            if isinstance(item, dict)
        )
        else mapping_payload.get("status", "verified")
    )
    mapping_payload["entries"].extend(candidates)
    mapping_file.parent.mkdir(parents=True, exist_ok=True)
    mapping_file.write_text(
        json.dumps(mapping_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    versions_payload = json.loads(
        Path(candidate_versions_path).read_text(encoding="utf-8")
    )
    candidate_versions = versions_payload.get("candidates", {}).get(
        result.query["keywordSearch"].casefold(), []
    )
    cpe_names: set[str] = set()
    for item in mapping_payload["entries"]:
        if (
            not isinstance(item, dict)
            or item.get("software_key") != result.query["keywordSearch"].casefold()
        ):
            continue
        base = CPEName(
            part=item["part"],
            vendor=item["vendor"],
            product=item["product"],
            version="*",
            components=(
                item["part"],
                item["vendor"],
                item["product"],
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
            ),
        )
        for version in candidate_versions:
            cpe_names.add(cpe_name_for_version(base, version))
    output_file = Path(cpe_name_output)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        "".join(f"{name}\n" for name in sorted(cpe_names)),
        encoding="utf-8",
    )
    return candidates
