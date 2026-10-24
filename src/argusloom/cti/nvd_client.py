"""NVD CVE clients with a persistent SQLite cache and offline fixture mode."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import httpx

from argusloom.domain.errors import CTIError

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(slots=True)
class CVE:
    id: str
    description: str
    cvss_score: float
    severity: str
    published: str
    source: str = "nvd"


class NVDClient(Protocol):
    def fetch_cves_for_keyword(self, keyword: str, limit: int = 20) -> list[CVE]: ...


class RealNVDClient:
    """HTTP client for the NVD CVE API with a keyword-based SQLite cache."""

    def __init__(
        self,
        cache_path: Path,
        api_key: str = "",
        timeout: int = 10,
        ttl_days: int = 7,
    ) -> None:
        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key
        self.timeout = timeout
        self.ttl_days = ttl_days
        self._last_request_at: float | None = None
        with sqlite3.connect(self.cache_path) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS cves (
                    keyword TEXT NOT NULL,
                    id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    fetched_at TIMESTAMP NOT NULL,
                    PRIMARY KEY(keyword, id)
                )""")

    @staticmethod
    def _parse_response(payload: dict[str, Any]) -> list[CVE]:
        results: list[CVE] = []
        for vulnerability in payload.get("vulnerabilities", []):
            cve_data = vulnerability.get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (
                    item.get("value", "")
                    for item in descriptions
                    if item.get("lang") == "en"
                ),
                descriptions[0].get("value", "") if descriptions else "",
            )
            metrics = cve_data.get("metrics", {})
            metric_items = metrics.get("cvssMetricV31") or metrics.get(
                "cvssMetricV2", []
            )
            metric_data = metric_items[0].get("cvssData", {}) if metric_items else {}
            score = float(metric_data.get("baseScore", 0.0))
            severity = str(
                metric_data.get("baseSeverity")
                or (metric_items[0].get("baseSeverity") if metric_items else "")
                or _severity_for_score(score)
            )
            results.append(
                CVE(
                    id=str(cve_data.get("id", "")),
                    description=str(description),
                    cvss_score=score,
                    severity=severity,
                    published=str(cve_data.get("published", "")),
                )
            )
        return results

    def _read_cache(self, keyword: str, limit: int) -> list[CVE]:
        cutoff = (datetime.now(UTC) - timedelta(days=self.ttl_days)).isoformat()
        with sqlite3.connect(self.cache_path) as connection:
            rows = connection.execute(
                "SELECT payload FROM cves WHERE keyword = ? AND fetched_at > ? "
                "ORDER BY id LIMIT ?",
                (keyword, cutoff, limit),
            ).fetchall()
        return [CVE(**json.loads(row[0])) for row in rows]

    def _write_cache(self, keyword: str, cves: list[CVE]) -> None:
        fetched_at = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.cache_path) as connection:
            connection.executemany(
                """INSERT INTO cves(keyword, id, payload, fetched_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(keyword, id) DO UPDATE SET
                       payload = excluded.payload,
                       fetched_at = excluded.fetched_at""",
                [
                    (keyword, cve.id, json.dumps(asdict(cve)), fetched_at)
                    for cve in cves
                ],
            )

    def _wait_for_rate_limit(self) -> None:
        if self.api_key or self._last_request_at is None:
            return
        remaining = 6.0 - (time.monotonic() - self._last_request_at)
        if remaining > 0:
            time.sleep(remaining)

    def fetch_cves_for_keyword(self, keyword: str, limit: int = 20) -> list[CVE]:
        cached = self._read_cache(keyword, limit)
        if cached:
            return cached

        self._wait_for_rate_limit()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        self._last_request_at = time.monotonic()
        try:
            response = httpx.get(
                NVD_API_URL,
                params={"keywordSearch": keyword, "resultsPerPage": limit},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            cves = self._parse_response(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise CTIError(
                f"NVD request failed for keyword '{keyword}': {exc}"
            ) from exc

        if cves:
            self._write_cache(keyword, cves)
        return cves[:limit]


class MockNVDClient:
    """Deterministic offline NVD client backed by a JSON fixture file."""

    def __init__(self, fixtures_path: Path) -> None:
        self.fixtures_path = Path(fixtures_path)
        payload = json.loads(self.fixtures_path.read_text(encoding="utf-8"))
        self._cves = [
            CVE(
                id=str(item["id"]),
                description=str(item["description"]),
                cvss_score=float(item["cvss_score"]),
                severity=str(item["severity"]),
                published=str(item.get("published", "")),
                source="nvd",
            )
            for item in payload
        ]

    def fetch_cves_for_keyword(self, keyword: str, limit: int = 20) -> list[CVE]:
        tokens = re.findall(r"[a-z0-9]+", keyword.casefold())
        matched = [
            cve
            for cve in self._cves
            if any(
                token in re.findall(r"[a-z0-9]+", cve.description.casefold())
                for token in tokens
            )
        ]
        return matched[:limit]


def _severity_for_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"
