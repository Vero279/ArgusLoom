"""Fetch the pinned official MITRE ATT&CK and ATLAS source bundles locally."""

from __future__ import annotations

import hashlib
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_DIR = ROOT / "data" / "mitre" / "official"
BRANCH_NOTICE = (
    "Both upstream URLs are branch URLs (ATT&CK uses master; ATLAS uses main), "
    "pinned only by SHA-256 for reproducibility. If upstream changed, use a "
    "verified local copy and do not overwrite it."
)
SOURCES = (
    (
        "enterprise-attack-20.1.json",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack-20.1.json",
        "539A843A7B53ED9749740B2123DDDAE3726B1A4831841C32ACA740B011B910B5",
    ),
    (
        "ATLAS-2026.10.yaml",
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/"
        "ATLAS-2026.10.yaml",
        "AC41EE9F99A47084BA5FDFC77AE83A28687E12390240FFFEB37DF7914FFE142D",
    ),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def fetch_one(filename: str, url: str, expected: str) -> None:
    destination = OFFICIAL_DIR / filename
    if destination.is_file():
        actual = sha256(destination)
        if actual != expected:
            raise SystemExit(
                f"Hash mismatch for {destination}: expected {expected}, got {actual}. "
                f"{BRANCH_NOTICE}"
            )
        print(f"Verified existing {destination.relative_to(ROOT)}")
        return

    OFFICIAL_DIR.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".download")
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            temp.write_bytes(response.read())
        actual = sha256(temp)
        if actual != expected:
            temp.unlink(missing_ok=True)
            raise SystemExit(
                f"Downloaded hash mismatch for {filename}: expected {expected}, "
                f"got {actual}. {BRANCH_NOTICE}"
            )
        temp.replace(destination)
        print(f"Downloaded and verified {destination.relative_to(ROOT)}")
    except (urllib.error.URLError, OSError) as exc:
        temp.unlink(missing_ok=True)
        raise SystemExit(f"Download failed for {filename}: {exc}. {BRANCH_NOTICE}") from exc


def main() -> int:
    try:
        for filename, url, expected in SOURCES:
            fetch_one(filename, url, expected)
        return 0
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
