"""Fetch versioned raw NVD CVE or CPE snapshots when run locally."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argusloom.cti.nvd_discovery import (
    NVDAPIClient,
    persist_cpe_product_candidates,
    persist_discovery,
)

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cve-list", type=Path)
    mode.add_argument("--cpe-names", type=Path)
    mode.add_argument("--discover-product")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--manifest", type=Path, default=Path("data/cti_snapshot_manifest.json")
    )
    parser.add_argument(
        "--mapping-table", type=Path, default=Path("data/cpe_product_mappings.json")
    )
    parser.add_argument(
        "--candidate-versions",
        type=Path,
        default=Path("data/cpe_version_candidates.json"),
    )
    parser.add_argument("--cpe-names-output", type=Path)
    parser.add_argument("--api-key-env", default="NVD_API_KEY")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--min-interval", type=float)
    parser.add_argument("--max-retries", type=int, default=5)
    parser.add_argument("--refetch", action="store_true")
    parser.add_argument("--manifest-version", type=int)
    return parser


def main() -> None:
    args = _parser().parse_args()
    root = args.root.resolve()
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    api_key = os.environ.get(args.api_key_env, "")
    client = NVDAPIClient(
        api_key=api_key,
        timeout_seconds=args.timeout,
        min_interval_seconds=args.min_interval,
        max_retries=args.max_retries,
    )

    if args.cve_list is not None:
        list_path = (
            args.cve_list if args.cve_list.is_absolute() else root / args.cve_list
        )
        cve_ids = _read_lines(list_path)
        invalid = [value for value in cve_ids if not CVE_ID_PATTERN.fullmatch(value)]
        if invalid:
            raise SystemExit(f"Invalid CVE IDs: {', '.join(invalid)}")
        results = client.fetch_cves_by_ids(cve_ids)
    elif args.cpe_names is not None:
        list_path = (
            args.cpe_names if args.cpe_names.is_absolute() else root / args.cpe_names
        )
        results = client.fetch_cves_by_cpe(_read_lines(list_path))
    else:
        results = [client.discover_cpe_products(args.discover_product)]

    for result in results:
        entries = persist_discovery(
            result,
            root,
            manifest_path,
            refetch=args.refetch,
            new_manifest_version=args.manifest_version,
        )
        print(f"Saved {len(entries)} raw page(s) for {result.mode} " f"{result.query}")
        if result.mode == "cpe_dictionary_keyword":
            mapping_path = args.mapping_table
            versions_path = args.candidate_versions
            cpe_output = args.cpe_names_output or (
                Path("data/nvd")
                / f"candidate_cpe_names_{re.sub(r'[^a-z0-9._-]+', '_', result.query['keywordSearch'].casefold())}.txt"
            )
            if not mapping_path.is_absolute():
                mapping_path = root / mapping_path
            if not versions_path.is_absolute():
                versions_path = root / versions_path
            if not cpe_output.is_absolute():
                cpe_output = root / cpe_output
            candidates = persist_cpe_product_candidates(
                result,
                entries,
                mapping_path,
                versions_path,
                cpe_output,
            )
            print(
                f"Discovered {len(candidates)} vendor/product candidates; "
                "all require user verification."
            )
            for candidate in candidates:
                print(
                    f"  {candidate['vendor']}/{candidate['product']} "
                    f"(pending verification)"
                )
            print(f"Candidate exact CPE queries: {cpe_output}")


if __name__ == "__main__":
    main()
