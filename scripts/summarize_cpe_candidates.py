"""Print offline CVE statistics for the discovered candidate CPEs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argusloom.cti.candidate_summary import summarize_candidate_versions


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("data/cti_snapshot_manifest.json"),
    )
    parser.add_argument(
        "--mapping-table",
        type=Path,
        default=Path("data/cpe_product_mappings.json"),
    )
    parser.add_argument(
        "--candidate-versions",
        type=Path,
        default=Path("data/cpe_version_candidates.json"),
    )
    return parser


def _format_cell(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, dict):
        return "; ".join(f"{key}={value[key]}" for key in value)
    return str(value).replace("|", "\\|")


def main() -> None:
    args = _parser().parse_args()
    rows = summarize_candidate_versions(
        args.root,
        args.manifest,
        args.mapping_table,
        args.candidate_versions,
    )
    columns = (
        ("software_key", "Software"),
        ("vendor", "Vendor"),
        ("product", "Product"),
        ("version", "Version"),
        ("total_cves", "Total CVEs"),
        ("cvss_v3x_cves", "CVSS v3.x"),
        ("severity_distribution", "CVSS v3.x severity"),
        ("publication_year_range", "Publication years"),
        ("status", "Status"),
    )
    print("| " + " | ".join(title for _, title in columns) + " |")
    print("| " + " | ".join("---" for _ in columns) + " |")
    for row in rows:
        print(
            "| " + " | ".join(_format_cell(row[column]) for column, _ in columns) + " |"
        )


if __name__ == "__main__":
    main()
