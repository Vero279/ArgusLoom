"""
Audit script: validate CTI fixtures against official sources.
Run once before thesis. NOT part of the test suite.
Outputs a report you can paste into the thesis.
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path

# ---------- NVD ----------
def validate_cves(fixtures_path: Path) -> list[dict]:
    cves = json.loads(fixtures_path.read_text(encoding="utf-8"))
    results = []
    for cve in cves:
        cve_id = cve.get("id", "")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        status = "UNKNOWN"
        detail = ""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ArgusLoom-audit/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
            total = data.get("totalResults", 0)
            if total == 1:
                status = "VALID"
                official = data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"][:120]
                detail = f"official: {official}"
            else:
                status = "NOT FOUND"
                detail = f"totalResults={total}"
        except urllib.error.HTTPError as e:
            status = f"HTTP {e.code}"
        except Exception as e:
            status = "ERROR"
            detail = str(e)[:100]
        results.append({"id": cve_id, "status": status, "detail": detail})
        print(f"  {cve_id:22s} {status:12s} {detail[:80]}")
        # NVD rate limit: 5 req/30s without key -> sleep 6s
        time.sleep(6.5)
    return results

# ---------- ATT&CK ----------
def validate_attack(fixtures_path: Path) -> list[dict]:
    """Fetch official ATT&CK Enterprise STIX bundle and check each ID."""
    print("  Fetching official ATT&CK Enterprise STIX bundle...")
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    req = urllib.request.Request(url, headers={"User-Agent": "ArgusLoom-audit/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        stix = json.loads(r.read())

    official_ids = set()
    for obj in stix.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    official_ids.add(ref["external_id"])

    techniques = json.loads(fixtures_path.read_text(encoding="utf-8"))
    results = []
    for t in techniques:
        tid = t.get("id", "")
        status = "VALID" if tid in official_ids else "NOT FOUND"
        results.append({"id": tid, "status": status})
        print(f"  {tid:12s} {status}")
    return results

# ---------- ATLAS ----------
def validate_atlas(fixtures_path: Path) -> list[dict]:
    """Fetch official ATLAS YAML and extract AML.T#### IDs."""
    print("  Fetching official ATLAS YAML...")
    # latest release YAML — adjust if newer release exists
    url = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.09.yaml"
    req = urllib.request.Request(url, headers={"User-Agent": "ArgusLoom-audit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            yaml_text = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  ATLAS fetch failed: {e}")
        return [{"id": "ALL", "status": f"FETCH FAILED: {e}"}]

    # crude extraction of AML.T#### IDs from YAML (no yaml dep needed)
    import re
    official_ids = set(re.findall(r"AML\.T\d{4}(?:\.\d{3})?", yaml_text))

    techniques = json.loads(fixtures_path.read_text(encoding="utf-8"))
    results = []
    for t in techniques:
        tid = t.get("id", "")
        status = "VALID" if tid in official_ids else "NOT FOUND"
        results.append({"id": tid, "status": status})
        print(f"  {tid:14s} {status}")
    return results

# ---------- MAIN ----------
def main():
    root = Path.cwd()
    print("=" * 70)
    print("CTI FIXTURE VALIDATION")
    print("=" * 70)

    print("\n[1/3] CVEs (NVD API 2.0, ~6.5s between requests)")
    cve_results = validate_cves(root / "data/fixtures/cves.json")
    cve_valid = sum(1 for r in cve_results if r["status"] == "VALID")
    cve_invalid = [r for r in cve_results if r["status"] != "VALID"]

    print(f"\n[2/3] ATT&CK techniques (official STIX bundle)")
    attack_results = validate_attack(root / "data/mitre/attack.json")
    attack_valid = sum(1 for r in attack_results if r["status"] == "VALID")
    attack_invalid = [r for r in attack_results if r["status"] != "VALID"]

    print(f"\n[3/3] ATLAS techniques (official YAML)")
    atlas_results = validate_atlas(root / "data/mitre/atlas.json")
    atlas_valid = sum(1 for r in atlas_results if r["status"] == "VALID")
    atlas_invalid = [r for r in atlas_results if r["status"] != "VALID"]

    # ---------- Report ----------
    print("\n" + "=" * 70)
    print("SUMMARY FOR THESIS")
    print("=" * 70)
    print(f"CVEs:   {cve_valid}/{len(cve_results)} valid")
    print(f"ATT&CK: {attack_valid}/{len(attack_results)} valid")
    print(f"ATLAS:  {atlas_valid}/{len(atlas_results)} valid")

    if cve_invalid or attack_invalid or atlas_invalid:
        print("\nINVALID ENTRIES:")
        for r in cve_invalid + attack_invalid + atlas_invalid:
            print(f"  {r['id']} — {r['status']} — {r.get('detail','')}")

    # write report
    report = {
        "cves": {"total": len(cve_results), "valid": cve_valid, "invalid": cve_invalid},
        "attack": {"total": len(attack_results), "valid": attack_valid, "invalid": attack_invalid},
        "atlas": {"total": len(atlas_results), "valid": atlas_valid, "invalid": atlas_invalid},
    }
    out = root / "cti_validation_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nReport written to {out}")

if __name__ == "__main__":
    main()