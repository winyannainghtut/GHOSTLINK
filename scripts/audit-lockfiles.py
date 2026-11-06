"""Query OSV for both Rust lockfiles. Sends public dependency names/versions only.

Python 3.11+. Findings include every locked target, not just reachable Windows code.
API reference: https://google.github.io/osv.dev/post-v1-querybatch/
"""
import datetime
import json
from pathlib import Path
import sys
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    packages = set()
    for lock in (ROOT / "Cargo.lock", ROOT / "apps/desktop/src-tauri/Cargo.lock"):
        with lock.open("rb") as source:
            for package in tomllib.load(source)["package"]:
                if package.get("source", "").startswith("registry+"):
                    packages.add((package["name"], package["version"]))
    findings = []
    ordered = sorted(packages)
    for start in range(0, len(ordered), 100):
        batch = ordered[start:start + 100]
        queries = [{"package": {"ecosystem": "crates.io", "name": name}, "version": version} for name, version in batch]
        pending = list(enumerate(queries))
        while pending:
            request = urllib.request.Request("https://api.osv.dev/v1/querybatch", json.dumps({"queries": [query for _, query in pending]}).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=30) as response:
                results = json.load(response)["results"]
            if len(results) != len(pending):
                raise RuntimeError("Incomplete OSV response")
            next_page = []
            for (index, query), result in zip(pending, results):
                name, version = batch[index]
                for advisory in result.get("vulns", []):
                    finding = {"name": name, "version": version, "id": advisory["id"], "url": "https://osv.dev/vulnerability/" + advisory["id"]}
                    findings.append(finding)
                    print(json.dumps(finding), flush=True)
                if result.get("next_page_token"):
                    next_page.append((index, {**query, "page_token": result["next_page_token"]}))
            pending = next_page
    report = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "https://api.osv.dev/v1/querybatch", "package_versions": len(ordered), "findings": findings}
    destination = ROOT / "artifacts/rust-vulnerability-scan.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Checked {len(ordered)} locked Rust package versions; {len(findings)} advisory matches. Report: {destination}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
