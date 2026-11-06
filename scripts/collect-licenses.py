#!/usr/bin/env python3
"""Collect actual dependency licenses from Cargo metadata and pinned Go modules."""
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "LICENSES" / "dependencies"


def copy_notices(directory, destination, recursive=False):
    found = []
    candidates = directory.rglob("*") if recursive else directory.iterdir()
    for path in candidates:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        name = path.name.lower()
        if name.startswith(("license", "copying", "notice")) and path.suffix.lower() not in (".go", ".rs", ".py", ".js"):
            relative = path.relative_to(directory)
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
            found.append(str(relative).replace("\\", "/"))
    return sorted(found)


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    entries = {}
    for manifest in [ROOT / "Cargo.toml", ROOT / "apps/desktop/src-tauri/Cargo.toml"]:
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", str(manifest)], cwd=ROOT))
        for package in metadata["packages"]:
            if not package["source"]:
                continue
            key = f"rust-{package['name']}-{package['version']}"
            if key not in entries:
                notices = copy_notices(Path(package["manifest_path"]).parent, DEST / key)
                entries[key] = {"ecosystem": "rust", "name": package["name"], "version": package["version"], "license": package["license"], "repository": package["repository"], "notices": notices}
    listing = subprocess.check_output(["go", "list", "-deps", "-tags", "with_gvisor", "-f", "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}", "."], cwd=ROOT / "core/outline-worker", text=True)
    for line in set(listing.splitlines()):
        if not line.strip():
            continue
        name, version, directory = line.split("|", 2)
        if name.startswith("myvpn.local/"):
            continue
        key = "go-" + name.replace("/", "_") + "-" + version
        notices = copy_notices(Path(directory), DEST / key, recursive=True)
        entries[key] = {"ecosystem": "go", "name": name, "version": version, "notices": notices}
    (ROOT / "LICENSES" / "dependency-inventory.json").write_text(json.dumps(list(entries.values()), indent=2) + "\n", encoding="utf-8")
    print(f"Collected notices for {len(entries)} locked Rust packages and used Go modules")


if __name__ == "__main__":
    main()
