#!/usr/bin/env python3
"""Collect actual dependency licenses from Cargo metadata, pinned Go modules and the web UI's bundled npm packages."""
import os
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
    # Start empty, so notices of versions that are no longer locked do not stay behind and ship.
    # The folder holds only generated notices; hand-kept texts are at the top of LICENSES/.
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)
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
    go_list = ["go", "list", "-deps", "-tags", "with_gvisor,with_utls,with_wireguard", "-f", "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}"]
    worker = ROOT / "core/outline-worker"
    # The worker for this platform, plus the Linux server, IPsec agent and mesh agent (Linux-only
    # imports).
    listing = subprocess.check_output(go_list + [".", "./cmd/ghostlink-server"], cwd=worker, text=True)
    listing += subprocess.check_output(go_list + [".", "./cmd/ghostlink-server", "./cmd/ghostlink-ipsec-agent", "./cmd/ghostlink-mesh"], cwd=worker, text=True,
                                       env={**os.environ, "GOOS": "linux", "GOARCH": "amd64"})
    # Sorted, so that the inventory comes out in the same order on every run.
    for line in sorted(set(listing.splitlines())):
        if not line.strip():
            continue
        name, version, directory = line.split("|", 2)
        if name.startswith("ghostlink.local/"):
            continue
        key = "go-" + name.replace("/", "_") + "-" + version
        notices = copy_notices(Path(directory), DEST / key, recursive=True)
        entries[key] = {"ecosystem": "go", "name": name, "version": version, "notices": notices}
    # The web UI (ui/): npm packages whose code or files are in the built dashboard. That is the
    # runtime dependencies (types-only packages ship nothing), plus two build tools whose own code
    # is copied into the output: Tailwind's base styles and the bundler's runtime helpers.
    ui = ROOT / "ui"
    lock = json.loads((ui / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    bundled = {path.removeprefix("node_modules/") for path, meta in lock.items() if path.startswith("node_modules/") and not meta.get("dev")}
    bundled = {name for name in bundled if not name.startswith("@types/") and name != "csstype"} | {"tailwindcss", "rolldown"}
    for name in sorted(bundled):
        meta = lock["node_modules/" + name]
        directory = ui / "node_modules" / name
        if not directory.is_dir():
            raise SystemExit("ui/node_modules is missing; run: cd ui && npm ci --ignore-scripts")
        key = "npm-" + name.replace("@", "").replace("/", "_") + "-" + meta["version"]
        notices = copy_notices(directory, DEST / key)
        entries[key] = {"ecosystem": "npm", "name": name, "version": meta["version"], "license": meta.get("license"), "notices": notices}
    (ROOT / "LICENSES" / "dependency-inventory.json").write_text(json.dumps(list(entries.values()), indent=2) + "\n", encoding="utf-8")
    print(f"Collected notices for {len(entries)} locked Rust packages, used Go modules and bundled npm packages")


if __name__ == "__main__":
    main()
