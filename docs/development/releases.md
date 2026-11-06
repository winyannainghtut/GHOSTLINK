# Releases

`.github/workflows/release.yml` builds unsigned pre-release packages on GitHub-hosted runners.

| Job | Runner | Files |
|---|---|---|
| Windows x64 | `windows-2022` | `Ghostlink-<v>-windows-x64.msi`, `Ghostlink-<v>-windows-x64-portable.zip`, `Ghostlink-<v>-worker-corresponding-source.zip` |
| Linux x64 | `ubuntu-22.04` | `ghostlink-<v>-linux-x64.tar.gz`, `ghostlink_<v>-1_amd64.deb`, `ghostlink-<v>-1.x86_64.rpm`, `ghostlink-server_<v>-1_amd64.deb`, `ghostlink-server-<v>-1.x86_64.rpm`, `Ghostlink-<v>-ipsec-component-source-x64.tar.gz` |
| Linux arm64 | `ubuntu-22.04-arm` | `ghostlink-<v>-linux-arm64.tar.gz`, `ghostlink_<v>-1_arm64.deb`, `ghostlink-<v>-1.aarch64.rpm`, `ghostlink-server_<v>-1_arm64.deb`, `ghostlink-server-<v>-1.aarch64.rpm`, `Ghostlink-<v>-ipsec-component-source-arm64.tar.gz` |

Each Linux job installs pinned nfpm 2.48.0, then smoke-tests the client `.deb` as a real systemd service (install, `ghostlink status`/`doctor`, purge) and inspects the `.rpm`. It builds the server image with Docker (`scripts/build-linux-server.sh`), installs the server `.deb` and exercises it (pin, API, keys, hardening, reinstall, purge), and inspects the server `.rpm`. Then it runs `tests/ipsec/interop.sh` (the IPsec component with a strongSwan client for each sign-in method) and builds the component's GPL source bundle with `scripts/ipsec-source.sh` before uploading. The Linux archives are headless (`ghostlink`, `ghostlinkd`, `ghostlink-mcp`, the tunnel worker, the systemd unit, notices and `INSTALL.txt`). Building on Ubuntu 22.04 links against glibc 2.35 and OpenSSL 3, so the binaries also run on newer distributions. Both Linux archives come from the reusable `.github/workflows/linux-package.yml`. The arm64 job never gates the draft release: `publish` waits only for Windows and Linux x64, and `attach-linux-arm64` adds the arm64 archive and its checksum line when it finishes. If hosted arm64 runners are unavailable to the repository, that job stays queued; cancel it and the draft is unaffected.

## Cutting a release

1. Set the new version in every declaration: `[workspace.package]` in `Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`, `apps/desktop/src-tauri/tauri.conf.json`, the version label in `apps/desktop/ui/index.html`, `Ghostlink` in `core/outline-worker/internal/version/version.go` (shared by the worker and the server), and `WORKER_VERSION` in `core/vpn-engine/src/worker_session.rs`. Update the lockfiles with a normal build, and update the CLI version assertion in `tests/integration/control-plane.test.mjs`.
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new `## [<version>] - <date>` heading; the release notes include that section (`scripts/changelog-section.mjs`).
3. Run `node scripts/release-version.mjs`. It prints the version, or names every declaration that disagrees.
4. Regenerate notices if dependencies changed: `python scripts/collect-licenses.py`.
5. Update the README and docs for anything user-visible, commit, then push a matching tag: `git tag v<version> && git push origin v<version>`.

Every job runs the version check first and fails if the tag is not `v<version>`. After all builds pass, the `publish` job writes `SHA256SUMS.txt` and creates a **draft** pre-release from `.github/release-notes.md`; re-running it uploads replacement files to the same draft. Review the draft, then publish it. Nothing is public before that.

To test the pipeline without a release, run the workflow manually (**Actions → Release → Run workflow**); the files appear as workflow artifacts only.

## Local builds

```powershell
./scripts/bootstrap-windows.ps1
./scripts/build-windows.ps1            # MSI + portable ZIP under artifacts/windows-x64
./scripts/package-worker-source.ps1    # GPL corresponding source (whole Go module, build-checked) under artifacts/source
```

```sh
bash scripts/build-linux.sh            # client: .tar.gz, .deb, .rpm under artifacts/linux-<arch>/
bash scripts/build-linux-server.sh     # server image and its .deb/.rpm (needs Docker and nfpm)
```

All scripts default to the checked version from `scripts/release-version.mjs`.

## Not built yet

- **Linux desktop GUI**: the GTK chain still carries the `glib` advisory in [dependencies](../security/dependencies.md).
- **Windows arm64**: the MSI is x64-only.
- **macOS**: `core/vpn-engine/src/process.rs` has no macOS listener-ownership check, so connections fail closed.
- **Android and iOS**: no implementation exists.

Code signing is not configured. Signed Windows builds need a certificate and a signing step before `light.exe` output is published.
