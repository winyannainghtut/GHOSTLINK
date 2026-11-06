# Releases

`.github/workflows/release.yml` builds unsigned pre-release packages on GitHub-hosted runners.

| Job | Runner | Files |
|---|---|---|
| Windows x64 | `windows-2022` | `Ghostlink-<v>-windows-x64.msi`, `Ghostlink-<v>-windows-x64-portable.zip`, `Ghostlink-<v>-worker-corresponding-source.zip` |
| Linux x64 | `ubuntu-22.04` | `ghostlink-<v>-linux-x64.tar.gz` |
| Linux arm64 | `ubuntu-22.04-arm` | `ghostlink-<v>-linux-arm64.tar.gz` |

The Linux archives are headless (`ghostlink`, `ghostlinkd`, `ghostlink-mcp`, the tunnel worker, the systemd unit, notices and `INSTALL.txt`). Building on Ubuntu 22.04 links against glibc 2.35 and OpenSSL 3, so the binaries also run on newer distributions. Both Linux archives come from the reusable `.github/workflows/linux-package.yml`. The arm64 job never gates the draft release: `publish` waits only for Windows and Linux x64, and `attach-linux-arm64` adds the arm64 archive and its checksum line when it finishes. If hosted arm64 runners are unavailable to the repository, that job stays queued; cancel it and the draft is unaffected.

## Cutting a release

1. Set the new version in every declaration: `[workspace.package]` in `Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`, `apps/desktop/src-tauri/tauri.conf.json`, the version label in `apps/desktop/ui/index.html`, `version` in `core/outline-worker/main.go`, and `WORKER_VERSION` in `core/vpn-engine/src/outline_session.rs`. Update the lockfiles with a normal build, and update the CLI version assertion in `tests/integration/control-plane.test.mjs`.
2. Run `node scripts/release-version.mjs`. It prints the version, or names every declaration that disagrees.
3. Regenerate notices if dependencies changed: `python scripts/collect-licenses.py`.
4. Commit, then push a matching tag: `git tag v<version> && git push origin v<version>`.

Every job runs the version check first and fails if the tag is not `v<version>`. After all builds pass, the `publish` job writes `SHA256SUMS.txt` and creates a **draft** pre-release from `.github/release-notes.md`; re-running it uploads replacement files to the same draft. Review the draft, then publish it. Nothing is public before that.

To test the pipeline without a release, run the workflow manually (**Actions → Release → Run workflow**); the files appear as workflow artifacts only.

## Local builds

```powershell
./scripts/bootstrap-windows.ps1
./scripts/build-windows.ps1            # MSI + portable ZIP under artifacts/windows-x64
./scripts/package-worker-source.ps1    # GPL corresponding source under artifacts/source
```

```sh
bash scripts/build-linux.sh            # artifacts/linux-<arch>/ghostlink-<v>-linux-<arch>.tar.gz
```

All scripts default to the checked version from `scripts/release-version.mjs`.

## Not built yet

- **Linux desktop GUI**: the GTK chain still carries the `glib` advisory in [dependencies](../security/dependencies.md).
- **DEB/RPM**: wait until the Linux runtime has been verified.
- **Windows arm64**: the MSI is x64-only.
- **macOS**: `core/vpn-engine/src/process.rs` has no macOS listener-ownership check, so connections fail closed.
- **Android and iOS**: no implementation exists.

Code signing is not configured. Signed Windows builds need a certificate and a signing step before `light.exe` output is published.
