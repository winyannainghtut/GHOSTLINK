# Releases

`.github/workflows/release.yml` builds unsigned pre-release packages on GitHub-hosted runners.

| Job | Runner | Files |
|---|---|---|
| Windows x64 | `windows-2022` | `Ghostlink-<v>-windows-x64.msi`, `Ghostlink-<v>-windows-x64-portable.zip`, `Ghostlink-<v>-worker-corresponding-source.zip` |
| Linux x64 | `ubuntu-22.04` | `ghostlink-<v>-linux-x64.tar.gz`, `ghostlink_<v>-1_amd64.deb`, `ghostlink-<v>-1.x86_64.rpm`, `ghostlink-server_<v>-1_amd64.deb`, `ghostlink-server-<v>-1.x86_64.rpm`, `ghostlink-mesh_<v>-1_amd64.deb`, `ghostlink-mesh-<v>-1.x86_64.rpm`, `Ghostlink-<v>-ipsec-component-source-x64.tar.gz` |
| Linux arm64 | `ubuntu-22.04-arm` | `ghostlink-<v>-linux-arm64.tar.gz`, `ghostlink_<v>-1_arm64.deb`, `ghostlink-<v>-1.aarch64.rpm`, `ghostlink-server_<v>-1_arm64.deb`, `ghostlink-server-<v>-1.aarch64.rpm`, `ghostlink-mesh_<v>-1_arm64.deb`, `ghostlink-mesh-<v>-1.aarch64.rpm`, `Ghostlink-<v>-ipsec-component-source-arm64.tar.gz` |

Each Linux job installs pinned nfpm 2.48.0, then smoke-tests the client `.deb` as a real systemd service (install, `ghostlink status`/`doctor`, a reinstall with the service enabled and one with it disabled, removal and a new install, purge) and inspects the `.rpm`. It builds the server image with Docker (`scripts/build-linux-server.sh`), installs the server `.deb` and exercises it (pin, API, keys, hardening, reinstall, dashboard). It then builds the mesh agent (`scripts/build-linux-mesh.sh`) and smoke-tests it against that server: the **Add node** installer with an invite, `leave`, `install-server.sh --mesh-package` (join-here as the relay), and purge, with no interface, chains or hosts entries left. It inspects the mesh `.rpm` and purges the server. Then it smoke-tests the move from Outline against a fake Outline (shadowbox's files and stand-in containers): `install-server.sh --migrate-outline --check`, a failed import that must put Outline back, the real migration with Outline's original `ss://` credentials, a refused second run and the printed rollback; then it purges the server again and inspects the server `.rpm`. Then it runs `tests/ipsec/interop.sh` (the IPsec component with a strongSwan client for each sign-in method, and a capped download at a speed limit) and builds the component's GPL source bundle with `scripts/ipsec-source.sh` before uploading. The Linux archives are headless (`ghostlink`, `ghostlinkd`, `ghostlink-mcp`, the tunnel worker, the systemd unit, notices and `INSTALL.txt`). Building on Ubuntu 22.04 links against glibc 2.35 and OpenSSL 3, so the binaries also run on newer distributions. Both Linux archives come from the reusable `.github/workflows/linux-package.yml`. The release workflow also runs `desktop.yml` (Go tests and vet, govulncheck, the process suite, clippy and formatting) and `ui.yml` (the committed web UI builds match `ui/`). The arm64 job never gates the draft release: `publish` waits for Windows, Linux x64, `desktop.yml` and `ui.yml`, and `attach-linux-arm64` adds the arm64 files and their checksum lines when it finishes. If hosted arm64 runners are unavailable to the repository, that job stays queued; the draft is unaffected, but don't publish it without the arm64 files (see below).

## Cutting a release

1. Set the new version in every declaration: `[workspace.package]` in `Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`, `apps/desktop/src-tauri/tauri.conf.json`, `VERSION` in `ui/desktop/src/version.ts` (then rebuild the web UI: `cd ui && npm run build`, and commit `apps/desktop/ui`), `Ghostlink` in `core/outline-worker/internal/version/version.go` (shared by the worker and the server), and `WORKER_VERSION` in `core/vpn-engine/src/worker_session.rs`. Update the CLI version assertion in `tests/integration/control-plane.test.mjs` and the worker identity quoted in §5 of `agent.md`. After both `Cargo.toml` files, update the workspace members in the lockfiles with `scripts/cargo.ps1 update --workspace --offline`, and once more with `--manifest-path apps/desktop/src-tauri/Cargo.toml`: the release builds pass `--locked`, which refuses a stale lock, and the version check below does not look at the lockfiles.
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new `## [<version>] - <date>` heading, and update the links at the end of the file: `[Unreleased]` compares `v<version>` with `HEAD`, and a new `[<version>]` line compares the previous tag with `v<version>`. The release notes include that section (`scripts/changelog-section.mjs`).
3. Run `node scripts/release-version.mjs`. It prints the version, or names every declaration that disagrees.
4. Regenerate notices if dependencies changed: `python scripts/collect-licenses.py`.
5. Update the README and docs for anything user-visible, and commit on the release branch. Once its pull request is squash-merged into `main`, tag that squash commit and push the tag: `git fetch origin && git tag -a v<version> -m "Ghostlink <version>" origin/main && git push origin v<version>` (right after the merge, `origin/main` is that commit). The workflow accepts a lightweight tag too.

The Windows and Linux jobs run the version check first and fail if a declaration disagrees or the tag is not `v<version>`; `publish` and `attach-linux-arm64` only run after them. When the Windows, Linux x64, `desktop.yml` and `ui.yml` jobs pass, `publish` writes `SHA256SUMS.txt` and creates a **draft** pre-release from `.github/release-notes.md`; `attach-linux-arm64` adds the arm64 files and their checksum lines when that job finishes. Review the draft, then publish it once `attach-linux-arm64` has finished and the draft has every file (20 for 0.8.x). Don't publish without the arm64 files: `install-server.sh`, `install-mesh.sh` and the app's **Add node** command take the newest published release, pre-releases included, so arm64 servers would fail to install or upgrade until the files are there. Nothing is public before that.

Running the workflow again for the tag (**Re-run all jobs**, or pushing the tag again) replaces the draft's files. `publish` also deletes the files it did not build again, such as arm64 files when the arm64 job does not finish this time, so `SHA256SUMS.txt` always lists every file. A published release is never changed: `publish` and `attach-linux-arm64` fail instead. A transient failure on the tag run (a download, a flaky test) needs only **Re-run failed jobs** on that run; push the tag again only when the commit itself must change. Pushing the tag again replaces only the files: the draft keeps the notes it was created with. If the CHANGELOG section changed, a maintainer deletes the draft before the tag is pushed again, or pastes the new section into it.

To test the pipeline without a release, run the workflow manually (**Actions → Release → Run workflow**), on a branch or a tag; the files appear as workflow artifacts only.

## Local builds

```powershell
./scripts/bootstrap-windows.ps1
./scripts/build-windows.ps1            # MSI + portable ZIP under artifacts/windows-x64
./scripts/package-worker-source.ps1    # GPL corresponding source (whole Go module, build-checked) under artifacts/source
```

```sh
bash scripts/build-linux.sh            # client: .tar.gz, .deb, .rpm under artifacts/linux-<arch>/
bash scripts/build-linux-server.sh     # server image and its .deb/.rpm (needs Docker and nfpm)
bash scripts/build-linux-mesh.sh       # mesh agent .deb/.rpm (needs nfpm)
```

All scripts default to the checked version from `scripts/release-version.mjs`.

## Not built yet

- **Linux desktop GUI**: the GTK chain still carries the `glib` advisory in [dependencies](../security/dependencies.md).
- **Windows arm64**: the MSI is x64-only.
- **macOS**: `core/vpn-engine/src/process.rs` has no macOS listener-ownership check, so connections fail closed.
- **Android and iOS**: no implementation exists.

Code signing is not configured. Signed Windows builds need a certificate and a signing step before `light.exe` output is published.
