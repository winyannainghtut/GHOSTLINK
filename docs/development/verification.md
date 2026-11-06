# Verification ledger

Updated 2026-11-06 (Asia/Singapore). A compiled binary or proxy-only traffic test does not meet the original full VPN platform definition of done.

## After the Ghostlink rename and review fixes (2026-11-06)

Observed on the same Windows development host, unelevated.

| Check | Result actually observed |
|---|---|
| Autoconnect startup failure (before the fix) | Reproduced with an isolated dev daemon: with autoconnect enabled, an engine-start error made the daemon exit 1, and `autoconnect disable` returned `daemon_unavailable` |
| Rust fmt / clippy | Root and desktop `fmt --check` clean; root clippy `--all-targets -D warnings` clean |
| Rust unit tests | 12 passed (2 contracts + 10 engine); 3 real-engine tests ignored as designed |
| Daemon/CLI/MCP process suite | 16 passed on debug binaries and again on release binaries. New: failed autoconnect keeps the service reachable and reports `autoconnect_failed`; crash leftovers removed at startup; import refuses to overwrite without `--replace`; fingerprint is not a plain credential hash |
| Real-engine tests | 3 passed with the renamed worker (`Ghostlink tunnel worker 0.1.0; sing-box 1.14.4`) against the independent sing-box 1.14.4 peer |
| Go worker | vet and test passed; Windows build passed; linux/amd64 and linux/arm64 cross-builds passed (not executed on Linux) |
| Python provisioning | 2 passed on Python 3.12 and Python 3.13 after `provision.py` switched to absolute System32 `whoami.exe`/`icacls.exe`; a bare `whoami` had resolved to Git's GNU tool |
| Windows packaging | Release Rust, desktop and worker builds passed. The MSI compiled, linked and validated after a quoting fix in `build-windows.ps1`. The MSI tables show ProductName `Ghostlink`, version 0.1.0, a new UpgradeCode and service `Ghostlink` with the renamed arguments; the portable ZIP and the worker source bundle were also produced. Installation still not executed |
| Release workflow | `release.yml` parses; version/tag check and publish file-collection logic exercised locally. Not yet run on GitHub-hosted runners; no tag pushed and no release created |
| Linux service | Unit now includes `CAP_CHOWN`; still not run on Linux |

## Earlier results (before the rename)

| Check | Result actually observed |
|---|---|
| Windows Rust root workspace | Builds; unit tests pass; clippy with warnings denied passes |
| Current Rust unit tests | 12 passed, including actual TCP listener process ownership and DPAPI storage |
| Daemon/CLI/MCP process suite | 14 passed using actual named pipes and subprocesses (16 after the rename; see above) |
| Real Shadowsocks interoperability | HTTP traversed a local encrypted server/client; incorrect password did not reach a live destination; controller denied missing authorization |
| Managed worker lifecycle | Explicit stop and parent-stdin EOF both produced graceful close and removed the real listener |
| Startup failure cleanup | Invalid engine configuration left no plaintext outline.json |
| Unelevated Outline TUN start | Rejected with failed state and no VPN IP; disconnect completed; temporary config removed (explicit unprivileged test enabled) |
| Native desktop runtime | Launched; empty state and access-key dialog inspected; a test key was imported through the GUI and confirmed via CLI; light/dark views inspected |
| Windows release / MSI | Optimized binaries and MSI built; WiX linking/package validation passed; installer execution and elevated service lifecycle are not verified |
| Release process suite | The same 14 tests passed again against final optimized CLI/service/MCP/worker binaries, including the unelevated TUN failure case |
| Worker corresponding source | Vendored source staging built successfully with Go 1.26.10 and the published flags; version command passed. Vendored builds omit module checksum build metadata, so byte-identical reproduction is not claimed |
| Wintun provenance | Embedded amd64 DLL matched official 0.14.1 bytes; Authenticode valid, WireGuard LLC |
| Dependency scans | npm audit: zero known vulnerabilities; govulncheck 1.9.0: no vulnerabilities after dependency updates; OSV Rust lock scan: 3 matches representing 2 unresolved Linux GUI/build dependencies (see security report) |
| Offline server provisioning | Two Python integration tests passed: distinct Outline keys/config/removal and real OpenSSL CA issuance, server-only bundle, CRL revocation |
| Linux | Managed Go worker cross-compiled for linux/amd64; Rust daemon/GUI and runtime remain unverified |
| Terraform | 1.14.6 init with backend disabled and validate passed; AWS provider 6.72.0 lock recorded; no plan/apply or cloud changes |
| Android / iOS | Not implemented or compiled; native toolchains/signing/devices required |
| Full-device routing / DNS / IPv6 / crash recovery | Not verified; requires authorized privileged network tests |

Commands:

```powershell
./scripts/cargo.ps1 test --locked --workspace
./scripts/cargo.ps1 clippy --locked --workspace --all-targets '--' -D warnings
npm test
$env:GHOSTLINK_TEST_SING_BOX = 'D:\custom vpn\.tools\sing-box\sing-box-1.14.4-windows-amd64\sing-box.exe'
$env:GHOSTLINK_TEST_OUTLINE_WORKER = 'D:\custom vpn\target\debug\ghostlink-tunnel.exe'
./scripts/cargo.ps1 test --locked -p ghostlink-engine --test outline_traffic '--' --ignored --nocapture
```

The ignored test suite contains three real-engine tests and is run explicitly with those paths. Keep `'--'` quoted through the PowerShell wrapper. Use a separately obtained, pinned standalone sing-box executable for the independent peer and the built managed worker for lifecycle tests.

`GHOSTLINK_TEST_EXPECT_UNPRIVILEGED=1` enables the TUN-start failure check inside the Node suite. Set it only after verifying the test process is unelevated; it intentionally attempts native startup and must not be enabled on a privileged shared machine. Standard tests otherwise do not replace OS routes.

GUI menu polling was found to recreate controls every refresh and has been changed to preserve unchanged server cards. Native inspection confirmed the menu remained open across refreshes. A second defect clipped the lower menu items at the card edge; the CSS fix was rebuilt, launched and visually verified with all four actions visible. Server details and Settings were also inspected. Narrow-window layout, service-recovery notice and tray/uninstall verification remain pending. Test fixture keys were removed from development state; no real access credential was used.

Security scan scope and remaining findings are recorded in [the dependency report](../security/dependencies.md). Scan databases change; rerun before a release.
