# Verification ledger

Updated 2026-11-06 (Asia/Singapore). A compiled binary or proxy-only traffic test does not meet the original full VPN platform definition of done.

| Check | Result actually observed |
|---|---|
| Windows Rust root workspace | Builds; unit tests pass; clippy with warnings denied passes |
| Current Rust unit tests | 12 passed, including actual TCP listener process ownership and DPAPI storage |
| Daemon/CLI/MCP process suite | 14 passed using actual named pipes and subprocesses |
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
$env:MYVPN_TEST_SING_BOX = 'D:\custom vpn\.tools\sing-box\sing-box-1.14.4-windows-amd64\sing-box.exe'
$env:MYVPN_TEST_OUTLINE_WORKER = 'D:\custom vpn\target\debug\myvpn-tunnel.exe'
./scripts/cargo.ps1 test --locked -p myvpn-engine --test outline_traffic '--' --ignored --nocapture
```

The ignored test suite contains three real-engine tests and is run explicitly with those paths. Keep `'--'` quoted through the PowerShell wrapper. Use a separately obtained, pinned standalone sing-box executable for the independent peer and the built managed worker for lifecycle tests.

`MYVPN_TEST_EXPECT_UNPRIVILEGED=1` enables the TUN-start failure check inside the Node suite. Set it only after verifying the test process is unelevated; it intentionally attempts native startup and must not be enabled on a privileged shared machine. Standard tests otherwise do not replace OS routes.

GUI menu polling was found to recreate controls every refresh and has been changed to preserve unchanged server cards. Native inspection confirmed the menu remained open across refreshes. A second defect clipped the lower menu items at the card edge; the CSS fix was rebuilt, launched and visually verified with all four actions visible. Server details and Settings were also inspected. Narrow-window layout, service-recovery notice and tray/uninstall verification remain pending. Test fixture keys were removed from development state; no real access credential was used.

Security scan scope and remaining findings are recorded in [the dependency report](../security/dependencies.md). Scan databases change; rerun before a release.
