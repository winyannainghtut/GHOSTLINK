# Ghostlink development journey and resume handoff

Last updated: **2026-11-06, Asia/Singapore**.

The user resumed work with **“continue”** and selected **“Continue with local test servers for now”**. Keep using local isolated test peers; no real Outline key is required at this stage. This current handoff supersedes the archived October snapshot below. Do not restart the project or replace the real service with a mockup.

The detailed standalone AI handover is [agent.md](agent.md), created on 2026-11-06. It consolidates the current architecture, source map, exact workflows, verified results, artifacts, security/licensing boundaries and continuation plan; this file retains the chronological history.

## Current handoff — November 6

### Later on November 6: v0.5.0 — IKEv2/IPsec for iPhone, iPad and Mac

The user asked for native iOS VPN protocols:
- IKEv2/IPsec first, with password and certificate sign-in, configurable server address, remote and local identifiers, and secure credential storage;
- IPsec second, with PSK and certificates.

They chose:
- configuration profiles instead of an app;
- hosting IKEv2/IPsec on the Ghostlink server as an optional component;
- PSK and certificates for IPsec, with certificates as the default;
- unsigned profiles, since there is no Apple Developer account or Mac yet.

Delivered:
- **the server's CA and profiles**;
- **a strongSwan 6 component** in a second, network-privileged container, driven by a validating agent from settings the unprivileged server writes;
- **accounting, limits and cut-offs** for IKEv2/IPsec users;
- **firewall rules and DNS-based site blocks**;
- **app, CLI, dashboard and server commands**;
- **a GPL source bundle** for the component's Alpine packages.

CI iterations on a feature branch fixed:
- strongSwan's critical-plugin syntax;
- hidden start-up logs;
- a test address created too late;
- the agent's polling delay;
- lost counters for sessions that ended between reports (now taken from charon's down and rekey events);
- Alpine's GitLab refusing CI downloads (switched to the GitHub mirror).

An unrelated flaky QR test was made deterministic. The license inventory now includes Linux-only Go modules.

Not verified: a real Apple device; hosts with iptables-legacy, firewalld or ufw; an internet-facing host.

### Later on November 6: v0.4.0 — monitoring, server-side admin, dashboard

The user asked for:
- detailed monitoring: traffic types and live data;
- server management without the app;
- a dashboard on a non-443 port;
- automatic rotation so traffic records cannot fill the disk.

They chose:
- server commands plus a tunnel-only web dashboard;
- opt-in top sites;
- no OpenVPN for now.

Delivered:
- **monitoring:** per-user live rates, connections, traffic types, protocols, opt-in services, client addresses and health;
- **history:** with age, size and low-disk rotation;
- **server commands and a dashboard** on its own port;
- **sharing:** QR codes and connection kits;
- **app and CLI support.**

Deviation from the plan: the dashboard login token is stored as-is in the server state, like the management secret, rather than hashed, so the same link can be printed again.

Incidents during GUI checks:
- the debug app exited because it couldn't share the installed app's WebView2 profile; it now uses its own profile;
- a `blob:` download failed in WebView2; it was replaced by a desktop save command;
- **headless Edge with a fresh profile was implicitly signed in to the user's Microsoft account.** It was stopped and its profile deleted, and the user was told.

### Later on November 6: v0.3.1 — first real Windows install

The user installed the v0.3.0 MSI and found two problems:
- **Unreachable service:** the app reported "Cannot reach the authorized local Ghostlink service". The client's identity check opened the SYSTEM service's process token, which a standard user may not do. It now checks the pipe owner. The fixed CLI was confirmed against the user's real installed service.
- **No icon:** the Start-menu shortcut had none. It now uses an `.ico` icon ID, and a desktop shortcut was added.

The user also pasted a real Outline access key into the chat. They were advised to rotate it, and the key was not used.

### Later on November 6: v0.3.0 — Ghostlink server and management from the app

- **v0.2.1 released as a draft:** client `.deb`/`.rpm` with a real systemd install test in CI, and the worker SIGPIPE fix.
  - **CI failure:** the CI workflow on the same commit failed on Linux with an AmneziaWG close race (a late packet write after the TUN closed). It is fixed in `internal/awg/tun.go`, with a regression test.
  - **Incomplete source zip:** the corresponding-source zip lacked `internal/awg`. The script now copies the whole module and build-checks it, and v0.2.1's zip was replaced in the draft.
- **Phase 3 (server):** `cmd/ghostlink-server` + `internal/server`:
  - users, keys, global and per-user rules, usage and limits, all over an HTTPS API;
  - the image is shipped inside `ghostlink-server` `.deb`/`.rpm` packages;
  - the admin shell command `ghostlink-server`.
- **Phase 4 (client):**
  - pinned management client (rustls);
  - daemon `ManagedServer*`/`ServerCall`, with calls outside the lock;
  - CLI `ghostlink server ...`;
  - GUI **Servers I run**;
  - management APIs bypass the tunnel while connected.
- **Shared version:** the worker and server share `internal/version`, and the release check reads it.
- **Tooling notes:**
  - shell heredocs mangle backslashes and some quote sequences, so write scripts with the file-writing tool;
  - drive the GUI over WebView2 DevTools, never with mouse clicks; one stray click landed on the user's browser before this was changed;
  - Docker Desktop stays off, and container tests run in release CI.

### Later on November 6: first hosted CI of v0.2.0 and documentation pass

- **CI failure on Linux:** the new real-engine tests failed because Go raises SIGPIPE when writing to a closed stderr. The tests had dropped the pipe, but a crashed daemon could do the same to a real worker, so the worker now ignores SIGPIPE on Unix. The tests drain events, warm up the tunnel and run serially in CI.
- **Documentation:**
  - the README was rewritten as a proper project README;
  - `CHANGELOG.md` was added, and the release workflow puts each version's section into its release notes;
  - `docs/architecture/protocols.md` records the protocol and split-tunnel design and pitfalls;
  - the worker README, Windows guide and handover were brought up to date.

### Later on November 6: v0.2.0 — WireGuard, AmneziaWG, VLESS-REALITY, Amnezia import, split tunneling

The approved plan is in four phases: (1) client protocols, (2) client split tunneling, (3) an Outline-style Ghostlink server shipped as `.deb`/`.rpm` packages with the Docker image included, and (4) server management from the app. Phases 1–2 are implemented as **v0.2.0**; phases 3–4 are next (v0.3.0).

- **Engine:** `core/outline-worker/internal/awg` drives unmodified amneziawg-go v3 through sing-box's userspace stack and interface-bound dialer. It serves both client and server roles and carries peer user names for `auth_user` rules.
  - Do not reuse sing-box's `ClientBind` unchanged: it rewrites packet bytes 1–3 for WARP, which breaks AmneziaWG headers.
  - Upstream amneziawg-go reports `AdvancedSecurity` as EINVAL in userspace mode, so the parser refuses `AdvancedSecurity = on`.
- **Worker:** registers VLESS, the native WireGuard endpoint and `amneziawg`. Build tags are now `with_gvisor,with_utls,with_wireguard`.
- **Dependencies:** uTLS made brotli/klauspost reachable, and both were updated after `govulncheck` flagged them.
- **Rust:**
  - `access.rs`: the single resolve entry point;
  - `wireguard.rs`, `vless.rs`, `amnezia.rs`: strict parsers;
  - `split.rs`: split-tunnel policies;
  - `worker_session.rs`: the renamed `outline_session.rs`, now generating every outbound.
- **Split tunneling:** the health probe is pinned to the tunnel so "only" mode cannot report a dead tunnel as connected.
- **Tests:** results are in the verification ledger. The interop tests run against the real upstream implementations.

### Later on November 6: Ghostlink rename, review fixes and release workflow

- **Rename.** The product is now Ghostlink everywhere: binaries, crates, Go module, service, pipe, data paths, `GHOSTLINK_*` variables, TUN interface, worker identity, UI and docs. It has a new ghost icon and a new MSI `UpgradeCode`. Old `MyVPN` state and artifacts are not migrated. Entries below that predate this note were renamed in place, so they describe the same work under the new name.
- **Fixes from the code review.**
  - A failed autoconnect no longer stops the service. This was reproduced first: the old daemon exited at startup and `autoconnect disable` became unreachable.
  - The Linux unit gained `CAP_CHOWN`, which the socket owner change needs.
  - Engine events are audited without waiting for the daemon mutex.
  - OpenVPN forced kills after hold release are flagged `forced_stop_network_cleanup_unverified`.
  - Crash leftovers (`state.pending`, plaintext `run/` configs) are removed at startup.
  - `Session::stop` is cancel-safe.
  - A first connection reports `connecting`, not `reconnecting`.
  - Imports refuse to overwrite an existing ID without `replace`/`--replace`.
  - Access-key fingerprints are salted.
  - MCP waits 75 s like the CLI, and its `vpn_status` wording is corrected.
  - `scripts/cargo.ps1` now detects MSVC by `cl.exe`, because Git for Windows' `link.exe` previously broke every link from Git Bash.
- **Releases.** `.github/workflows/release.yml`, `scripts/build-linux.sh`, `scripts/release-version.mjs` and `docs/development/releases.md` add Windows x64 and Linux x64/arm64 packages and a draft GitHub pre-release on `v*` tags. No tag has been pushed and no release has been created.
- Observed results are recorded in [the verification ledger](docs/development/verification.md).

### Product direction and implemented state

Outline-style UI and standard Outline access keys remain the primary product direction. OpenVPN is optional. The Windows Rust daemon, CLI, restricted MCP bridge and Tauri GUI use the same real local IPC and encrypted storage. Native GUI runs were performed this session, including actual key import followed by CLI confirmation, light/dark views, Settings and server details.

The main change is **a managed Go tunnel worker**, `core/outline-worker`, instead of force-killing the standalone sing-box CLI on Windows. It links unmodified sing-box 1.14.4 libraries, pins Go 1.26.10, and builds as `ghostlink-tunnel.exe`. Explicit stop, parent stdin EOF and termination signals cancel the engine and call bounded upstream `Close()`. Raw engine logs are suppressed; private JSON lifecycle events have fixed error codes. Native TUN startup must observe the actual interface address. The daemon also requires a real proxied HTTPS health check before reporting connected. No proxy-only fixture invents a VPN IP.

Additional changes:

- Rust validates managed-worker version and local proxy/controller listener PID before sending credentials. Temporary plaintext config uses RAII cleanup, including validation failure. Cleanup failure blocks reconnect. Worker rejects an existing interface name or overlapping local address.
- Private Windows directories reject reparse points and unexpected owners before ACL restriction. Windows SCM reports Running after IPC/state readiness and StopPending while stopping.
- UI polling preserves unchanged cards, menus and focus; recovery clears service-unavailable notices. Native QA found clipped menu actions; fixed the overflow and rebuilt/launched to verify all four actions visible. Server details show metadata only.
- MSI packaging installs the GUI, CLI, MCP bridge, worker, notices and automatic LocalSystem service, with one authorized owner SID. User-mode DPAPI state cannot be copied into SYSTEM state; reimport keys through the installed service. WebView2 Runtime is an external prerequisite.
- Added offline Outline server provisioning with distinct private keys/ports, add/list/render/remove, standard server config and exports. Added separate Linux systemd/Ansible deployment; no server deployed. Existing OpenVPN PKI issuance/bundle/revocation was exercised with real OpenSSL.
- Terraform formatting/init (backend disabled)/validate passed; AWS provider lock recorded. No plan/apply/cloud changes. Linux daemon service defaults protect SSH by denying full tunnel until deliberately overridden.
- Added Windows/Linux CI definitions; they have not been run on hosted runners. Android and iOS remain unimplemented, without native toolchains/devices/signing here.

### Verification actually run

See `docs/development/verification.md` for precise limits.

- Rust root workspace: build, **12 unit tests**, fmt and clippy with `-D warnings` passed.
- Actual daemon/CLI/MCP process suite: **14 passed**, including 32 concurrent requests, DPAPI persistence, scoped/revoked agent grants, malformed IPC and credential/config rejection.
- Explicit real-engine suite: **3 passed**. Real HTTP crossed independent encrypted local Shadowsocks peers; wrong password did not reach the live destination. Managed worker listener closed on stop and parent EOF; invalid config cleanup left no plaintext config.
- The Node suite also ran with `GHOSTLINK_TEST_EXPECT_UNPRIVILEGED=1` after checking the shell was unelevated. TUN start failed without pretending connected, disconnect succeeded and temporary config was removed.
- Go interface collision test and vet passed. **2 Python provisioning tests** passed for Outline key isolation/removal and OpenVPN CA/CRL/server-only bundle behavior.
- Native Tauri debug/release GUI launched and inspected. No real Connect button, native VPN permission prompt or UAC was automated.
- Windows optimized binaries and MSI compiled and passed WiX linking/validation. **MSI installation/service elevation/uninstall and full-device routing are not verified.** Linux worker cross-compiles; no Linux Rust/GUI/runtime verification.
- Final optimized binaries passed the same **14 process tests** again after security dependency updates. The rebuilt worker passed all **3 real-engine tests** again. The worker also built from its vendored corresponding-source staging with the published Go flags; its version command succeeded. Vendored build metadata omits module checksums, so its bytes differ from module-cache builds; no byte-identical build claim is made.
- Dependency scan fixed five reachable Go HTTP/2 advisories and then non-reachable module findings; final govulncheck reports no vulnerabilities. JS audit reports zero. Root Rust OpenSSL lock updated to 0.10.82/0.9.118. OSV scans 472 unique Rust package versions; remaining 3 IDs cover glib iterator unsoundness and an unmaintained GTK build dependency. These are Linux GUI dependencies, not compiled on Windows; see `docs/security/dependencies.md`. Do not claim every dependency scan is clean.

### Builds and tooling

Working directory remains `D:\custom vpn`, PowerShell. Git is now initialized on `main`; inspect `git status` and `git log` before committing. `.gitignore` now covers nested Cargo targets, build tools, caches, state, generated keys/tokens, artifacts and vendored worker source. Do not stage private state or binaries.

- Root build wrapper: `./scripts/cargo.ps1` discovers MSVC and pinned local Windows SDK. Rust 1.92 used. Do not replace `$HOME` or `$CODEX_HOME` variables.
- GUI: `apps/desktop/src-tauri/target/{debug,release}/ghostlink-desktop.exe`.
- CLI/service/MCP: `target/{debug,release}/{ghostlink,ghostlinkd,ghostlink-mcp}.exe`.
- Worker: build from `core/outline-worker` with `go build -mod=readonly -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -o ../../target/debug/ghostlink-tunnel.exe .`.
- Independent test peer: `.tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe`; optional OpenVPN: `.tools/openvpn-bin/openvpn.exe`. **The standalone sing-box CLI is no longer accepted as the managed daemon worker.** `--sing-box` is only a legacy flag alias for `--outline-engine`.
- Python: `C:\Users\winya\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`.
- Bootstrap: `scripts/bootstrap-windows.ps1 -IncludeSdk` extracts checksummed official build tools without installing them system-wide.
- Package: `scripts/build-windows.ps1`; vendored corresponding source: `scripts/package-worker-source.ps1`; dependency notices: `python scripts/collect-licenses.py`. Rebuild all three when Go dependencies change.
- Outputs: `artifacts/windows-x64/Ghostlink-0.1.0-windows-x64.msi`, portable ZIP beside it, `artifacts/source/Ghostlink-0.1.0-worker-corresponding-source.zip`, cross-compiled `artifacts/linux-x64/ghostlink-tunnel`. Final hashes are in `artifacts/SHA256SUMS.txt` once packaging is finalized; do not reuse earlier session hashes.

The worker is GPL-3.0-or-later; original Rust/UI is MIT. Corresponding-source archive includes actual vendored Go sources/resources and build instructions. Preserve it with distributed worker binaries. Official Wintun 0.14.1 amd64 bytes match the embedded DLL and its WireGuard LLC signature was valid; prebuilt DLL terms differ from source/wrapper licenses. Microsoft WebView2 SDK static loader also matched official package 1.0.3800.47; SDK and bindings licenses/notices preserved. See licensing notes; complete public-distribution review remains outstanding.

The user-owned `.state-dev` contains no saved profiles after cleanup. Temporary UI fixture `ui-local-test` was removed through CLI after verifying disconnected state. Owned development GUI/daemon processes were stopped for release rebuild. Before starting anything, check current processes; do not kill unrelated VPN software.

### Resume order and remaining requirements

1. Read this section plus verification/security reports. Keep the Outline key flow and real shared daemon intact. Check Git and package timestamps rather than recreating the project.
2. Privileged Windows verification is the next major gate: human-installed MSI on an authorized test machine, owner/other-user IPC authorization, local server full TUN connection, actual route/DNS/IPv6/egress checks, disconnect restoration, worker/daemon crashes, service stop/restart and uninstall. No admin token is available in this session. No automatic UAC or security-prompt bypass.
3. Verify network-change reconnect, sleep/wake, switching, full/split routing, leak behavior and kill-switch recovery with network snapshots and real traffic. Do not convert successful proxy tests into claims about device-wide routes.
4. Linux needs an actual Linux build/runtime environment, GTK dependency advisory resolution, root-private storage/vault review, DEB/RPM packaging and SSH-safe network tests. Only the Go worker was cross-compiled here. Docker is not available; an earlier automatic review rejected launching Docker Desktop, so do not retry that action as a workaround.
5. Finish native GUI narrow-window, service-recovery and tray checks. Mobile requires actual native integration, build projects/toolchains, OS consent, signing/entitlements and device verification. Do not add success stubs or claim completed APK/iOS deliverables.
6. Deployment remains local/offline tooling; no production server, key or cloud credentials were supplied. User requested local test servers for now. Public release also needs licensing review, code signing and tested update/rollback.

## Archived snapshot — October 30

Everything below records the earlier pause. Statements such as “not visually tested”, “no Git”, “no MSI”, or “standalone sing-box process” describe that date and are superseded by the current handoff above.

## 1. What the user wants

The original brief requested a real self-hosted, cross-platform VPN ecosystem, initially based on OpenVPN, with a first-class Rust CLI, privileged local daemon, desktop GUI, mobile apps, deployment tooling, and optional restricted MCP integration. Windows/Linux CLI and client engine were the highest priority. All status must reflect real state; no simulated success or fabricated platform completion.

**Important subsequent clarification, now the primary product direction:**

> “I want to have the UI and features like https://github.com/OutlineFoundation/outline-apps. The user need to use the outline key to access the VPN.”

Consequently, **Outline-compatible access keys and an Outline-style desktop client are now the main user experience**. Outline keys authenticate Shadowsocks, not OpenVPN. Keep the OpenVPN work as an optional backend; do not try to turn an Outline key into an OpenVPN certificate/profile.

The original complete brief is attached at:

`C:\Users\winya\.codex\attachments\a7a2160c-34e7-4a49-8284-fcc1508ca4ec\Pasted text.txt`

Working directory: **`D:\custom vpn`**. Shell: PowerShell. The original workspace was empty.

## 2. Current overall state

We have working, compiled Windows development binaries for:

- Rust CLI: `target\debug\ghostlink.exe` (3,390,976 bytes at pause).
- Rust local daemon: `target\debug\ghostlinkd.exe` (9,080,320 bytes).
- Optional Rust stdio MCP bridge: `target\debug\ghostlink-mcp.exe` (3,181,056 bytes).
- Tauri desktop GUI: `apps\desktop\src-tauri\target\debug\ghostlink-desktop.exe` (14,037,504 bytes).

The GUI and the CLI call the same daemon over OS-restricted IPC. There is no mock backend.

**Do not call the VPN/platform complete.** No real full-device TUN connection or route/DNS restoration was verified. The Windows session is unelevated and the user has not supplied a real access key/server. A real encrypted Shadowsocks proxy traffic test did run successfully without changing OS routes. The desktop app compiled, but was not yet launched or visually verified.

No MSI/release package, Linux package, Android APK/AAB, or iOS binary has been produced. No mobile implementation exists yet. The server deployment files are written but unvalidated and undeployed.

At pause, a process check found **no running `ghostlinkd`, `ghostlink-desktop`, `sing-box`, or `openvpn` processes**. Tests cleaned their temporary state. Do not assume a daemon is still running.

There is **no Git repository initialized in the project root**, and no project commits have been made. The `.upstream` clones have their own Git metadata and are ignored. Before initializing/staging the project, fix ignore rules for nested Tauri build output; see remaining work.

## 3. Architecture decisions already made

### Shared control plane

- Rust workspace containing contracts/IPC client, engine code, daemon, CLI and MCP bridge.
- Tauri desktop is a separate Rust workspace, excluded from the root workspace, so normal CLI/service builds do not require GUI dependencies.
- Newline-delimited JSON IPC, schema version 1, maximum frame 2 MiB, bounded connection count and timeouts.
- Response envelope: `{ "schema_version": 1, "success": true, "data": ... }`; errors use `error.code` and `error.message`. This intentionally uses an envelope rather than the original brief's illustrative flat status object.
- Windows named pipe, default `\\.\pipe\ghostlink`, explicit protected DACL for SYSTEM and one authorized owner SID, remote pipe clients rejected.
- Windows clients use identification-only security QoS and verify the server runs as the current user or SYSTEM.
- Linux Unix-domain socket code uses private socket permissions, configured owner UID, and peer credentials. **Linux implementation is not built/tested here yet.**
- Service state mutations are serialized. Some long operations also hold that mutex; only short concurrent status requests have been tested so far.
- Audit entries use fixed operation/outcome labels, not request payloads or raw engine logs.
- Windows profile/key contents are sealed with **user-scoped DPAPI**, plus private file/directory ACLs. Service identity must remain the same when reading those files. Linux currently uses root-private file storage, not an implemented OS encrypted credential vault.

### OpenVPN backend, implemented before the clarification

- Unmodified external OpenVPN 2 executable, controlled through its documented management interface.
- This was a documented staged deviation from the preferred OpenVPN 3 engine, selected to get the desktop control plane running without inventing protocol/crypto code.
- Engine reverse-connects to a listener created by the daemon. Fresh random management password, private configuration/auth files, no secret process arguments.
- Windows checks the management peer's TCP process ID; Linux uses Unix peer PID.
- Connection state comes from management events. Only `CONNECTED,SUCCESS` with a valid assigned IP sets connected state. Counters come from bytecount events.
- Strict profile allowlist: inline CA/certificate/key; rejects scripts, plugins, nested config, external paths, weak ciphers/TLS, unknown options, and password/encrypted-key profiles that lack a proper vault workflow.
- Certificates are checked for current validity on import and again on connect.
- Original validated input is stored encrypted, then revalidated and canonicalized at each connect. Storing canonical output initially caused revalidation to reject internal directives; that bug was fixed.
- No claim of kill-switch support, leak prevention, or completed Linux resolver integration for this backend.

### Outline-compatible backend, current priority

- Static standard **`ss://`** keys: SIP002 base64 credentials, legacy whole-key base64, percent-encoded plain credentials, IPv6 endpoint syntax, optional human-readable fragment and `outline=1` query.
- Accepted modern AEAD methods: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`.
- **`ssconf://`** dynamic keys: verified HTTPS, public-address checks, DNS resolution pinned to validated addresses, no redirects, 64 KiB response cap. Supports response bodies containing a static `ss://` key or legacy Shadowsocks JSON.
- Advanced Outline YAML transports, prefixes and plugins are **explicitly unsupported**, not silently ignored. Dynamic source is re-fetched on each connect.
- Access keys enter through GUI private IPC or CLI file/stdin. There is no access-key command-line argument and no reveal/export API. Lists/status/audit return metadata only.
- Native tunnel engine is **an unmodified, external sing-box 1.14.4 process**, configured only from typed/validated values. This is Shadowsocks/Outline-key wire compatibility; it does **not** embed the Outline SDK.
- Reason: the inspected Outline SDK sample VPN CLI was Linux-only, while Outline Apps has separate native desktop routing implementations. External sing-box provides a Windows/Linux TUN engine with a clean Rust service boundary. This decision was communicated and documented before implementing it.
- Generated configuration has full IPv4/IPv6 TUN routes, rejects tunneled IPv6, enables strict routing/native DNS hijacking, and uses proxied DNS-over-HTTPS. **Configuration intentions are not independently verified leak-protection results.**
- An authenticated loopback proxy is used for an actual HTTPS health request to `https://www.gstatic.com/generate_204`. The connection is marked connected only after the child reports engine startup and that proxied request returns 204. Periodic checks move state to reconnecting on failure. Counters come from an authenticated loopback controller.
- The reported Outline `vpn_ip` is the configured local TUN address `172.28.85.1`, not the public exit IP or a server-assigned OpenVPN address.
- Linux full-tunnel connections require explicit administrator policy `--allow-full-tunnel`, to avoid unexpectedly replacing routes on an SSH-administered machine.

Read the detailed records:

- `docs\architecture\decision-record.md` — original plan and upstream analysis; its initial environment snapshot predates downloaded local tooling.
- `docs\architecture\outline-access-keys.md` — superseding access-key/product-direction decision.
- `apps\desktop\brand-spec.md` — UI design decisions.

## 4. Source map

| Path | Purpose |
|---|---|
| `Cargo.toml`, `Cargo.lock` | Root Rust workspace and dependency lock |
| `packages/shared-contracts/src/lib.rs` | Typed actions/responses/status, IPC framing/client, agent action restrictions |
| `packages/shared-contracts/response.schema.json` | Stable response-envelope schema |
| `packages/shared-contracts/status.schema.json` | Connection status schema |
| `core/vpn-engine/src/profile.rs` | Strict OpenVPN profile validation and metadata |
| `core/vpn-engine/src/storage.rs` | Private ACL/mode handling, atomic writes, Windows DPAPI |
| `core/vpn-engine/src/management.rs` | Real OpenVPN management worker, lifecycle/status/counters |
| `core/vpn-engine/src/outline.rs` | Outline access-key parsing and safe dynamic resolution |
| `core/vpn-engine/src/outline_session.rs` | Typed sing-box config, process lifecycle, health/counters |
| `core/vpn-engine/tests/outline_traffic.rs` | Real encrypted Shadowsocks traffic test, explicitly ignored unless requested with an engine path |
| `services/vpn-daemon/src/main.rs` | Persistent profiles/keys/defaults/autoconnect, authorization, audit, command dispatch |
| `services/vpn-daemon/src/ipc.rs` | Windows named-pipe / Linux Unix-socket listener |
| `services/vpn-daemon/src/service.rs` | Windows SCM entrypoint; compiled but service install/start not tested |
| `cli/ghostlink/src/main.rs` | CLI commands, JSON/human output, exit codes, connect wait, secret-file issuance |
| `integrations/mcp-server/src/main.rs` | Restricted stdio MCP server with explicit agent token |
| `apps/desktop/ui/` | Original HTML/CSS/JS UI, original monoline app icon |
| `apps/desktop/src-tauri/` | Native Tauri app, tray, IPC command, close-to-tray behavior, separate Cargo lock |
| `tests/integration/control-plane.test.mjs` | Real daemon/CLI/MCP integration tests and JSON schema validation |
| `server/openvpn/pki.py` | OpenSSL-backed offline CA/provision/revoke/CRL/bundle utility; not run yet |
| `server/openvpn/server.conf` | Personal OpenVPN server configuration; not deployed |
| `server/ansible/` | Ubuntu deployment, dedicated NAT table, no host firewall flush; not validated |
| `server/terraform/main.tf` | Initial AWS EC2/EIP/security group draft; currently needs HCL syntax fixes |
| `scripts/cargo.ps1` | Local MSVC/SDK environment wrapper |
| `scripts/generate-icon.ps1` | Generates native PNG/ICO from original Ghostlink icon geometry |
| `package.json`, `package-lock.json` | Node integration-test dependency (Ajv 8.20.0) |
| `upstream.lock.json` | OpenVPN pins; still needs Outline and sing-box entries |

## 5. CLI and MCP behavior already implemented

CLI commands include:

```text
ghostlink profile import FILE [--name ID]
ghostlink profile list
ghostlink profile default ID
ghostlink profile remove ID
ghostlink key add --name ID --file PRIVATE_KEY_FILE
ghostlink key add --name ID --stdin
ghostlink connect [--profile ID] [--no-wait]
ghostlink switch --profile ID [--no-wait]
ghostlink disconnect
ghostlink status
ghostlink info
ghostlink servers list
ghostlink autoconnect enable|disable
ghostlink logs --tail N
ghostlink doctor
ghostlink agent grant --name NAME [--control] --token-file NEW_PRIVATE_FILE
ghostlink agent revoke --name NAME
ghostlink version
```

Global flags: `--json`, `--timeout 1..600`, `--endpoint`, `--agent-token-file`.

- Connect/switch wait for a terminal connection result by default; `--no-wait` returns the actual accepted state, commonly `connecting`.
- CLI interruption does not pretend to cancel an already accepted service operation; inspect status or explicitly disconnect.
- Exit codes: 0 success; 2 input/profile/not-found; 3 permission; 4 unavailable/unsupported engine or daemon; 5 timeout; 6 busy; 1 other failure; 130 interrupted. `doctor` returns 4 when no engine is found even though the diagnostics request itself completed successfully.
- Autoconnect currently means **daemon startup**, not a complete installed boot/login workflow. Explicit disconnect is respected until restart.
- Agent grants are read-only by default. `--control` explicitly authorizes connect/disconnect/switch. Tokens are hashed in daemon state; the one-time issued secret is written by CLI into a new private file and removed from printed output.
- The trusted boundary is the OS owner. A hostile process already running as that same user can call the owner CLI/IPC; agent labels are not a same-user sandbox.

MCP tools: `vpn_list_profiles`, `vpn_status`, `vpn_diagnostics`, and, only with `--allow-control`, `vpn_connect`, `vpn_disconnect`, `vpn_switch`. Daemon token scope still applies. No shell/config-execution tools. Server is stdio only and requires `--token-file`. Protocol versions handled include 2025-11-25, 2025-06-18 and 2024-11-05. Actual initialize/list/call requests through the daemon were tested.

## 6. Desktop UI already implemented

Original Ghostlink branding with Outline-inspired utility layout: teal, neutral background, sidebar, saved-server cards and a prominent add-key dialog. Includes:

- Actual daemon state, connection duration and transfer totals.
- Empty state with no invented servers or statistics.
- Add static/dynamic access key; key field hidden by default, optional show/hide; clears secret input on close/import.
- Search, connect/disconnect/switch, rename, details, choose default, remove confirmation.
- Autoconnect setting and diagnostics.
- Light/dark themes; only theme preference is in localStorage, never access keys.
- Native tray menu: open, disconnect, quit; window close hides to tray.
- Quitting the interface leaves the independent daemon/VPN running; UI About text explains this.
- Restrictive CSP; GUI does not expose daemon agent-grant/revoke or OpenVPN profile-import actions.

**Verification still pending:** native launch, visual inspection at desktop/narrow viewport, actual click-through with the real daemon, console/runtime warnings, keyboard accessibility, tray behavior and service-unavailable recovery. The last work before pausing was preparing for this step; no UI automation was performed yet.

## 7. Environment and downloaded local tooling

Available: Windows x64; Rust 1.92.0 MSVC and GNU toolchains; Git 2.47.1; Node/npm; Go; VS2022 C++ Build Tools at:

`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`

MSVC version: `14.44.35207`. Initially `link.exe` was not on PATH, and a system Windows SDK was absent. This was resolved with **workspace-local official Microsoft NuGet SDK packages**, not a machine-wide install. `scripts/cargo.ps1` sets PATH/LIB/INCLUDE for these files.

Local ignored tooling:

- `.tools\winsdk\` — `microsoft.windows.sdk.cpp.x64` 10.0.28000.2957, libraries.
- `.tools\winsdk-tools\` — `microsoft.windows.sdk.cpp` 10.0.28000.2957, headers and resource compiler.
- `.tools\openvpn-bin\openvpn.exe` — official OpenVPN 2.7.8, extracted from the signed MSI without installing drivers/services.
- `.tools\sing-box\sing-box-1.14.4-windows-amd64\sing-box.exe` — actual external Outline-compatible engine.
- `.tools\sing-box.LICENSE` and engine archive license; no project-wide notice bundle prepared yet.

Downloaded SHA-256 values:

```text
OpenVPN-2.7.8-I001-amd64.msi
1EA61A3056905B90607D4B0F084C04E5CF3043E07CF192D9CD44B0474F29CC49

microsoft.windows.sdk.cpp.x64.10.0.28000.2957.nupkg
7CA47E7345DCBDF36EC4C3C4CD59AB9CB5C9F620A2E785CC4FA641509647CC5A

microsoft.windows.sdk.cpp.10.0.28000.2957.nupkg
F0A200DAE58858F418B30DC9E2F52B4188F97EB7837BD4F73074652A01937DDD

sing-box-1.14.4-windows-amd64.zip
99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF
```

OpenVPN MSI Authenticode status was **Valid**, signer **OpenVPN Inc.** The original `msiexec /a` extraction attempt stalled; that process was stopped, and the MSI cabinet was instead extracted using Windows Installer COM plus `expand.exe`. No driver install was performed. Sing-box archive hash was recorded; an independent release-digest/signature comparison still needs to be added to reproducible bootstrap tooling.

OpenSSL used by integration tests:

`C:\Program Files\Git\usr\bin\openssl.exe` (3.2.3). An additional newer OpenSSL executable is in `.tools\openvpn-bin\`.

Usable Python runtime found, but not yet used for PKI tests:

`C:\Users\winya\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`

Windows session is **not elevated**. Existing Outline TAP and OpenVPN Connect adapters were observed, but **do not assume either driver is appropriate for the new engines or safe to redistribute**.

Docker engine is unavailable. Automatic approval review **blocked launching Docker Desktop**. This was reported to the user; no container network tests ran. WSL lists only Docker Desktop's internal distro, not a general Linux development distro. Do not silently retry the blocked launch or claim Linux runtime verification.

No Android SDK/JDK/Xcode/signing credentials/authorized mobile devices or real VPN server credentials were supplied. No cloud resources were created, no remote server was changed and no external messages were sent.

## 8. Upstream sources inspected

Ignored, shallow clones are available under `.upstream\`:

| Project | Revision |
|---|---|
| OpenVPN 2.7.8 | `dc1f569087135894ac2703aeabd7a960ee9452d4` |
| OpenVPN 3 Core release/3.11.8 | `4f3bdef73245d4ee9e8216c5d65baccc9568f6ef` |
| Outline Apps | `ce518e8c058d4db9100ec27d15bc071a246a2274` |
| Outline SDK | `45e87213a473ff573378eb5f42081f71aff76664` |
| sing-box 1.14.4 (binary-reported revision) | `c005f35300ce76427dc285481ec5695f5b179cd2` |

Read actual upstream license files, OpenVPN management source/options, OpenVPN 3 ClientAPI/TunBuilder documentation, Outline access-key parsers, shared CSS and server-card/access-key-dialog code, desktop VPN/routing code, and sing-box TUN/DNS/Shadowsocks/controller docs.

Licenses observed: OpenVPN 2 GPLv2 with its stated exceptions; OpenVPN 3 MPL-2.0 or AGPL-3.0 with applicable file/exception terms; Outline Apps/SDK Apache-2.0; sing-box GPLv3-or-later with an additional naming/association statement. Ghostlink authored crate manifests currently say MIT, but a full repository license/NOTICE/source-compliance bundle and distribution review remain unfinished. Do not claim distribution strategy is legally guaranteed.

## 9. Tests and builds actually run

### Passed

1. Root Windows workspace `cargo check` and `cargo build` after adding the Outline backend.
2. Tauri Windows debug build: `apps/desktop/src-tauri/target/debug/ghostlink-desktop.exe`.
3. JavaScript syntax check: `node --check apps/desktop/ui/app.js`.
4. Original Rust unit suite: **8 tests passed** before the later Outline additions: framing limits, agent restrictions, profile names/unsafe profiles, management state/counter/auth event parsing, private storage/DPAPI round trip. **New Outline unit tests have been written but the full unit suite has not yet been rerun after adding them.**
5. Latest Node integration suite: **14 passed, 0 failed, 0 skipped**. It launches actual built daemon/CLI/MCP processes and validates JSON with Ajv. Coverage:
   - Real named-pipe IPC and disconnected status schema.
   - Profile import/list/default/persistence and Windows DPAPI storage.
   - Forbidden scripts/plugins/config/weak crypto and path traversal.
   - Malformed/expired certificate rejection.
   - 32 concurrent status commands.
   - Invalid schema/arbitrary command rejection.
   - Explicit agent issuance/scope/audit/revocation.
   - Actual MCP initialization/tool listing/status and denied control tool.
   - Real OpenVPN executable against an unavailable loopback server; no false connected state; disconnect and daemon restart behavior.
   - Stable CLI version/not-found/switch-target error handling.
   - Outline key import/metadata/DPAPI/rename/default/autoconnect/remove.
   - Dynamic-key private-address SSRF rejection, obsolete cipher/plugin rejection, no credentials in error JSON.
6. Explicit real-engine Shadowsocks integration: **1 passed**. Starts a real sing-box Shadowsocks server and real client proxy on loopback; HTTP traverses encrypted transport, controller rejects unauthenticated access and reports real counters; an incorrect key cannot reach a live destination listener.
7. `npm audit` after updating test-only Ajv to **8.20.0**: **0 vulnerabilities reported**. Initial 8.17.1 had a moderate advisory and was replaced.

### Not verified

- Real OS TUN traffic, external Outline server connection or public exit IP.
- Full/split route behavior, DNS/IPv6 leaks, disconnect restoration, crash/kill-switch recovery or adapter cleanup.
- Native GUI runtime/visual/click-through behavior.
- Linux compilation/runtime/packages or systemd integration.
- Windows service installation/start/stop, release builds or MSI installation.
- Python PKI utility, Ansible or Terraform validation/deployment.
- Android/iOS anything, including compilation.
- Full Rust/Tauri dependency advisory scanning, clippy, rustfmt, static analysis and complete license audit.

The Shadowsocks test is **proxy transport verification only**, not the VPN platform definition of done. Test credentials are ephemeral local fixtures, never real access credentials.

## 10. Exact commands for resuming

From PowerShell in `D:\custom vpn`:

```powershell
# Root CLI/service/MCP
./scripts/cargo.ps1 build --workspace
./scripts/cargo.ps1 test --workspace
npm ci --ignore-scripts
npm test

# Real Shadowsocks traffic test (does not modify system routes)
$env:GHOSTLINK_TEST_SING_BOX = 'D:\custom vpn\.tools\sing-box\sing-box-1.14.4-windows-amd64\sing-box.exe'
./scripts/cargo.ps1 test -p ghostlink-engine --test outline_traffic '--' --ignored --nocapture

# Native desktop
./scripts/cargo.ps1 build --manifest-path apps/desktop/src-tauri/Cargo.toml
```

**PowerShell wrapper detail:** quote `'--'` when forwarding Cargo test-harness arguments. An unquoted `--` was consumed by PowerShell and caused Cargo to reject `--ignored`. `scripts/cargo.ps1` uses `$args` to avoid PowerShell interpreting Cargo's `-p` as an ambiguous common parameter.

To run a user-owned development daemon in a terminal (no service installation, no connection until explicitly requested):

```powershell
./target/debug/ghostlinkd.exe `
  --data-dir 'D:\custom vpn\.state-dev' `
  --openvpn 'D:\custom vpn\.tools\openvpn-bin\openvpn.exe' `
  --sing-box 'D:\custom vpn\.tools\sing-box\sing-box-1.14.4-windows-amd64\sing-box.exe'
```

Then, in another terminal:

```powershell
./target/debug/ghostlink.exe status --json
./target/debug/ghostlink.exe doctor --json
./apps/desktop/src-tauri/target/debug/ghostlink-desktop.exe
```

Use a private key file or piped stdin for a real Outline key; **never put the key itself in command arguments, screenshots, logs or this handoff**. Default engine installation paths differ from the local extracted development paths, so pass the explicit flags shown above.

## 11. Next actions, in priority order

1. Read this handoff and the Outline decision record; keep the user's Outline-key UI requirement primary.
2. Run the full current Rust test suite, rustfmt and clippy; fix actual failures. The GUI currently compiles and 14 process integration tests plus one real transport test pass, so preserve that baseline.
3. Launch the compiled GUI with a user-owned dev daemon; inspect actual screens and click through key import, empty/error states, settings, rename/details/remove, light/dark, tray and close behavior. Use no fake connected state or invented servers. Tests can use explicitly identified local fixtures.
4. Add a test for actual Outline session startup failure in an unelevated environment, and review engine startup/shutdown semantics before any production use.
5. Obtain a user-authorized real Outline key/server and administrator-authorized tunnel test environment when the user returns. Do not ask for secrets in chat if a private local file can be used. Verify real routing, external egress, DNS/IPv6 behavior, disconnect restoration and network-change recovery before claiming a working VPN platform.
6. Implement safe Windows service installation and end-user packaging. Add Linux systemd/package scripts and build/CI checks; then test them on Linux. Build a real release package instead of labeling debug executables an installer.
7. Add an Outline self-hosted deployment/key-provisioning path. Existing OpenVPN server tooling does not issue Outline access keys and must not be presented as doing so.
8. Finish README, developer/user setup, security/limitations, licensing/attribution, CI, reproducible dependency/bootstrap scripts and a platform completion report.
9. Fix root `.gitignore` to exclude **nested `**/target/`** and review generated Tauri schema artifacts before Git staging. Initialize Git and commit logical source changes only after checking no PKI/key/state/tool/build files would be included.
10. Mobile apps remain future work requiring native toolchains, signing/entitlements, OS consent and real-device verification. Do not add placeholder/mobile mock code and call it a VPN implementation.

## 12. Known unfinished issues / review checklist

These are pending engineering work, not claims of completed fixes:

- `server/terraform/main.tf` was drafted with semicolon-separated attributes; HCL needs proper multiline syntax. Terraform has not been installed or run. Fix and validate before use.
- Windows Outline engine currently uses forced child termination for a console-less external process; route/DNS cleanup is unverified. Investigate a graceful managed shutdown/native wrapper or rigorously verify adapter-lifetime cleanup before release. The persistent kill switch is unsupported.
- Outline local proxy/controller use fresh random credentials, loopback and ephemeral ports. Unlike OpenVPN's management path, their listeners do not yet have OS PID ownership verification. Review port-reservation race, health-state authenticity, controller/proxy exposure and parent/service-death cleanup.
- Confirm correct sing-box Windows TUN driver/runtime requirements. Existing TAP/DCO adapters do not prove the required runtime is installed. The extracted archive contains `sing-box.exe`, `libcronet.dll` and LICENSE; do not silently distribute an unrelated driver.
- Clean up private `outline.json` and temporary configuration files on every startup/config-check failure, not only successful worker shutdown. Current state directories are private, but lifecycle cleanup needs hardening.
- Check for address/interface-name collisions before assigning the fixed Ghostlink TUN addresses. Do not interfere with another VPN or existing adapter.
- OpenVPN status currently initializes protocol from the first configured remote; mixed per-remote protocols and remote-random selection need accurate reporting or rejection. Do not present planned endpoint/protocol information as observed traffic state.
- OpenVPN Linux DNS integration and encrypted credential workflow are not implemented. Password/encrypted-key profiles are deliberately rejected rather than stored unsafely.
- Full-tunnel leak-protection configuration is not a substitute for actual tests; retain explicit diagnostic `not_tested` fields.
- Agent scope is a restriction on the MCP path, not isolation from other processes running as the trusted OS user. Optional per-operation human confirmation is not implemented in the daemon; client/tool-host policy must be considered.
- GUI refresh polls every 1.5 seconds and may reset card menus while open; inspect/fix actual interaction issues during runtime QA.
- Server import currently accepts replacing an inactive server with the same ID; review intentional UX/idempotency and duplicate-key handling.
- `Cargo.toml` still declares Rust 1.85 as a workspace package value, but builds actually used 1.92 and current locked dependencies may need newer than 1.85. Establish/document a verified minimum rather than advertising an untested one.
- The local SDK bootstrap was performed manually. Create reproducible download/hash/signature validation scripts; don't assume another machine has `.tools`.
- `upstream.lock.json` needs Outline Apps/SDK and sing-box pins added. Licenses/notices currently live mainly in ignored upstream/tool directories; they must be included appropriately before distribution.
- No `README.md`, root `LICENSE`, `LICENSES/` compliance bundle, CI workflows, install scripts or release artifacts exist yet.

## 13. Working style and constraints to preserve

- User prefers autonomous implementation and dislikes unnecessary approval questions. Ask only when access/signing/hardware, administrator privileges, destructive actions or real security decisions require it.
- Continue implementing/building/testing; don't spend the next session only rewriting architecture documents.
- Do not spawn subagents unless the user or applicable instructions explicitly request delegation.
- Keep secrets out of arguments, stdout/status JSON, audit, screenshots, Git and documentation. Agent token issuance is a narrow private IPC-to-file path, not a normal JSON output feature.
- Automatic review blocked Docker Desktop launch. Preserve that boundary and report the container-test limitation honestly.
- Skills read so far: `web-design-engineer` for frontend work; its design checkpoints were superseded by the user's explicit autonomous-build instruction and supplied Outline reference. `computer-use` SKILL.md was read while preparing native GUI QA, but **no computer-use runtime was initialized and no UI automation took place**. Before Windows UI control, read its required `../../docs/guidance.md` and `../../docs/confirmations.md`, then initialize the documented `@oai/sky` runtime. Do not invent helper protocols.
- No background goal/automation/thread was created. Resume only when the user returns and asks to continue.

**Resume checkpoint:** real Windows binaries exist; 14 process integration tests and one real encrypted Shadowsocks proxy test pass; native GUI build passes. Next is full-current-unit/static checks, actual GUI runtime QA, secure engine lifecycle/packaging, then administrator-authorized real VPN testing.
