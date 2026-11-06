# MyVPN

A personal desktop VPN client with an Outline-style interface, standard Outline access keys, a local privileged service, a Rust CLI and an optional restricted MCP bridge.

**Current status:** Windows development/release binaries build; key management, real local IPC, authorization and encrypted Shadowsocks proxy traffic have been tested. Full-device TUN routing, DNS/IPv6 leak behavior and installer execution still need an administrator-authorized Windows test. Linux runtime and mobile apps are not complete. See [the verification report](docs/development/verification.md).

## Install on Windows

Build output: `artifacts/windows-x64/MyVPN-0.1.0-windows-x64.msi`. This unsigned development installer installs the GUI, CLI, MCP bridge, managed tunnel worker, notices and a LocalSystem service. It authorizes one Windows user over a private local named pipe. The service owns encrypted state under `%ProgramData%\MyVPN`; the GUI runs as your normal user. Installing requires Windows administrator consent. Microsoft WebView2 Runtime must already be installed for the GUI.

Open **MyVPN** from the Start menu, choose **Add access key**, paste an `ss://` or supported `ssconf://` key supplied by your server administrator, then choose **Connect**. You can rename servers, inspect their metadata, choose a default and disconnect from the app or CLI. Window close hides to the tray; quitting the GUI leaves the independent VPN service running.

Installation has not been exercised in this development environment. Before installing, disconnect other VPNs and use a machine where a temporary route change is authorized. Do not treat an unsigned development build as a verified public release.

For unattended installation, explicitly authorize the intended user's SID with the MSI property `MYVPN_OWNER_SID`. Never use a broad group SID to authorize every local user. An existing installation's owner is retained during upgrades. See [Windows setup](docs/development/windows.md) for the exact workflow and development commands.

## CLI

```powershell
myvpn --help
myvpn key add --name singapore --file C:\private\singapore-access.txt
myvpn profile list --json
myvpn profile default singapore
myvpn connect --profile singapore --json
myvpn status --json
myvpn switch --profile japan --json
myvpn disconnect --json
myvpn doctor --json
myvpn logs --tail 100
```

The key file contains only the access key. Use `myvpn key add --name singapore --stdin` with redirected input if preferred; the key itself is never a process argument. Routine commands do not prompt for passwords. `connect` waits for an observed connection result; `--no-wait` returns the accepted state. A timeout or interrupted CLI does not cancel an already accepted daemon operation: inspect `status` or explicitly `disconnect`.

`--json`, `--timeout`, `--endpoint` and `--agent-token-file` are global flags. JSON uses a versioned success/error envelope, documented in [the CLI contract](docs/development/cli-contract.md). No access key is returned by list, status, details or logs.

## Supported access keys and engines

- Standard modern-AEAD Shadowsocks `ss://` keys compatible with Outline: SIP002 credentials, legacy base64 keys, percent-encoded plain credentials, named fragments and IPv4/IPv6 endpoints.
- `ssconf://` dynamic HTTPS sources containing a static key or legacy JSON. Private/loopback metadata destinations and redirects are blocked. Advanced YAML transports, prefixes and plugins are explicitly unsupported.
- Optional inline-certificate OpenVPN profiles via `myvpn profile import file.ovpn`. OpenVPN Community is separately installed. Scripts, plugins, external file references, weak options, password-auth profiles and encrypted-key profiles without a supported vault workflow are rejected.

The managed Outline-compatible worker links pinned, unmodified sing-box libraries. It uses the standard Shadowsocks protocol; MyVPN implements no new encryption protocol. The worker receives a stop over a private inherited pipe and calls the engine's graceful close. Parent-pipe EOF also closes it. Native interface observation and a successful proxied HTTPS health request are required before the daemon reports `connected`. This does not independently certify all application routes or leak prevention.

## Build and test

Windows requirements: Rust 1.92+, MSVC C++ Build Tools and Windows SDK, Go (the pinned Go 1.26.10 toolchain downloads through Go), Node.js and WebView2 Runtime. Install test-only JS dependencies with `npm ci --ignore-scripts`.

```powershell
./scripts/bootstrap-windows.ps1 -IncludeSdk
./scripts/cargo.ps1 build --locked --workspace
Push-Location core/outline-worker
go build -mod=readonly -trimpath -tags with_gvisor -o ..\..\target\debug\myvpn-tunnel.exe .
Pop-Location
./scripts/cargo.ps1 test --locked --workspace
npm test
./scripts/cargo.ps1 build --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
```

The bootstrap extracts pinned, checksummed build tools into `.tools`; it does not install drivers or services. With a complete system SDK you can omit `-IncludeSdk`. Build packaging with `scripts/build-windows.ps1` after collecting notices using `python scripts/collect-licenses.py`. Produce the worker corresponding-source bundle with `scripts/package-worker-source.ps1`; keep it with any distributed worker binaries.

The optional real-engine tests are explicitly enabled with the executable paths described in [the verification report](docs/development/verification.md). They use isolated local servers and do not replace full-device tunnel testing.

## Agents and MCP

```powershell
myvpn agent grant --name assistant --token-file C:\private\myvpn-assistant.token
myvpn-mcp --token-file C:\private\myvpn-assistant.token
```

This grants read access. Add `--control` when issuing the grant and `--allow-control` when starting the MCP bridge to expose connect/disconnect/switch. The daemon still enforces token scope. Revocation: `myvpn agent revoke --name assistant`. The token is written into a new private file and omitted from command output. Never paste it into a chat or put it in a process argument.

The tool host can ask for confirmation before state changes. MyVPN does not yet implement a daemon approval queue. Trusted-user processes share the OS user's authority; this is not a sandbox against a hostile process running as the same user. See [the security model](docs/security/model.md).

## Hosting and other platforms

The [Outline-compatible server path](docs/deployment/outline-server.md) generates separate private access keys and a standard Shadowsocks server configuration, with an unprivileged Linux systemd/Ansible deployment. The optional OpenVPN path has a separately tested offline CA/issuance/revocation tool. These deployments are distinct. No cloud instance or production server has been created.

Linux source includes Unix IPC and privilege policy, but runtime/package verification is pending. Android and iOS implementations are pending; no APK, AAB or Xcode project is claimed complete. The [development journey](devjourney.md) records decisions, tested results and continuation steps.

Original MyVPN Rust/UI code is MIT; the separate Go tunnel worker is GPL-3.0-or-later. Dependencies and embedded signed drivers retain their terms. Read [NOTICE.md](NOTICE.md) and [licensing notes](docs/security/licensing.md) before redistribution.
