<p align="center"><img src="apps/desktop/ui/mark.svg" alt="" width="72" height="72"></p>

<h1 align="center">Ghostlink</h1>

<p align="center">A personal, self-hosted VPN for Windows and Linux: one app to run your own server and to connect to it.<br>Outline, WireGuard, AmneziaWG and VLESS-REALITY, with split tunneling, per-user traffic rules and a scriptable CLI.</p>

<p align="center"><a href="https://github.com/winyannainghtut/GHOSTLINK/actions/workflows/desktop.yml"><img src="https://github.com/winyannainghtut/GHOSTLINK/actions/workflows/desktop.yml/badge.svg" alt="CI"></a> <a href="CHANGELOG.md">Changelog</a> · <a href="docs/development/verification.md">What is verified</a> · <a href="docs/security/model.md">Security model</a></p>

> **Pre-release.** Builds are unsigned and intended for personal use and testing. Key handling, the local service, every protocol's encrypted traffic and split-tunnel routing are tested automatically. A full-device VPN session (routes, DNS and IPv6 leak checks) still needs an administrator test machine. See [what is verified](docs/development/verification.md).

## Contents

- [Features](#features)
- [Download and install](#download-and-install)
- [Quick start](#quick-start)
- [Supported keys](#supported-keys)
- [Split tunneling](#split-tunneling)
- [Command line](#command-line)
- [AI agents and MCP](#ai-agents-and-mcp)
- [How it works](#how-it-works)
- [Security and privacy](#security-and-privacy)
- [Running your own server](#running-your-own-server)
- [Building from source](#building-from-source)
- [Status and roadmap](#status-and-roadmap)
- [Documentation](#documentation)
- [License and acknowledgements](#license-and-acknowledgements)

## Features

- **Five ways to connect:** Outline-compatible Shadowsocks, WireGuard, AmneziaWG (obfuscated WireGuard, legacy and 2.0), VLESS with REALITY, and optional OpenVPN.
- **Paste or import any key:** `ss://`, `ssconf://`, `vless://`, Amnezia `vpn://`, and WireGuard/AmneziaWG `.conf` files.
- **Split tunneling:** send listed sites, IP ranges or apps around the VPN (bypass), or only those through it, and keep LAN devices direct. Set it globally or per server.
- **One service, three front ends:** the desktop app, the `ghostlink` CLI and an optional restricted MCP bridge for AI agents all control the same local service.
- **Your own server, Outline-style:** install one `.deb`/`.rpm` on a Linux machine with Docker (the image is inside the package), paste the management key it prints into the app, then create users and keys and set traffic rules from **Servers I run** or `ghostlink server`.
- **Server traffic rules:** block sites, IP ranges, ports, BitTorrent or outgoing mail for everyone or per user; data limits and usage per user; local networks and the server itself are always off-limits to VPN users.
- **Server monitoring:** live speed per user, who is online, traffic types (web, video/QUIC, calls, BitTorrent…), protocols used, optional top services, connection addresses and server health. History rotates itself so it never fills the disk.
- **Three ways to manage your server:** the app, `sudo ghostlink-server …` commands on the server (with QR codes in the terminal and a live `top`), or a web dashboard on its own port (private behind an SSH tunnel by default).
- **Easy sharing:** QR codes for every key and a one-page connection kit per person, for the Outline, WireGuard, AmneziaVPN and v2ray-family apps on any phone.
- **Honest status:** "Connected" means the tunnel was observed up and an HTTPS request through it succeeded. Nothing is reported that was not measured.
- **Safe imports:** script hooks, plaintext VLESS, insecure TLS, obsolete ciphers and Amnezia "full access" keys that carry an SSH login are refused.

## Download and install

Pre-release builds are attached to [GitHub Releases](https://github.com/winyannainghtut/GHOSTLINK/releases) once published. Check every download against `SHA256SUMS.txt`.

| Platform | File | Contents |
|---|---|---|
| Windows 10/11 x64 | `Ghostlink-<version>-windows-x64.msi` | Desktop app, CLI, MCP bridge, tunnel worker and the `Ghostlink` service |
| Windows 10/11 x64 | `Ghostlink-<version>-windows-x64-portable.zip` | The same programs, without installing the service |
| Linux x64 / arm64 (Debian, Ubuntu) | `ghostlink_<version>-1_<amd64\|arm64>.deb` | CLI, service, MCP bridge and tunnel worker (no desktop app yet) |
| Linux x64 / arm64 (Fedora, RHEL family) | `ghostlink-<version>-1.<x86_64\|aarch64>.rpm` | The same, as an RPM |
| Linux x64 / arm64 (any) | `ghostlink-<version>-linux-<arch>.tar.gz` | The same files for a manual install |
| Server, Debian/Ubuntu (x64, arm64) | `ghostlink-server_<version>-1_<amd64\|arm64>.deb` | The Ghostlink server with its Docker image included ([guide](docs/deployment/ghostlink-server.md)) |
| Server, Fedora/RHEL family (x64, arm64) | `ghostlink-server-<version>-1.<x86_64\|aarch64>.rpm` | The same, as an RPM |
| Source | `Ghostlink-<version>-worker-corresponding-source.zip` | GPL source of the tunnel worker and the server |

**Windows.** Install [Microsoft WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) if it is not already present, then run the MSI. It needs administrator consent and installs a LocalSystem service that only your Windows account may control. For an unattended install, pass the intended user's SID as `GHOSTLINK_OWNER_SID` ([details](docs/development/windows.md)). Open **Ghostlink** from the Start menu or the desktop shortcut. Windows SmartScreen warns about unsigned builds. Use v0.3.1 or later on Windows: in earlier installers, the app could not reach the installed service.

**Linux.** Install the package for your distribution with `sudo`. It sets you as the owner and starts the `ghostlinkd` service:

```sh
sudo apt install ./ghostlink_<version>-1_amd64.deb       # Debian / Ubuntu
sudo dnf install ./ghostlink-<version>-1.x86_64.rpm      # Fedora / RHEL family
ghostlink status
```

Full-tunnel routing is off on Linux until you add `GHOSTLINK_FLAGS=--allow-full-tunnel` to `/etc/ghostlink/ghostlinkd.env` and restart the service. Protect your SSH access first if the machine is remote. The `.tar.gz` contains the same files plus an `INSTALL.txt` for a manual install ([details](docs/development/linux.md)).

## Quick start

1. Open **Ghostlink** and choose **Add access key**.
2. Paste the key your server owner gave you, or choose **Import a file…** for a WireGuard/AmneziaWG `.conf`.
3. Choose **Connect**. The card shows the protocol, and the panel shows time connected and traffic.

Closing the window keeps Ghostlink in the tray, and the VPN service keeps running. Use **Disconnect** to stop the VPN.

## Supported keys

| Protocol | Import | Notes |
|---|---|---|
| Shadowsocks (Outline) | `ss://`, `ssconf://` | Modern AEAD ciphers only. Dynamic `ssconf://` keys are fetched over verified HTTPS from public hosts, with no redirects. |
| VLESS | `vless://`, Amnezia XRay `vpn://` | REALITY (or TLS) over TCP, with XTLS Vision. Plaintext, insecure TLS, `xhttp` and mKCP are refused. |
| WireGuard | `.conf`, Amnezia `vpn://` | One peer per file. Limited `AllowedIPs` become a split tunnel. |
| AmneziaWG | `.conf`, Amnezia `vpn://` | Legacy and 2.0 parameters (junk packets, header ranges, I1–I5 signature packets, header protection). |
| OpenVPN | `.ovpn` via CLI | Optional, using a separately installed OpenVPN Community. Inline certificates only, strict allowlist. |

`PostUp`/`PreUp` hooks, `Table`, `FwMark` and unknown settings in `.conf` files are rejected. Keys are encrypted by the service (Windows DPAPI) and never shown again in lists, status or logs.

## Split tunneling

Open **Settings → Split tunneling** for all servers, or choose **Split tunneling** in a server's **⋮** menu to override it for that server.

- **Everything uses the VPN** is the default.
- **Bypass**: listed sites (with their subdomains), IP ranges and apps go direct; everything else uses the VPN.
- **Only listed items use the VPN**: the reverse.
- **Keep local network devices off the VPN**: printers, NAS boxes and the like stay reachable.

Changes apply the next time you connect. Sites are matched by name (TLS SNI, HTTP Host, QUIC and DNS), so an app that hides the name, for example with ECH or hard-coded IPs, can still use the VPN. Bypassed traffic deliberately leaves the tunnel. The connection health check always goes through the VPN, so a broken tunnel can never be reported as connected. OpenVPN profiles ignore split tunneling.

## Command line

The CLI talks to the same service as the app. Keys are read from a file or stdin, never from a command argument.

| Task | Command |
|---|---|
| Add a key | `ghostlink key add --name tokyo --file tokyo.txt` (or `--stdin`; `--replace` to overwrite) |
| Import a `.conf` / `.ovpn` | `ghostlink profile import home.conf --name home` |
| List, set default, remove | `ghostlink profile list` · `profile default tokyo` · `profile remove tokyo` |
| Connect, switch, disconnect | `ghostlink connect --profile tokyo` · `switch --profile home` · `disconnect` |
| Status and diagnostics | `ghostlink status` · `info` · `doctor` · `logs --tail 100` |
| Split tunneling | `ghostlink split set --mode bypass --site netflix.com --ip 192.168.1.0/24 --app steam.exe --lan-direct` · `split show` · `split clear` (add `--profile NAME` for one server) |
| Start-up connection | `ghostlink autoconnect enable` / `disable` |
| Manage your server | `ghostlink server add --name home --key-file key.json` · `server users add --server home --name Alice` · `server keys create --server home --user 1 --protocol amneziawg --import alice` · `server rules set --server home --block-site ads.example` · `server usage --server home` (`ghostlink server install-help` for setup) |
| Monitor and share | `ghostlink server live --server home` · `server stats --server home --user 1 --range 7d` · `server clients --server home` · `server keys qr --server home --user 1 --key 2` · `server keys kit --server home --user 1 --output alice.html` |

Add `--json` for a versioned machine-readable envelope ([CLI contract](docs/development/cli-contract.md)). `connect` waits until the tunnel is verified; `--no-wait` returns immediately. Exit codes: 0 ok, 1 connection/internal failure, 2 invalid input, 3 permission denied, 4 service or engine unavailable, 5 timeout, 6 busy, 130 interrupted.

## AI agents and MCP

```powershell
ghostlink agent grant --name assistant --token-file C:\private\assistant.token
ghostlink-mcp --token-file C:\private\assistant.token
```

A grant is read-only: profiles, status and diagnostics. Add `--control` to the grant **and** `--allow-control` to the bridge to allow connect, disconnect and switch. Agents can never import keys, change split tunneling, manage servers or issue grants. Revoke with `ghostlink agent revoke --name assistant`. Tokens are written to a new private file and never printed. A token limits what an agent can ask the service to do; it is not a sandbox against other programs running as your user.

## How it works

```mermaid
flowchart LR
  GUI[Desktop app] --> IPC[Private local IPC]
  CLI[ghostlink CLI] --> IPC
  MCP[MCP bridge] --> IPC
  IPC --> D[ghostlinkd service<br/>keys, policy, audit]
  D --> W[ghostlink-tunnel worker<br/>sing-box + amneziawg-go]
  D -. optional .-> O[OpenVPN 2]
  W --> S[(Your server)]
  D -- pinned HTTPS, management key --> S
```

- **Unprivileged front ends.** The app, CLI and MCP bridge run as you; only the service holds network privileges.
- **One tunnel engine.** The managed worker links unmodified [sing-box](https://github.com/SagerNet/sing-box) 1.14.4 for the TUN adapter, routing, DNS, Shadowsocks, VLESS and WireGuard, and unmodified [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) for AmneziaWG. Ghostlink implements no encryption of its own.
- **Lifecycle.** The service generates each tunnel's configuration privately, verifies it, starts the worker and stops it gracefully. If the service dies, the worker shuts down on its own.
- **Your server.** `ghostlink-server` runs the same unmodified engines in a hardened container, with an HTTPS management API. The service talks to it with the certificate pinned inside the TLS handshake, so the secret API path never reaches anyone else.

More: [protocol design](docs/architecture/protocols.md) · [architecture record](docs/architecture/decision-record.md).

## Security and privacy

- **Local control:** a named pipe (Windows) or Unix socket restricted to SYSTEM/root and the one authorized user. Clients check who created the pipe before sending anything.
- **Credentials:** encrypted at rest. Keys never appear in process arguments, lists, status or audit logs, and agent fingerprints are salted. Server management keys are sealed the same way and are owner-only.
- **Imports:** strict allowlist parsing everywhere; no imported setting can run a command.
- **Network health:** "connected" requires an observed tunnel interface and a successful HTTPS check through it. A cleanup failure blocks the next connection until it is investigated.
- **Not yet provided:** a persistent kill switch, an approval queue for agent actions, and signed builds.

Details: [security model](docs/security/model.md) · [dependency scans](docs/security/dependencies.md) · [licensing](docs/security/licensing.md).

## Running your own server

**The Ghostlink server** (v0.3.0) runs AmneziaWG, WireGuard, VLESS-REALITY and Shadowsocks in one hardened Docker container on Linux (x64 or arm64). The package carries the image, so nothing is downloaded from a registry:

```sh
sudo apt install ./ghostlink-server_<version>-1_amd64.deb      # or: sudo dnf install ./ghostlink-server-<version>-1.x86_64.rpm
sudo ghostlink-server show-key                               # prints the management key again
```

Paste the key into **Servers I run → Add server** (or `ghostlink server add`). You can also manage everything on the server itself (`sudo ghostlink-server users`, `key add`, `top`…) or in its web dashboard (`sudo ghostlink-server dashboard`). From there:
- **Users:** add users, with optional data limits.
- **Keys:** issue keys per protocol. You can copy them, share a `.conf` for WireGuard/AmneziaWG apps, or use one on this device.
- **Rules:** block sites, IPs, ports, BitTorrent or outgoing mail for everyone or for one user.
- **Usage and monitoring:** see live speeds, who is online, data used, traffic types and, if you turn it on, each user's top services.
- **Sharing:** show a key's QR code, or save a connection kit page for each person.

Upgrading the package keeps everything. Full guide: [Ghostlink server](docs/deployment/ghostlink-server.md).

Also available: [an Outline-compatible Shadowsocks server](docs/deployment/outline-server.md) generated offline and deployed with systemd/Ansible, and an optional OpenVPN PKI tool.

## Building from source

**Windows** needs Rust 1.92+, MSVC Build Tools with the Windows SDK, Go (the pinned 1.26.10 toolchain downloads automatically), Node.js and WebView2 Runtime.

```powershell
./scripts/bootstrap-windows.ps1 -IncludeSdk          # pinned WiX (+ SDK); installs nothing system-wide
./scripts/cargo.ps1 build --locked --workspace
Push-Location core/outline-worker
go build -mod=readonly -trimpath -tags with_gvisor,with_utls,with_wireguard -o ..\..\target\debug\ghostlink-tunnel.exe .
Pop-Location
./scripts/cargo.ps1 build --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
./scripts/build-windows.ps1                           # optimized MSI + portable ZIP
```

**Linux** needs Rust, Go, `pkg-config` and `libssl-dev`, plus [nfpm](https://nfpm.goreleaser.com/) 2.48 for packages (`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0`). Run `bash scripts/build-linux.sh` to produce the client `.tar.gz`, `.deb` and `.rpm`, and `bash scripts/build-linux-server.sh` (also needs Docker) for the server image and its `.deb`/`.rpm`, all under `artifacts/linux-<arch>/`.

**Tests.**

```powershell
./scripts/cargo.ps1 test --locked --workspace         # Rust unit tests
npm ci --ignore-scripts; npm test                      # service/CLI/MCP process tests
cd core/outline-worker; go test -tags with_gvisor,with_utls,with_wireguard ./...   # engine + interop
```

Real-engine traffic tests are opt-in and need the built worker; see the [verification ledger](docs/development/verification.md). Releases are built by GitHub Actions from a `v<version>` tag ([release process](docs/development/releases.md)).

## Status and roadmap

| Area | Status |
|---|---|
| Windows app, service, CLI, MCP | Built and packaged (MSI); installer and full-device routing need an administrator test |
| Protocols | Shadowsocks, VLESS-REALITY, WireGuard, AmneziaWG: encrypted traffic tested against upstream implementations. OpenVPN: optional |
| Split tunneling | Routing rules tested in the real engine; app matching and full-device behavior need an elevated test |
| Linux | CLI/service/worker build and tests pass in CI; release CI installs the `.deb` and checks the service runs; a full VPN session is not yet verified on a real host; no desktop app yet |
| Ghostlink server, management, monitoring | Server API, rules, limits, monitoring and all four protocols tested end to end with real clients; server commands and dashboard tested; release CI installs the server `.deb` with Docker and exercises API, commands and dashboard; a real internet-facing VPS deployment is not yet verified |
| macOS, Android, iOS | Not started |

The [changelog](CHANGELOG.md) lists what each release changed.

## Documentation

| Topic | Document |
|---|---|
| What changed | [CHANGELOG.md](CHANGELOG.md) |
| What is verified | [docs/development/verification.md](docs/development/verification.md) |
| CLI / IPC contract | [docs/development/cli-contract.md](docs/development/cli-contract.md) |
| Windows and Linux setup | [windows.md](docs/development/windows.md) · [linux.md](docs/development/linux.md) |
| Releases | [docs/development/releases.md](docs/development/releases.md) |
| Protocol design | [docs/architecture/protocols.md](docs/architecture/protocols.md) |
| Security, dependencies, licensing | [model.md](docs/security/model.md) · [dependencies.md](docs/security/dependencies.md) · [licensing.md](docs/security/licensing.md) |
| Ghostlink server | [docs/deployment/ghostlink-server.md](docs/deployment/ghostlink-server.md) |
| Offline Outline-compatible server | [docs/deployment/outline-server.md](docs/deployment/outline-server.md) |
| Developer / AI-agent handover | [agent.md](agent.md) · [devjourney.md](devjourney.md) |

## License and acknowledgements

Ghostlink's Rust service, CLI, MCP bridge and desktop UI are [MIT](LICENSE). The separate tunnel worker and the Ghostlink server (`core/outline-worker`) link GPL-3.0-or-later sing-box and are GPL-3.0-or-later; their corresponding source is published with every release. Dependencies and embedded drivers keep their own terms; see [NOTICE.md](NOTICE.md) and [licensing notes](docs/security/licensing.md).

Ghostlink builds on [sing-box](https://github.com/SagerNet/sing-box), [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go), [Wintun](https://www.wintun.net/), [Tauri](https://tauri.app/) and others, and is compatible with keys from [Outline](https://getoutline.org/) and [Amnezia](https://amnezia.org/). It is an independent project, not affiliated with or endorsed by any of them. "WireGuard" is a registered trademark of Jason A. Donenfeld.
