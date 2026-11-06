# Changelog

All notable changes to Ghostlink. Versions follow [semantic versioning](https://semver.org/); pre-1.0 releases are unsigned pre-releases. The release workflow copies a version's section into its GitHub release notes.

## [Unreleased]

## [0.3.1] - 2026-11-06

### Fixed

- **Windows: the app and CLI could not reach the installed service.**
  - **Symptom:** after installing the MSI, every request failed with "Cannot reach the authorized local Ghostlink service".
  - **Cause:** before talking to the service, the client checks who is serving its pipe, so a fake service cannot receive your keys. It did that by opening the service process's token, and Windows does not let a standard user open a SYSTEM process's token.
  - **Fix:** the client now checks the pipe's owner, which any client may read. It must be SYSTEM, Administrators (the owner a SYSTEM service gives its objects) or your own account, and an ordinary process cannot fake any of these.
  - **Testing:** development tests ran the service as the same user, which hid this.
- **Windows: the Start-menu shortcut had no icon.** Windows Installer shows an icon on these shortcuts only when the icon's ID ends in `.ico`.
- **Windows: no desktop shortcut.** The MSI now adds a desktop shortcut too.

## [0.3.0] - 2026-11-06

### Added

- **Ghostlink server**, Outline-style.
  - **What it runs:** AmneziaWG (2.0), WireGuard, VLESS-REALITY and Outline-compatible Shadowsocks in one hardened Docker container.
  - **Packages:** `ghostlink-server` `.deb` and `.rpm` for x64 and arm64, with the image inside, so no registry is needed.
  - **First install:** prints a management key.
  - **Upgrades:** keep users, keys and rules.
  - **Admin command:** `ghostlink-server` on the host (`setup`, `show-key`, `status`, `logs`, `restart`, `stop`, `remove`).
- **Users and keys:**
  - users with data limits and usage counters;
  - keys per protocol: `ss://`, `vless://`, `.conf`, and Amnezia-format `vpn://` for WireGuard and AmneziaWG;
  - disable a user, reset usage.
- **Server traffic rules:**
  - block sites, IP ranges, ports, BitTorrent and outgoing mail, for everyone or per user;
  - exempt a user from the rules for everyone;
  - always-on blocks for loopback, private, link-local, CGNAT, multicast and cloud-metadata destinations, the API port and the server's own IP;
  - all DNS is answered by the server, so site blocks hold.
- **Manage servers from Ghostlink:**
  - **App:** a new **Servers I run** view with users, keys (copy, copy `.conf`, use on this device), rules, usage and server settings;
  - **CLI:** `ghostlink server add|list|remove|info|set|users|keys|rules|usage|install-help`;
  - **Security:** the management key is sealed in the service, and the certificate is pinned inside the TLS handshake (TLS 1.3, rustls);
  - **While connected:** management calls go around the tunnel and never block the service.
- Process test with a real local `ghostlink-server` covering every management action, plus server tests with unmodified clients for all four protocols.
- Release CI builds the server image natively on x64 and arm64. It installs the server `.deb` with Docker, then checks the certificate pin, the API, key creation, container hardening, upgrade and purge.

### Fixed

- **AmneziaWG crash on disconnect (Linux CI, any OS):**
  - **What happened:** a peer could write one last packet into the userspace network stack after it was closed, crashing the worker during a graceful stop.
  - **Server impact:** the server would have hit the same race on every configuration change.
  - **Fix:** the TUN adapter now refuses writes once closing starts, and waits for writes already in flight.
- **Corresponding source:** the zip now contains the whole Go module (it lacked `internal/awg` in v0.2.0 and v0.2.1, so it could not build). The packaging script builds from the staged copy before zipping, and uses `/` in zip paths.
- **Debian unit path:** the client `.deb` installs its systemd unit under `/lib/systemd/system`, so `apt purge` no longer warns about `/usr/lib/systemd/system`.

### Changed

- The worker and server share one version constant (`core/outline-worker/internal/version`), which the release check reads.

## [0.2.1] - 2026-11-06

### Added

- **Linux `.deb` and `.rpm` packages** (x64 and arm64), alongside the `.tar.gz`:
  - they install to `/usr/bin` and `/usr/lib/ghostlink`, with the systemd unit in `/usr/lib/systemd/system`;
  - the installer fills in `GHOSTLINK_OWNER_UID` from the user who ran `sudo` and starts the service;
  - upgrades keep your settings;
  - removing the package stops the service, and `apt purge` also deletes saved servers and keys.
- **`GHOSTLINK_FLAGS`** in `/etc/ghostlink/ghostlinkd.env` passes extra service flags. Set `GHOSTLINK_FLAGS=--allow-full-tunnel` to enable full-tunnel routing on Linux without a systemd override.
- **Release smoke test:** CI installs the `.deb` on Ubuntu (x64 and arm64), checks the service runs and answers `ghostlink status`/`doctor`, then purges it. It also inspects the `.rpm`.

### Fixed

- **Linux:** the tunnel worker now ignores `SIGPIPE`. Previously, if the service's end of its status pipe had closed (for example after a service crash), the worker's next status write could kill it before its graceful shutdown finished, which could leave routes behind.
- The real-engine tests keep draining worker output, wait for the tunnel to come up before checking split-tunnel routing, and run one at a time in CI. They failed on GitHub's Linux runners for v0.2.0.

### Documentation

- Rewrote the README.
- Added this changelog and a protocol design note.
- GitHub release notes now include the version's changelog section.

## [0.2.0] - 2026-11-06

### Added

- **WireGuard** and **AmneziaWG** connections (legacy and 2.0 obfuscation: junk packets, S1–S4, header ranges, I1–I5, header protection), from `.conf` files or Amnezia `vpn://` keys.
- **VLESS with REALITY** (and TLS), including XTLS Vision, from `vless://` links or Amnezia XRay keys.
- **Amnezia `vpn://` import** for AmneziaWG, WireGuard and XRay connection keys.
- **Split tunneling**: bypass or "only these" by site, IP range or app, plus a keep-LAN-direct option. Set globally or per server, in the app (Settings and each server's menu) or with `ghostlink split show|set|clear`.
- Desktop app: **Import a file…** for `.conf` files, protocol badges on server cards, and a calm style for success messages.
- Interop tests against upstream amneziawg-go, a stock WireGuard client and a sing-box REALITY server, plus end-to-end traffic tests through the real worker.

### Changed

- The tunnel worker identifies as `Ghostlink tunnel worker 0.2.0; sing-box 1.14.4; amneziawg-go 3.1.20260828` and builds with `with_gvisor,with_utls,with_wireguard`.
- The connection health check is pinned to the tunnel and sniffing runs first, so DNS hijacking and site rules see protocol and site names.

### Security

- `.conf` script hooks (`PreUp`/`PostUp`/`PreDown`/`PostDown`), `Table`, `FwMark`, unknown keys and `AdvancedSecurity = on` are rejected.
- Plaintext VLESS, insecure TLS and `xhttp`/mKCP transports are refused.
- Amnezia "full access" keys that carry the server's SSH login are refused, and the credential is never stored or echoed.
- `vpn://` decompression is capped at 1 MiB.
- Updated `github.com/andybalholm/brotli` (1.2.7) and `github.com/klauspost/compress` (1.20.2) after `govulncheck` found advisories newly reachable through uTLS.

### Fixed

- The release version check pointed at a renamed source file and would have failed the release build.

## [0.1.0] - 2026-11-06

### Added

- Ghostlink (renamed from MyVPN): new ghost icon, binaries `ghostlink`, `ghostlinkd`, `ghostlink-mcp` and `ghostlink-tunnel`, `GHOSTLINK_*` variables and a new MSI upgrade code.
- Release workflow: Windows x64 MSI and portable ZIP, Linux x64/arm64 archives, the GPL worker source bundle, checksums and a draft pre-release on `v*` tags.

### Fixed

- A failed autoconnect at start-up no longer stops the service.
- The Linux service unit gains `CAP_CHOWN`.
- Engine events no longer stall the service's main loop.
- OpenVPN forced kills are flagged as unverified cleanup.
- Crash leftovers are removed at start-up.
- Imports refuse to overwrite an existing server without `--replace`.
- Access-key fingerprints are salted.
- Build-script fixes for Git Bash (`link.exe`) and paths with spaces.

[Unreleased]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/winyannainghtut/GHOSTLINK/releases/tag/v0.1.0
