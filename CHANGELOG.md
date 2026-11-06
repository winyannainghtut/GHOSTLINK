# Changelog

All notable changes to Ghostlink. Versions follow [semantic versioning](https://semver.org/); pre-1.0 releases are unsigned pre-releases. The release workflow copies a version's section into its GitHub release notes.

## [Unreleased]

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

[Unreleased]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/winyannainghtut/GHOSTLINK/releases/tag/v0.1.0
