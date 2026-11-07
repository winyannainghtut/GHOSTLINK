# Changelog

All notable changes to Ghostlink. Versions follow [semantic versioning](https://semver.org/); pre-1.0 releases are unsigned pre-releases. The release workflow copies a version's section into its GitHub release notes.

## [Unreleased]

## [0.8.0] - 2026-11-08

### Added

- **Speed limits per client.** One cap per client in bytes per second (for example 2 MB/s), for download and upload alike, shared by all of the client's keys and devices.
  - **Default for everyone:** an optional server default applies to every client without a limit of its own. A client can also have **no limit**, whatever the default.
  - **Live:** a change applies within a second to open connections, with no engine restart and nobody disconnected.
  - **Every protocol:** Shadowsocks, VLESS, WireGuard and AmneziaWG are paced in the server's relay loop, a token bucket per client and direction. IKEv2/IPsec sessions are policed by the IPsec component's firewall (`hashlimit` rules on each session's address, shared by a client's sessions).
  - **Everywhere you manage the server:**
    - the client's Settings, New client and Server settings in the app and the dashboard, plus a chip on client cards and a column in the list;
    - `sudo ghostlink-server user speed NAME 2MB|none|default`, `user add --speed`, `set --speed-limit` and a SPEED column in `users`;
    - `ghostlink server users add|update --speed-limit MB/s|none|default` and `ghostlink server set --default-speed-limit MB/s|none`;
    - the API: `speed_limit_bps` and `effective_speed_limit_bps` on users, `default_speed_limit_bps` on the server.
- **Move from Outline.** `install-server.sh --migrate-outline` (or `sudo ghostlink-server migrate-outline`) takes over an Outline server on the same machine. Guide: [docs/deployment/migrate-from-outline.md](docs/deployment/migrate-from-outline.md).
  - **Clients:** every access key becomes a client with the same password, port and cipher, so the `ss://` keys people already use keep working. Names, data limits (per key or Outline's default), paused keys, the server's name and its address come along.
  - **Ports:** keys on other ports than the main one keep theirs, each extra port with its own Shadowsocks listener. Ghostlink's VLESS, WireGuard and AmneziaWG ports move out of the way if they clash. Keys that cannot be kept (ports below 1024, a port the management API uses, a cipher mix on one port) get a new key, and the report lists them.
  - **Check first:** `--check` shows what would happen, without a password, while Outline keeps running.
  - **Atomic, with a way back:** the import is one change. If it fails, Outline is started again. When it works, Outline is stopped and kept from restarting, its files stay as a backup, and the rollback command is printed.
  - **API:** `POST /import/outline` with Outline's two files and `dry_run`; `GET /server` reports `shadowsocks_extra_ports`.
  - **On the server:** `sudo ghostlink-server import-outline --dir DIR [--check]`.

### Changed

- **Speeds are in bytes per second everywhere** (B/s, KB/s, MB/s, GB/s, decimal like data sizes), including live monitoring in the app, the dashboard, the Island and `top`. They were shown in bits per second before. The API's `*_bps` fields were already bytes per second.
- The users table of `sudo ghostlink-server users` has a SPEED column, and `settings` shows the default speed limit and any extra Shadowsocks ports.
- The installer lists the extra Shadowsocks ports of keys imported from Outline among the ports to allow.
- `--add-swap` is listed in the server guide's installer options.

## [0.7.0] - 2026-11-07

### Added

- **A new look: frosted glass.** The server dashboard and the desktop app are rebuilt on one component library: React, TypeScript, Tailwind CSS and Lucide icons, built with Vite (`ui/`).
  - **Materials:** frosted, translucent surfaces with crisp edges, generous rounded corners and pill controls, over three slow, faint glass waves.
  - **Waves:** the background control sets them to Subtle, Calm or Still, and they are still when the system asks for reduced motion.
  - **Finishes:** three of them, Obsidian, Titanium and Daylight.
  - **Type:** labels in sentence case; a monospace face only for addresses, keys and ports; steady tabular figures for every live number.
  - **Fonts:** Plus Jakarta Sans and JetBrains Mono, both self-hosted, so the pages load nothing from outside.
- **Dashboard and the app's "Servers I run":** the same views, with the same features as before plus:
  - **Live capsule:** a floating navigation bar with a Dynamic Island-style capsule that shows live state and opens a switch for each protocol.
  - **Overview:** a bento of KPIs (active tunnels, live throughput, uptime, address pool), plus a throughput chart for the last 60 seconds, hour or 24 hours.
  - **Clients:** cards or a list, with search, Online/Idle/Paused filters and an access switch. Each shows its tunnel IP, last endpoint, last handshake and live speed, with quick QR, .conf, copy and revoke actions.
  - **New client:** shows the next free tunnel address before creating; then the server issues the key and the sheet shows the QR code and the .conf at once.
  - **Network:** protocols with switches and ports, the address pools, the rules for everyone and the mesh map, in one place.
- **Full window:** both apps use the whole window. On wide screens, client and server cards go up to five a row and the protocol tiles to one row. The desktop app has a full-screen mode: F11 or the button in the navigation bar, with Escape to leave.
- **Desktop app:** My servers has a connection hero with a large power control, live speed and server cards with a menu. The Island shows the connection and switches servers. Settings now has the finish and motion controls.
- **API:**
  - `GET /server` reports `address_pools` (WireGuard and AmneziaWG subnets: in use, capacity, next address);
  - key summaries carry their tunnel `address`;
  - `/live` adds an hour of per-minute averages (`minutes`).

### Changed

- The dashboard (`internal/server/dashboard`) and the desktop UI (`apps/desktop/ui`) are now build output of `ui/`, committed so the Go module and the Tauri app build without Node. The new **Web UI** workflow rebuilds both and fails if the committed files differ. A Go test checks the embedded dashboard is complete and CSP-safe.
- The desktop app maps the admin views' requests onto the local service's typed operations through one table. A test checks the table against the Rust contract, and paths that are not plain are refused.
- The desktop shell can save `.conf` files to Downloads.
- The worker corresponding-source zip includes the UI source (`web-ui/`), and the license inventory and server image include the notices of the bundled npm packages and fonts.

## [0.6.0] - 2026-11-06

### Added

- **Ghostlink mesh: a private network between your Linux servers.** Every server you add gets a mesh address (`100.96.0.0/16` by default) and reaches the others over kernel WireGuard, across clouds, data centres and home networks. Guide: [docs/deployment/mesh.md](docs/deployment/mesh.md).
  - **Coordinator:** the Ghostlink server hands out addresses, keys, paths and access rules on its own TLS 1.3 port (pinned like the management API). Nodes get changes within about a second.
  - **Agent:** the new `ghostlink-mesh` package (.deb/.rpm, x64 and arm64) runs a hardened systemd service. It sets up `glmesh0`, firewall chains and `<node>.mesh` names, and reports handshakes, traffic and latency. The node's private key never leaves it.
  - **Direct links, relay fallback:** pairs connect directly; a pair that can't (for example two nodes behind NAT) goes through a relay node, and direct is retried later.
  - **Tag-based access rules** (`tag:web → tag:db tcp 5432`), enforced by each receiving node. A new mesh allows everything until the first rule.
  - **Shared subnets (site-to-site):** a node offers a subnet behind it (`--advertise-routes`), and the administrator approves it. It is masqueraded by default.
  - **Easy setup:**
    - `install-server.sh --mesh` makes the server the coordinator and its first node (the relay).
    - **Add node** in the app gives a one-line command for each new server: `install-mesh.sh --join 'glmesh1:…'`. Invites are single-use and expire after 24 hours by default; they can carry tags, a relay role or an approval step.
  - **Live map** in the app (**Servers I run → Manage → Mesh**) and the dashboard (**Mesh** view):
    - it shows nodes and links: direct, through the relay, or down, with latency and traffic;
    - nodes can be dragged; node details let you approve, tag, share subnets, set the relay, disable or remove;
    - it also has Add node and an access-rules editor.
  - Everywhere you manage the server: `sudo ghostlink-server mesh …` (including `join-here`), `ghostlink server mesh …` in the CLI, and the dashboard. AI agents cannot use mesh operations.
  - Linux servers only for now; Windows servers and the Ghostlink app on Windows as a mesh node will follow.
- **One-command server install:** `curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash`.
  - It picks the `.deb` or `.rpm` for the distribution and CPU, installs Docker if needed and verifies the package against the release checksums.
  - It prints the management key and the ports to open.
  - Options: `--hostname`, `--ipsec`, `--mesh`, `--open-firewall` (only for an active ufw or firewalld), `--version`, `--package` and `--mesh-package` for offline installs.
  - Running it again upgrades.
  - On servers with under 1 GB of memory and swap (for example the smallest AWS Lightsail plans) it stops before installing, because the kernel would kill the installation; `--add-swap` adds a 1 GB swap file. It also finishes an installation that was interrupted.

### Fixed

- `sudo ghostlink-server --json users` (and the other admin commands) failed with a usage message, although the guide documents it; the host command now passes `--json` through.
- A test of the engine's listener-ownership check could fail at random on Linux, when the PID it used as "another process" was one of the test's own threads.

## [0.5.0] - 2026-11-06

### Added

- **iPhone, iPad and Mac with no app:** the server can serve Apple's built-in VPN types and hand out configuration profiles (`.mobileconfig`):
  - **IKEv2** (`NEVPNProtocolIKEv2`) with username and password (EAP-MSCHAPv2) or a certificate;
  - **IPsec** (`NEVPNProtocolIPSec`, IKEv1) with a certificate or a shared group key, plus an XAuth password. Certificates are the default; group keys come with a warning.
  - Per key: server address, remote identifier and local identifier.
  - Profiles install in Settings and keep credentials in the Keychain. They can leave out the certificate password (`--prompt-password`) or connect on demand.
- **IPsec component** (`sudo ghostlink-server ipsec enable|disable|status|logs`): strongSwan 6 in a second container shipped inside the server package.
  - **Isolation:** the main server stays unprivileged and writes validated settings for `ghostlink-ipsec-agent`, which runs with only the network capabilities IPsec needs and applies them to strongSwan, its own firewall chains and a gateway interface.
  - **Limits:** data limits, usage, live speed, online state and "connected from" work for IKEv2/IPsec users. Disabled, removed and over-limit users are cut off within seconds, and their certificates are put on hold or revoked.
  - **Rules:** blocked addresses and ports, mail blocking, always-blocked internal ranges and DNS-based site blocks apply.
- **Internal CA** per server (RSA 3072) with automatic server-certificate renewal and a CRL.
- **Everywhere you manage the server:**
  - IKEv2/IPsec keys and profile saving in the app (**Save iPhone/Mac profile**), the CLI (`ghostlink server keys create --protocol ikev2 …`, `keys profile`), the dashboard and server commands (`key add NAME ikev2 …`, `profile NAME ID --output FILE`);
  - `set --rotate-ipsec-psk` everywhere;
  - connection kits explain how to install profiles.
- **Corresponding source** for the IPsec component's GPL packages (Alpine recipes and upstream sources) is published with each release.

### Fixed

- A QR-decoding test could fail at random on synthetic images. It now falls back to reading the clean bitmap directly.
- The dependency notice inventory missed Go modules only the Linux server links (netlink, nftables, nfqueue, dbus); it is now generated for Linux too, and the server images carry those notices.

## [0.4.0] - 2026-11-06

### Added

- **Server monitoring:**
  - live speed per user, open connections, who is online, and the last 2 minutes of server traffic;
  - server health: CPU, memory, disk, network, uptime;
  - traffic types (Web, QUIC/video, DNS, calls, BitTorrent, SSH, remote desktop, other) and protocols used, per user and in total;
  - usage history: hourly for 7 days and daily for 90;
  - the addresses users connected from: Shadowsocks/VLESS sources, and WireGuard/AmneziaWG endpoints from the engine.
- **Top services per user**, opt-in and off by default:
  - totals per service (YouTube, Netflix, TikTok…) or site;
  - kept 30 days, never page addresses or times;
  - turning it off deletes them.
- **Automatic rotation of recorded traffic:**
  - age-based retention (configurable);
  - a hard size limit for the history file (default 20 MB; oldest detail goes first);
  - a low-disk guard that pauses detailed recording below 500 MB or 5 % free.
- **Manage on the server:** `sudo ghostlink-server users | user | key | keys | kit | rules | usage | stats | clients | top | settings | set | site-stats | dashboard`.
  - These go through the server's own API on loopback.
  - Users can be named.
  - `key add` prints a QR code in the terminal, and `top` shows live speeds.
- **Web dashboard** on its own port, never 443:
  - **Private by default:** loopback only, reached through an SSH tunnel.
  - **Opt-in public mode:** HTTPS on that port.
  - **Sign-in:** a login link with the token after `#`, then an HttpOnly SameSite=Strict session, a CSRF header, a Host check against DNS rebinding, and throttling.
  - **Pages:** overview, users, keys with QR codes, statistics, rules and settings.
- **QR codes** for every key, as SVG for the app and dashboard or text for terminals. WireGuard/AmneziaWG keys offer both `.conf` (WireGuard/AmneziaWG apps) and `vpn://` (AmneziaVPN).
- **Connection kit:** one self-contained HTML page per user with all of their keys, QR codes and per-app instructions (Outline, WireGuard, AmneziaWG/AmneziaVPN, v2rayNG/Hiddify/Streisand/Shadowrocket, Ghostlink).
- **Ghostlink app:**
  - a live panel on each server page;
  - live speed and online state per user;
  - a statistics dialog per user and for the whole server;
  - QR codes and **Save connection kit** (saved to your Downloads folder, never overwriting);
  - monitoring settings.
- **CLI:** `ghostlink server live | stats | clients`, `server keys qr | kit`, and `server set --site-stats on|off --history-days --site-days --history-max-mb`.

### Changed

- User names on a server are now unique (ignoring case), so they can address users.
- The service reuses one pinned connection per managed server, so live updates don't repeat the TLS handshake.

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

[Unreleased]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/winyannainghtut/GHOSTLINK/releases/tag/v0.1.0
