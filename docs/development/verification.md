# Verification ledger

Updated 2026-11-06 (Asia/Singapore). A compiled binary or proxy-only traffic test does not meet the original full VPN platform definition of done.

## v0.5.0 IKEv2/IPsec for iPhone, iPad and Mac (2026-11-06)

### Real strongSwan interop (CI, `tests/ipsec/interop.sh`)

- **Setup:** observed on GitHub's `ubuntu-24.04` runner (kernel 7.0.0-1017-azure, Docker, iptables-nft).
  - The script installed the built `ghostlink-server` `.deb`, ran `ghostlink-server ipsec enable` and checked the hardening: read-only, `drop=[ALL]`, only NET_ADMIN, NET_BIND_SERVICE and NET_RAW, user `0:<server gid>`, host network, `no-new-privileges`, `ipsec/` mode 770, IPv4 forwarding on.
  - It enabled IKEv2 and IPsec over the API, created keys and downloaded their profiles (`application/x-apple-aspen-config`).
  - `tests/ipsec/client_config.py` turned each profile into a strongSwan client configuration with exactly the profile's addresses, identifiers, credentials, CA, PKCS#12 identity (opened with the embedded password) and algorithms.
  - The client (strongSwan 6.0.7 from the same image) ran in its own network namespace (10.99.0.2), with an "internet" host 198.51.100.10 in another.
- **Each method connected:** IKEv2 EAP-MSCHAPv2, IKEv2 certificate, IPsec certificate + XAuth (Main Mode) and IPsec group key + XAuth (Aggressive Mode). Through each tunnel:
  - HTTP to the internet host worked (NAT);
  - the globally blocked port 8081 was refused;
  - the server's own API (10.99.0.1) was unreachable;
  - DNS for a blocked site returned NXDOMAIN, both from the pool gateway and from another resolver address (redirected);
  - the server counted the connection.
- **Refusals:**
  - a wrong EAP password was rejected;
  - disabling the user ended the live session and refused the certificate (strongSwan log: certificate on hold) and the group key;
  - re-enabling allowed the certificate again;
  - removing the certificate key refused it (revoked in the CRL).
- **Accounting:**
  - usage became non-zero;
  - `/stats` showed `ikev2` and `ipsec` bytes and "IPsec (not inspected)";
  - `/clients` recorded 10.99.0.2;
  - lowering the data limit to the usage ended the session and marked the user over the limit.
- **Logs:** no password appeared in the agent's log.
- **`ipsec disable`:** it left no `GHOSTLINK-IPSEC` chains, no `glipsec0` and no sysctl drop-in.

### Server and agent (Go, Windows host)

- **Profiles (strict plist parser):**
  - required keys per method;
  - unique and stable `PayloadUUID`s;
  - the VPN payload references its PKCS#12, which decodes with the embedded password to a client certificate that verifies against the CA with the ClientAuth EKU, and is absent with `prompt_password`;
  - the CA payload equals the state's CA;
  - a hostile server and user name is escaped and reads back exactly;
  - on demand.
- **Server certificate:** verifies for the IP and an extra remote identifier, and carries the IKE intermediate EKU.
- **NT hash and CRL:** the NT hash matches the RFC 2759 vector. The CRL is signed by the CA; a disabled user's certificate is on hold (reason 6) and lifted on enabling, and a removed key is revoked.
- **Desired state:**
  - it validates and holds NT hashes, never EAP passwords;
  - disabled and over-limit users drop out;
  - `rotate_ipsec_psk` changes the key.
- **Agent:**
  - `swanctl.conf`, firewall rules and pool ranges are rendered as expected, with secrets only in `0s` base64;
  - validation refuses newline or brace identities, `@` forms, short hashes or keys, oversized pools, a non-first gateway, invalid or injected ranges and ports, a low DNS port, wrong PEM types and an unknown version;
  - `list-sa`, `child-updown` and `child-rekey` events parse into status, with final counters;
  - established-but-disallowed SAs are selected for termination.
- **Accounting:** a session that ends between reports is counted once from its final counters.
- **DNS listener:** it answered NXDOMAIN for a blocked name to an allowed source and nothing to others.

### Daemon, CLI and app

- **Node suite:** 19/19. The new steps cover the component check, IKEv2/IPsec key creation (refusing `--import` and a wrong method), the PSK warning, `keys profile --output` (a new private file, never overwriting), no certificate password in key lists, `--rotate-ipsec-psk`, and an agent token refused `key_profile`.
- **App GUI, over WebView2 DevTools with an isolated profile and a local test server:**
  - **Server settings:** shows IKEv2/IPsec toggles ("UDP 500, 4500") and the component state, and saving them turns both on.
  - **Key dialog:**
    - IKEv2 shows auth eap/certificate and the remote identifier, and hides "use on this device";
    - IPsec + group key shows the weak-key warning, and the server's warning appears after creation;
    - key rows show method, identity and address, with **Save iPhone/Mac profile** (and **Profile without password** for certificates).
  - **Saving:** writes a `.mobileconfig` to Downloads containing the VPN payload and the custom remote identifier. The test file was deleted by its exact path.
- **CI:** the desktop workflow (Windows and Ubuntu: Go tests, vet, govulncheck, Rust build, tests, clippy, Node suite) passed.

### Not verified

- Installing and connecting a profile on a real iPhone, iPad or Mac.
- The component on hosts using iptables-legacy, firewalld or ufw, and on a real internet-facing host.
- IPv6 leaks from Apple devices with IPv4-only tunnels.
- arm64 interop until the release workflow's arm64 job runs.

## v0.4.0 Monitoring, server-side admin and dashboard (2026-11-06)

Observed on the Windows development host (unelevated, loopback only). The release CI server test now also runs the admin commands and dashboard checks on Ubuntu with Docker.

### Monitoring with real clients (Go)

An unmodified Shadowsocks client and a WireGuard client reached the server:

- Alice's live download rate was measured above 100 KB/s, and she showed online.
- An open CONNECT tunnel counted as 1 active connection and dropped to 0 after closing.
- Traffic counted under "Web (HTTP)" and "shadowsocks" (Bob's under "wireguard"), with an hourly series.
- With site stats on, Host `www.youtube.com` was counted as "YouTube".
- Client addresses: Alice `shadowsocks 127.0.0.1` from the inbound, Bob `wireguard 127.0.0.1` from the parsed UAPI endpoint.
- History saved and reloaded into a new monitor; turning site stats off removed every stored site

### Rotation

Retention kept exactly 30 daily buckets and removed site totals older than the 10-day site retention. A cap 200 bytes under the full size trimmed site data before breakdowns while keeping all days, and a 400-byte cap was honored. Client records outside 30 days were dropped. A simulated low disk paused detail recording (no detail counters created), and it resumed when space returned

### QR codes and kit

For all four protocols, both the SVG (path parsed back to modules) and the terminal half-block output decoded with an independent decoder (gozxing) to exactly the key or `.conf`. The kit contains every key, one QR code per key and the privacy note, with no script

### Dashboard

Index served with a strict CSP:

- **Auth:** no session 401; wrong token 401; the right token gave a 204 with an HttpOnly, SameSite=Strict cookie; a missing CSRF header 403; a foreign Host 403; the API and kit worked through the dashboard.
- **Ports:** 443, 80, the API port and a protocol port were refused as dashboard ports; moving the port closed the old one; a token reset signed sessions out.
- **Public mode:** TLS 1.3 with the pinned certificate and a Secure cookie; back to private worked.
- **Throttling:** 20 bad tokens returned 429 even for the right token

### Server commands

Against the real API listener:

- **Users and keys:** user add (with a limit), a duplicate-name refusal, key add (key, `.conf` and terminal QR), keys list with and without `--show`, key qr.
- **Rules:** per-user and global rules.
- **Monitoring:** site-stats, settings, top --once, stats, usage, clients.
- **Sharing and dashboard:** the kit; dashboard (tunnel command and link); a `--port 443` refusal; a token reset.
- **Settings and users:** set including the retention cross-check; user limit, disable and remove; JSON output. On Windows the same commands ran against a live local server

### Daemon/CLI (Node, real server)

`server live`, `stats` (and an invalid range refused through IPC), `clients`, `keys qr` (terminal QR), `keys kit` (a new file with keys and QR SVGs), and `set --site-stats on --history-days 60` reflected in `info`. Agents were refused for live and kit; 19/19 process tests passed

### App GUI (WebView2 DevTools, isolated profile)

Server page live panel, per-user online and speed lines, the Stats dialog, the AmneziaWG QR dialog, and Server settings with the monitoring section. **Save connection kit** wrote `Downloads\Alice-vpn.html` (2 QR codes, test keys for the local test server), which was then deleted. The first attempt with a `blob:` download failed in WebView2 and was replaced by a desktop save command

### Web dashboard (in the app's isolated WebView2)

The login link signed in and the fragment was removed. Overview (live cards, chart, server card, empty breakdowns), Users (status, offline, actions), Keys (QR `.conf`/`vpn://`, copy, kit) and Settings (protocols, monitoring, retention, dashboard port note) were inspected

### Static checks

Rust fmt and clippy clean (root and desktop); 33 Rust unit tests passed; Go vet clean; all Go tests passed; `govulncheck` **No vulnerabilities found**; server cross-builds for linux/amd64 and arm64

### Release dry run

The first dry run of this commit built and passed Linux x64 and arm64: client and server packages, the server install, the admin commands and the dashboard checks. The Windows job failed, correctly, at the corresponding-source build check: the bundle copied only `.go`/`.mod`/`.sum`/`.md` files and missed the dashboard pages that the server embeds (`pattern dashboard: no matching files found`). The script now copies every module file except `vendor/` and binaries; the local rerun built from the staged copy.

### Not verified

Health readings on a real Linux host (CPU, memory and network come from `/proc`; unavailable on Windows dev); the dashboard over a real SSH tunnel; public dashboard mode in a browser; top-services accuracy for apps using ECH

## v0.3.1 Windows installed-service fix (2026-11-06)

First real MSI installation, on the user's Windows 11 machine by the user.

| Check | Result actually observed |
|---|---|
| Installed v0.3.0 | The `Ghostlink` service was installed and running as LocalSystem, with the user's SID as owner. `\\.\pipe\ghostlink` existed: owner BUILTIN\Administrators, DACL `D:P(A;;FA;;;SY)(A;;0x12019f;;;<user SID>)`, and a plain pipe connect succeeded. The installed v0.3.0 CLI and app still reported `daemon_unavailable`: the client's identity check opened the SYSTEM process token, which a standard user may not do |
| Fixed client against the real installed service | The rebuilt CLI with the pipe-owner check answered `status` and `doctor` from that SYSTEM service, while the installed v0.3.0 CLI failed side by side. Shortly afterwards the user uninstalled v0.3.0 (16:43), so the fixed desktop app could not also be checked against an installed service |
| Same-user development path | The 19 process tests (service as the same user, pipe owned by that user) passed with the new check |
| Shortcuts | The v0.3.0 MSI's Start-menu shortcut had no icon (`IconLocation ",0"`) and there was no desktop shortcut. The v0.3.1 MSI's Shortcut table has `StartMenuShortcut` and `DesktopShortcut`, both with `Icon_ = Ghostlink.ico`, which is present in the Icon table and set as `ARPPRODUCTICON`. The WiX build validated |
| Not verified | The fixed app installed from the v0.3.1 MSI, and the shortcut icon appearing in Explorer (both need the user's installation) |

## v0.3.0 Ghostlink server and server management (2026-11-06)

Observed on the Windows development host (unelevated, loopback only) unless noted. Release CI results for the server packages are recorded when the release runs.

| Check | Result actually observed |
|---|---|
| Server, real traffic (Go `internal/server`) | Keys issued through the API were turned into **unmodified** sing-box clients, using only the key text, for all four protocols: AmneziaWG (our endpoint), WireGuard (sing-box native client), VLESS-REALITY (local TLS 1.3 handshake target) and Shadowsocks. Each carried HTTP through the server. In each, a per-user blocked site, a global blocked site (`*.Global-Blocked.test`, normalized and matched for `www.` by Host sniffing) and a loopback service on another port were refused. A second user was unaffected by the first user's rule; an exempt user skipped global rules but not the internal block. Usage was counted; a 1-byte limit cut the user off and resetting restored access; disabling a user and deleting a key cut them off; state persisted |
| Server API | Unknown fields, missing or control-character names, bad IPs, ports and sites, unknown protocols, missing IDs, bad hostnames and IP REALITY sites were refused with the right status. A port clash was refused and changed nothing; a disabled protocol could not issue keys. Only the exact secret path worked, and 20 wrong guesses gave `429`. The real listener served TLS 1.3 only, with a certificate matching the printed pin. `init` creates once, keeps the secret, updates the hostname and fails without an address |
| Keys format | Amnezia `vpn://` keys decode in the exporter format (length prefix, zlib, `last_config` with the `.conf` and AWG parameters, no `userName`/`password`). AWG 2.0 parameters drawn 200 times were valid (S1+56≠S2, disjoint header ranges) |
| Daemon/CLI with a **real** `ghostlink-server` (Node suite) | `server add` with the printed key, no overwrite without `--replace`, and list output with neither the secret nor the pin (nor in Windows state). Then: user with a 5 GB limit; an AmneziaWG key created with `--import` became a working profile via the Rust parser; VLESS and WireGuard keys written to new private files (`.conf` imported as `wireguard`), with no overwrite; a printed `ss://` key imported. `keys list` hid key material unless `--show-keys`. Global and per-user rules, usage, disabling WireGuard (key creation then refused) and disabling a user worked. A wrong pin gave `server_identity_mismatch`; `http`, missing-pin and extra-field keys gave `invalid_request` without echoing the secret. Agent tokens were refused for all server actions; the audit log never contained the secret; a stopped server gave `server_unreachable` |
| Pinned client (Rust unit) | With a wrong pin, the TLS server received **zero** application bytes (the secret path was never sent). Outline servers were recognized and refused as unsupported; server error text came back without the key; operations map to fixed paths, with path-traversal IDs and unknown protocols refused |
| Desktop GUI | Debug app against an isolated dev daemon and a real local server, driven over the WebView2 DevTools protocol. Inspected: server list; server page (users with status chips, limit meter, rules summary, ports); keys dialog; per-user rules; server settings; creating a WireGuard key with "Also use it on this device", which then appeared under My servers as "Alice @ Home lab" with its badge; dark and light themes |
| AmneziaWG close race (Linux CI of v0.2.1, `596633b`→`5ea1347`) | Hosted CI crashed an AWG 2.0 client worker during graceful stop: nil dereference in sing-box's stack `Write`, called from amneziawg-go's receive goroutine after the TUN closed. Fixed in the TUN adapter; a regression test passes with the fix and panics ("write after close") without it |
| Corresponding source | The v0.2.1 zip was rebuilt from the `v0.2.1` tag with the fixed script: it built every command on Windows inside the script and `ghostlink-tunnel` for linux/amd64 from the unzipped copy, reporting `0.2.1`, with 0 backslash paths. It replaced the incomplete zip in the v0.2.1 draft, and `SHA256SUMS.txt` was refreshed |
| Static checks | Rust fmt and clippy (`-D warnings`) clean; 33 Rust unit tests (29 engine, 4 contracts) and 19 Node process tests passed; Go vet clean; Go tests passed; `govulncheck` **No vulnerabilities found**; server cross-builds for linux/amd64 and arm64 |
| Package spec (local) | nfpm built placeholder server `.deb`/`.rpm`; the `.deb` control has `Depends: docker.io \| docker-ce \| moby-engine \| docker-engine \| podman-docker, passwd`, the three maintainer scripts and a `0755` `/usr/sbin/ghostlink-server` |
| Not verified | The server on an internet-facing VPS; Amnezia's own apps importing our `vpn://` keys; RPM install on Fedora/RHEL; podman; IPv6 inside tunnels; management through a connected full TUN (the bypass rule is unit-tested, not routed) |

## v0.2.1 Linux packages (2026-11-06)

| Check | Result actually observed |
|---|---|
| Linux SIGPIPE fix in CI | The full CI run after the fix (`596633b`) passed on Ubuntu 24.04 and Windows 2022, including all real-engine protocol and split-tunnel tests |
| Package spec (local) | nfpm 2.48.0 built a `.deb` and an `.rpm` from the template with placeholder binaries. The `.deb` control has `Depends: libc6 (>= 2.35), libssl3 \| libssl3t64`, a conffile for `/etc/ghostlink/ghostlinkd.env`, postinst/prerm/postrm, root-owned `0755` binaries in `/usr/bin` and `/usr/lib/ghostlink`, and the unit with `/usr` paths and `$GHOSTLINK_FLAGS` |
| Checksum refresh for arm64 files | The idempotent update was exercised locally twice: a stale line was replaced, with no duplicates |
| Release CI (run 42175275443) | On Ubuntu 22.04 x64 and arm64 the `.deb` installed as a real systemd service: the installer set owner UID 1001 from `sudo`, `ghostlinkd` was `active`, and `ghostlink status`/`doctor` answered as that user. Purge removed it. The `.rpm` passed `rpm -qip/-qlp/--scripts`. The draft had all 10 files. A cosmetic dpkg warning about `/usr/lib/systemd/system` was fixed in v0.3.0 |
| Same commit, CI workflow | Failed on Ubuntu: the AmneziaWG close race recorded under v0.3.0 (the release workflow does not run that test) |

## First hosted CI run of v0.2.0 (2026-11-06)

- **What failed:** on GitHub's Ubuntu runner, two new real-engine tests failed; the Windows job was cancelled by the matrix.
- **Cause:** the test helper dropped the worker's stderr pipe after the first event, so the worker's final event write raised **SIGPIPE** on Linux and killed it; Windows has no SIGPIPE. The split test's first tunneled request also outran its short retry budget under parallel load.
- **Fixes:**
  - the worker now ignores SIGPIPE on Unix, so a broken status pipe can never interrupt the engine's graceful close (a product hardening, not only a test fix);
  - the tests drain worker events for the worker's lifetime and report its failure code;
  - the split test waits for the tunnel through the always-tunneled health proxy before checking routes;
  - CI runs these tests one at a time.
- **Local result:** all three pass serially on Windows. The Linux result is pending the next CI run.

## Client split tunneling (2026-11-06)

| Check | Result actually observed |
|---|---|
| Real worker routing (proxy-only, loopback) | Full mode kept everything in the tunnel; bypass by IP (`127.0.0.1/32`) and by site (`bypass.test`, matched for `www.bypass.test` via HTTP Host sniffing) went direct while other sites stayed tunneled; "only" mode tunneled the listed range and sent the rest direct; the **health probe stayed in the tunnel** in "only" mode |
| Rust unit tests | 22 engine tests passed (new: policy normalization/rejection, bypass/only rule rendering) |
| Daemon/CLI process suite | 18 passed (new: set/show/clear globally and per server, normalization, invalid entries rejected, override kept across `--replace`, agent tokens refused) |
| Desktop GUI | Settings card summarized a CLI-set policy; the dialog loaded and saved it; a per-server override was created from the server menu and confirmed via CLI (screenshots inspected) |
| Not verified | Process (app) matching and full-TUN routing need an elevated test; domain rules against ECH traffic |

## WireGuard, AmneziaWG, VLESS-REALITY and Amnezia import (2026-11-06)

Observed on the Windows development host, unelevated; all traffic tests are loopback and proxy-only.

| Check | Result actually observed |
|---|---|
| AmneziaWG endpoint (`internal/awg`) vs **upstream amneziawg-go** | Real HTTP through the tunnel with legacy AWG, AWG 2.0 (H ranges, I1 chain, header protection key) and zero-parameter WireGuard; a mismatched H1 failed the handshake |
| Server role | Upstream amneziawg-go AWG 2.0 client and a stock WireGuard client (sing-box native endpoint) both reached a web server behind our endpoint; `auth_user` rules blocked only the named peer's user |
| VLESS-REALITY | Client outbound as generated by Rust carried HTTP through a sing-box REALITY server borrowing a local TLS 1.3 handshake; a wrong short ID was refused |
| Generated configs | All seven kinds (WireGuard full/split, AWG legacy/2.0, VLESS-REALITY/TLS, Shadowsocks) accepted by the real worker `check`, with and without the TUN inbound |
| End-to-end engine test | `.conf` → Rust parser → generated config → worker client → worker server → loopback web server, for WireGuard, legacy AWG and AWG 2.0; both workers stopped cleanly on stdin EOF |
| Daemon/CLI process suite | 17 passed, including `.conf`/`vpn://`/`vless://` imports, `PostUp`/`Table`/plaintext-VLESS rejection, full-access `vpn://` refusal without echoing the SSH password, and no key material in list output or sealed state |
| Rust unit tests | 19 engine + 2 contracts passed (new: WireGuard/AWG parser, VLESS parser, `vpn://` decoder incl. decompression caps) |
| Dependency scan | `govulncheck` found two advisories newly reachable via uTLS (brotli, klauspost/compress); after updating both, **No vulnerabilities found** |
| Desktop GUI | Debug app launched against an isolated dev daemon; three test servers rendered with AmneziaWG/WireGuard/VLESS badges and imported display names (screenshot inspected) |
| Not verified | A full-TUN connection with any new protocol (needs administrator), and Amnezia's own apps importing keys exported by Ghostlink (server phase) |

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
