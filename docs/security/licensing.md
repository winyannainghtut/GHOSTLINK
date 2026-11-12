# Licensing decisions and unresolved distribution review

Original Rust control-plane and UI files use MIT. The separate Go worker links the pinned sing-box libraries and uses GPL-3.0-or-later. Its process boundary avoids linking GPL code into the Rust GUI/CLI, but does not remove the worker's own source and notice obligations. Package its source, exact Go dependencies, notices, build flags and toolchain reference together with any binary distribution. The packaging script prepares a vendored source archive.

The worker also links unmodified amneziawg-go v3.1.20260828 (MIT; a fork of WireGuard's wireguard-go), SagerNet's wireguard-go fork (MIT) and uTLS (BSD-3-Clause), whose notices are in `LICENSES/dependencies/`. `core/outline-worker/internal/awg` adapts a few sing-box files (GPL-3.0-or-later, attributed in each file header) to drive amneziawg-go; that adapted code stays inside the GPL worker. "WireGuard" is a registered trademark of Jason A. Donenfeld and is used only to describe compatibility.

The actual sing-box license contains its GPL notice and an additional naming/association statement; the upstream text is preserved in `LICENSES/sing-box.txt`. Ghostlink uses its own name/icon and does not imply endorsement. Dependencies retain their file-level licenses. Generated Rust/Go notice inventory is a review aid, not a legal compatibility guarantee.

Wintun is a separate signed binary embedded by the pinned sing-tun module. Its source and its prebuilt DLL have different licensing terms. Ghostlink preserves the official prebuilt-binaries license, uses the unmodified DLL through the permitted API, and verifies that the embedded DLL matches the official 0.14.1 archive. Review the distribution/embedding conditions in `LICENSES/Wintun-0.14.1.txt` and the source-level MIT wrapper notices. Do not describe the prebuilt DLL as MIT or silently substitute an unsigned rebuilt driver.

**Ghostlink server.**
- **License:** `ghostlink-server` is built from the same GPL-3.0-or-later Go module as the worker.
- **What the package carries:** its `.deb`/`.rpm` contains a container image made of the pinned `gcr.io/distroless/static-debian12:nonroot` base, the static binary, and the GPL text, sing-box notice and Go dependency notices under `/usr/share/doc/ghostlink-server/`. The base is Apache-2.0 and carries Debian's `base-files`, `netbase`, `tzdata` and `ca-certificates` with their own notices in the image. The package's `SOURCE.txt` points to the corresponding source published with the same release.
- **Corresponding-source zip:** it now contains the whole Go module (the worker, the server command and every internal package), and the script builds every command from the staged copy before zipping. The zips first attached to the v0.2.0 and v0.2.1 drafts did not include `internal/awg` and could not build. v0.2.1's was replaced with a complete one before publication.

**IPsec component (v0.5.0).**
- **Contents:** the server packages also contain the `ghostlink-ipsec` image.
  - `ghostlink-ipsec-agent`: GPL-3.0-or-later, from the same Go module, with source in the corresponding-source zip.
  - **From Alpine Linux 3.24:** `charon`, `swanctl` and the strongSwan plugins it loads, the iptables multi-binaries and extensions, and their shared libraries. Nothing else: there is no shell, busybox or apk.
- **Package list:** `packages/linux/server/ipsec-collect.sh` records the Alpine package of every file in `/usr/share/doc/ghostlink-ipsec/packages.txt`, with version, origin and license.
- **Source bundle:** `scripts/ipsec-source.sh` reads that list in CI. For every package under a copyleft license (GPL, LGPL, MPL, including dual-licensed ones such as libcap), it fetches the Alpine recipe (APKBUILD and patches) at the exact installed version and the upstream sources, verified by Alpine's own `abuild verify`. It publishes them as `Ghostlink-<version>-ipsec-component-source-<arch>.tar.gz`, and the job fails if a recipe version differs from the image.
- **Licenses:**
  - strongSwan is GPL-2.0-or-later with an OpenSSL linking exception;
  - iptables and libnftnl are GPL-2.0-or-later, and libmnl is LGPL-2.1-or-later;
  - the agent runs them as separate programs, so no GPL-2.0-only code is linked into the GPL-3.0 agent.
- **New Go modules:** `github.com/strongswan/govici` (MIT) and `software.sslmate.com/src/go-pkcs12` (BSD-3-Clause). `github.com/sagernet/netlink` (Apache-2.0) was already in the module graph.

**Mesh agent (v0.6.0).**
- **License:** `ghostlink-mesh` is GPL-3.0-or-later, from the same Go module as the server; its source is in the corresponding-source zip. The `.deb`/`.rpm` carries the static binary, the GPL text, `NOTICE.md` and the Go dependency notices under `/usr/share/doc/ghostlink-mesh/`.
- **Data path:** it drives the Linux kernel's own WireGuard through netlink and links no WireGuard implementation itself.
- **New Go modules:** `golang.zx2c4.com/wireguard/wgctrl` (MIT) and `github.com/mdlayher/genetlink` (MIT). `mdlayher/netlink`, `mdlayher/socket` and `sagernet/netlink` were already in the module graph.
- **ZeroTier:** [ZeroTier One](https://github.com/zerotier/zerotierone) was a design reference for the controller model (authorizing members, managed routes, tag rules, relays when peer-to-peer fails, path visibility). No ZeroTier code is used: its agent is MPL-2.0, and its controller is source-available for non-commercial use only.

**Web UI (v0.7.0).**
- **License:** the desktop app's interface and the server dashboard are original MIT code in `ui/`. Their builds are committed in `apps/desktop/ui` and in `core/outline-worker/internal/server/dashboard`, which is embedded in the GPL server, so the worker corresponding-source zip includes `ui/` as `web-ui/`, with build instructions. Rebuilding from that copy gives byte-identical files.
- **Bundled npm packages:**
  - React, ReactDOM and scheduler (MIT);
  - Lucide icons (ISC);
  - Plus Jakarta Sans and JetBrains Mono from `@fontsource-variable` (SIL Open Font License 1.1, Latin subsets only, as `.woff2` files);
  - two build tools whose own code is copied into the output: Tailwind CSS's base styles and the rolldown bundler's runtime helpers (both MIT).
- **Notices:** `collect-licenses.py` inventories them from `ui/package-lock.json` as `npm-*` entries, and the server image carries them with the Go notices. Type-only packages (`@types/react`, `csstype`) ship nothing.
- **Apple fonts:** San Francisco is only named in the font stack for Apple devices. No Apple font files are distributed.

The provider lookup (0.9.0) downloads the combined IPv4/IPv6 list of iptoasn.com at run time and does not ship it. Its maker states the data is "Licensed under Public Domain (PDDL v1.0)" (checked 2026-11-11), so keeping a copy on the server needs no attribution. No MaxMind or other restricted database is used.

OpenVPN 2 is optional and separately installed. If bundled in future, preserve GPLv2/source obligations and its stated linking exceptions plus all driver/dependency terms. OpenVPN 3 Core was inspected but is not linked or distributed; its MPL/AGPL alternatives do not grant unrelated mobile/App Store distribution rights. Outline Apps/SDK were reference material and are not embedded components.

The WebView2 Rust bindings' MIT text is preserved from their published source revision `edc2caf886175ccaebe86078c9cfe1ae2a187328`. Their static loader matched the x64 library in Microsoft's official WebView2 SDK 1.0.3800.47 package byte for byte (SHA256 `89c6b872783b8f6c3cedbff618adb42082d455c615453ae10cfc753f1e8f25d8`). Its separate SDK license and notices are included. The WebView2 Runtime remains an installed prerequisite; it is not bundled.

The generated inventory covers 569 entries: locked Rust packages, Go modules across targets (including the mesh agent's) and the eight npm packages bundled into the web UI. Before the web UI it covered 561, including the mesh agent's. Before that it covered 549; the one added then was `rsc.io/qr` (BSD-3-Clause), linked into the server; the test-only `gozxing` QR decoder is not inventoried because it ships in no binary. Before that it covered 548 (520 before the server and its management client; 513 before AmneziaWG, uTLS, WireGuard and zlib). It reads whole lockfiles, so it also lists a few optional packages that are never compiled, such as `quinn`, which reqwest refers to through a weak feature. Thirty-nine Rust packages did not ship their own top-level license file; the manually preserved WebView2 texts address some runtime notices, but the inventory is not proof that every target's redistribution review is complete.

Unresolved before public release: review complete target-specific dependency and driver terms, corresponding-source completeness, code-signing certificates, app-store distribution restrictions, mobile entitlements and trademarks. This repository does not assert a legally guaranteed distribution strategy.
