# Third-party attribution and distribution

Ghostlink is an independent application. It is not an official product of OpenVPN Inc., the Outline Foundation, Amnezia, SagerNet, WireGuard LLC, Microsoft or the Tauri project, and implies no endorsement by them.

"WireGuard" is a registered trademark of Jason A. Donenfeld. Ghostlink uses the name only to describe protocol compatibility. AmneziaWG and Amnezia are names of the Amnezia project; Ghostlink imports their key formats for compatibility and is not affiliated with it.

The Rust control plane and original Tauri UI use the repository MIT license. The separate **core/outline-worker** executable links unmodified sing-box 1.14.4 and amneziawg-go v3.1.20260828 (MIT) libraries and is distributed under GPL-3.0-or-later, with upstream notices and applicable dependency/embedded-driver terms preserved. Its full corresponding source and dependency source must accompany distribution of the worker. A portable executable alone is not a complete compliant release package.

The **ghostlink-server** program (same Go module, GPL-3.0-or-later) is shipped inside a container image built on Google's distroless `static-debian12` base (Apache-2.0, carrying Debian's `base-files`, `netbase`, `tzdata` and `ca-certificates` under their own terms). The server packages include the GPL text and dependency notices, and point to the corresponding source published with the same release.

OpenVPN 2 is an optional separately installed engine; Ghostlink does not bundle its executable or OpenVPN 3 Core. OpenVPN's COPYING and other applicable notices remain relevant if a future package bundles those components. The Outline Apps and SDK repositories informed compatibility/design; their source is not embedded in the original Ghostlink UI or key parser.

`LICENSES/` contains upstream texts and generated dependency notices. `scripts/collect-licenses.py` inventories actual locked Rust dependencies and Go modules used by the worker. Review the resulting inventory and the embedded Wintun driver terms before public redistribution. No unreviewed distribution strategy is represented as legally guaranteed.

The Windows worker's pinned sing-tun dependency embeds Wintun and loads that embedded driver implementation; an unrelated installed TAP or DCO adapter is not a substitute. Driver signature, Windows permissions, driver notices and target-OS behavior require verification on the release installation.
