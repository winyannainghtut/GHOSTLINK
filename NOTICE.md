# Third-party attribution and distribution

MyVPN is an independent application. It is not an official product of OpenVPN Inc., the Outline Foundation, SagerNet, WireGuard LLC, Microsoft or the Tauri project.

The Rust control plane and original Tauri UI use the repository MIT license. The separate **core/outline-worker** executable links unmodified sing-box 1.14.4 libraries and is distributed under GPL-3.0-or-later, with upstream notices and applicable dependency/embedded-driver terms preserved. Its full corresponding source and dependency source must accompany distribution of the worker. A portable executable alone is not a complete compliant release package.

OpenVPN 2 is an optional separately installed engine; MyVPN does not bundle its executable or OpenVPN 3 Core. OpenVPN's COPYING and other applicable notices remain relevant if a future package bundles those components. The Outline Apps and SDK repositories informed compatibility/design; their source is not embedded in the original MyVPN UI or key parser.

`LICENSES/` contains upstream texts and generated dependency notices. `scripts/collect-licenses.py` inventories actual locked Rust dependencies and Go modules used by the worker. Review the resulting inventory and the embedded Wintun driver terms before public redistribution. No unreviewed distribution strategy is represented as legally guaranteed.

The Windows worker's pinned sing-tun dependency embeds Wintun and loads that embedded driver implementation; an unrelated installed TAP or DCO adapter is not a substitute. Driver signature, Windows permissions, driver notices and target-OS behavior require verification on the release installation.
