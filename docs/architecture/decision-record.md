# Architecture and implementation plan

> This is the original OpenVPN-era plan, kept as a record. It was superseded as the main path the same day: Outline-compatible keys became the primary experience ([outline-access-keys.md](outline-access-keys.md)), carried since 2026-11-06 by the managed sing-box/amneziawg-go worker ([protocols.md](protocols.md)). OpenVPN remains an optional backend. The environment described at the end is the one of that day.

2026-10-30. This is an incremental engineering project. A platform is complete only after the definition of done in the supplied brief is demonstrated. No mock backend is shipped.

## Inspected upstream

* OpenVPN 2.7.8, commit `dc1f569087135894ac2703aeabd7a960ee9452d4`: COPYING, COPYRIGHT.GPL, management-options.rst, management-notes.txt, manage.c, Windows CMake and DCO instructions.
* OpenVPN 3 Core release/3.11.8, commit `4f3bdef73245d4ee9e8216c5d65baccc9568f6ef`: LICENSE.md, LICENSES, client/ovpncli.hpp, TunBuilderBase, reference CLI, CMake and vcpkg manifest.
* https://openvpn.github.io/openvpn3/ and https://openvpn.net/community-docs/management-interface/

## Decision made before implementation

Use the separately installed, unmodified OpenVPN 2 executable for the first Windows/Linux vertical slice. Its documented management interface gives real connection events and counters, mature platform routing, reconnect behavior, and native adapter support. It avoids inventing a VPN protocol and makes the priority desktop path independently buildable. This is a staged deviation from the preferred OpenVPN 3 client engine, not a claim that a process adapter is OpenVPN 3 integration.

The OpenVPN 3 API is appropriate for mobile, but requires concrete TunBuilder callbacks, external key callbacks, driver integration on desktop, a C++20 dependency toolchain, and device builds. Preserve a separate engine boundary so it can replace the process adapter after those integrations are validated. Do not distribute untested mobile VPN binaries.

Rust workspace: shared versioned IPC contracts and client transport, strict profile parser and engine, privileged daemon, unprivileged CLI, optional stdio MCP bridge. GUI uses the same typed service protocol. The daemon serializes state mutations; status remains available while the connection worker runs. OpenVPN reverse-connects to an already-bound loopback management listener, authenticated with a fresh random password kept in service-private storage. OpenVPN exits when the manager disappears. Only a management CONNECTED/SUCCESS event sets connected state; traffic and leak diagnostics require separate measurements.

Windows: local-only named pipe with an explicit protected DACL for SYSTEM and one configured owner SID. Clients use identification-only security QoS. Service data has a protected ACL for the daemon identity and SYSTEM. Linux: private Unix socket with a configured owner UID, peer credential validation, root-private state, and no network-facing IPC. The allowed owner is the trusted human security boundary; processes running as that same user are not isolated from each other by an agent label.

Profiles are parsed and reconstructed using an allowlist. External paths, scripts, plugins, nested config, management directives, weak crypto, proxies and unknown directives are rejected. Certificate credentials must be inline. Password authentication and encrypted private keys are initially rejected until an end-to-end OS vault workflow exists. Windows profile contents are encrypted with DPAPI in addition to ACLs; Linux relies on root-private storage (disk encryption recommended). No claim of encrypted Linux credential storage is made.

## Execution sequence

1. Implement and compile contracts, profile validation, IPC daemon and CLI; test error paths and real local IPC.
2. Implement authenticated OpenVPN management worker; verify protocol parsing, lifecycle and available real-engine failure paths.
3. Add reproducible server provisioning, PKI tooling and network test procedure; run only where a privileged Linux host is available.
4. Add packaging, systemd and Windows service integration, CI and restricted MCP tools.
5. Implement desktop GUI and native mobile work only to the extent real toolchains permit; record external blockers explicitly.

Available environment: Windows x64, Rust 1.92 MSVC and GNU, VS2022 Build Tools, Node, Git, Go. Unelevated session. OpenVPN Connect adapters installed, but no standalone community OpenVPN executable on PATH. No Linux distro other than Docker Desktop's internal distro. Docker engine unavailable and launch blocked by automatic review. No supplied VPN server, credentials, Android SDK, Xcode or authorized mobile device. These limitations prevent claiming real routed VPN verification here.
