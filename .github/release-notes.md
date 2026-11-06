Unsigned pre-release of Ghostlink @VERSION@.

| Platform | Download | Contents |
|---|---|---|
| Windows 10/11 x64 | `Ghostlink-@VERSION@-windows-x64.msi` | Installer: desktop app, CLI, MCP bridge, tunnel worker and the `Ghostlink` service. Needs administrator consent and the Microsoft WebView2 Runtime. |
| Windows 10/11 x64 | `Ghostlink-@VERSION@-windows-x64-portable.zip` | The same executables without an installer or service registration. |
| Debian / Ubuntu | `ghostlink_@VERSION@-1_amd64.deb`, `ghostlink_@VERSION@-1_arm64.deb` | CLI, service, MCP bridge and tunnel worker. `sudo apt install ./<file>` sets you as the owner and starts the service. |
| Fedora / RHEL family | `ghostlink-@VERSION@-1.x86_64.rpm`, `ghostlink-@VERSION@-1.aarch64.rpm` | The same, as an RPM (`sudo dnf install ./<file>`). |
| Linux (any) | `ghostlink-@VERSION@-linux-x64.tar.gz`, `ghostlink-@VERSION@-linux-arm64.tar.gz` | The same files for a manual install. See `INSTALL.txt`. |
| Server: Debian / Ubuntu | `ghostlink-server_@VERSION@-1_amd64.deb`, `ghostlink-server_@VERSION@-1_arm64.deb` | Ghostlink server with its Docker images inside. `sudo apt install ./<file>` starts it and prints the management key. `sudo ghostlink-server ipsec enable` adds IKEv2/IPsec for iPhone, iPad and Mac. |
| Server: Fedora / RHEL family | `ghostlink-server-@VERSION@-1.x86_64.rpm`, `ghostlink-server-@VERSION@-1.aarch64.rpm` | The same, as an RPM. |
| Mesh agent: Debian / Ubuntu | `ghostlink-mesh_@VERSION@-1_amd64.deb`, `ghostlink-mesh_@VERSION@-1_arm64.deb` | Joins a Linux server to a Ghostlink mesh (kernel WireGuard). Usually installed by the one-line **Add node** command (`scripts/install-mesh.sh --join 'glmesh1:…'`). |
| Mesh agent: Fedora / RHEL family | `ghostlink-mesh-@VERSION@-1.x86_64.rpm`, `ghostlink-mesh-@VERSION@-1.aarch64.rpm` | The same, as an RPM. |
| Source | `Ghostlink-@VERSION@-worker-corresponding-source.zip` | Corresponding source for the GPL-3.0-or-later tunnel worker, server and mesh agent. |
| Source | `Ghostlink-@VERSION@-ipsec-component-source-x64.tar.gz`, `…-arm64.tar.gz` | Corresponding source (Alpine recipes and upstream sources) for strongSwan, iptables and the other copyleft packages in the server's optional IPsec component. |

Verify downloads against `SHA256SUMS.txt`.

## What's new

@CHANGES@

**Status.** Binaries are not code-signed, so Windows SmartScreen will warn. The server has been tested end to end on CI runners and locally, not yet on an internet-facing host. IKEv2/IPsec is tested in CI with a real strongSwan client using each Apple profile's parameters; installing a profile on an iPhone, iPad or Mac is checked by hand. Profiles are unsigned, so iOS shows them as "Unverified". The mesh is tested in CI with kernel WireGuard between network namespaces (direct and relayed paths, NAT, access rules, shared subnets) and with the packages on the runner; it has not yet run across real cloud servers. Full-device routing, DNS/IPv6 leak behavior, installer execution and the Linux runtime have not yet been verified on real hosts. The Linux desktop app and Ghostlink apps for macOS, Android and iOS are not available yet; Apple devices use their built-in VPN with the profiles.
