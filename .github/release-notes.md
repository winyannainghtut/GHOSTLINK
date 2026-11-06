Unsigned pre-release of Ghostlink @VERSION@.

| Platform | Download | Contents |
|---|---|---|
| Windows 10/11 x64 | `Ghostlink-@VERSION@-windows-x64.msi` | Installer: desktop app, CLI, MCP bridge, tunnel worker and the `Ghostlink` service. Needs administrator consent and the Microsoft WebView2 Runtime. |
| Windows 10/11 x64 | `Ghostlink-@VERSION@-windows-x64-portable.zip` | The same executables without an installer or service registration. |
| Debian / Ubuntu | `ghostlink_@VERSION@-1_amd64.deb`, `ghostlink_@VERSION@-1_arm64.deb` | CLI, service, MCP bridge and tunnel worker. `sudo apt install ./<file>` sets you as the owner and starts the service. |
| Fedora / RHEL family | `ghostlink-@VERSION@-1.x86_64.rpm`, `ghostlink-@VERSION@-1.aarch64.rpm` | The same, as an RPM (`sudo dnf install ./<file>`). |
| Linux (any) | `ghostlink-@VERSION@-linux-x64.tar.gz`, `ghostlink-@VERSION@-linux-arm64.tar.gz` | The same files for a manual install. See `INSTALL.txt`. |
| Server: Debian / Ubuntu | `ghostlink-server_@VERSION@-1_amd64.deb`, `ghostlink-server_@VERSION@-1_arm64.deb` | Ghostlink server with its Docker image inside. `sudo apt install ./<file>` starts it and prints the management key. |
| Server: Fedora / RHEL family | `ghostlink-server-@VERSION@-1.x86_64.rpm`, `ghostlink-server-@VERSION@-1.aarch64.rpm` | The same, as an RPM. |
| Source | `Ghostlink-@VERSION@-worker-corresponding-source.zip` | Corresponding source for the GPL-3.0-or-later tunnel worker and server. |

Verify downloads against `SHA256SUMS.txt`.

## What's new

@CHANGES@

**Status.** Binaries are not code-signed, so Windows SmartScreen will warn. The server has been tested end to end on CI runners and locally, not yet on an internet-facing host. Full-device routing, DNS/IPv6 leak behavior, installer execution and the Linux runtime have not yet been verified on real hosts. The Linux desktop app, macOS, Android and iOS are not available yet.
