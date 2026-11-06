Unsigned pre-release of Ghostlink @VERSION@.

| Platform | Download | Contents |
|---|---|---|
| Windows 10/11 x64 | `Ghostlink-@VERSION@-windows-x64.msi` | Installer: desktop app, CLI, MCP bridge, tunnel worker and the `Ghostlink` service. Needs administrator consent and the Microsoft WebView2 Runtime. |
| Windows 10/11 x64 | `Ghostlink-@VERSION@-windows-x64-portable.zip` | The same executables without an installer or service registration. |
| Linux x64 | `ghostlink-@VERSION@-linux-x64.tar.gz` | Headless CLI, service, MCP bridge and tunnel worker with a systemd unit. See `INSTALL.txt`. |
| Linux arm64 | `ghostlink-@VERSION@-linux-arm64.tar.gz` | As above, for 64-bit ARM. |
| Source | `Ghostlink-@VERSION@-worker-corresponding-source.zip` | Corresponding source for the GPL-3.0-or-later tunnel worker. |

Verify downloads against `SHA256SUMS.txt`.

## What's new

@CHANGES@

**Status.** Binaries are not code-signed, so Windows SmartScreen will warn. Full-device routing, DNS/IPv6 leak behavior, installer execution and the Linux runtime have not yet been verified on real hosts. The Linux desktop app, macOS, Android and iOS are not available yet.
