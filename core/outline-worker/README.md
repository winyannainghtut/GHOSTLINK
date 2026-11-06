# Managed Outline-compatible tunnel worker

This small GPL-3.0-or-later companion links the pinned, unmodified sing-box 1.14.4 libraries. It changes lifecycle integration, not protocol or cryptographic code. The Rust daemon remains a separate process. The worker supports a narrow `version`, `check -c FILE`, and `run -c FILE` interface; all configurations are generated in private daemon storage.

Unlike a console-less standalone CLI forcibly terminated on Windows, this worker calls the upstream `Box.Close()` when its parent sends a stop message **or the inherited stdin pipe reaches EOF**. It emits fixed JSON lifecycle events to inherited stderr, suppresses raw engine logs, and bounds shutdown. A graceful close is a prerequisite for reporting a clean disconnect; OS route/DNS restoration still requires platform verification.

Build with Go's checksum database enabled:

```text
go build -trimpath -tags with_gvisor,with_utls,with_wireguard -o ghostlink-tunnel.exe .
```

`go.mod` pins the Go toolchain and engine; `go.sum` records dependency checksums. Only TUN, mixed local proxy, Shadowsocks, direct routing, the DNS transports needed by Ghostlink, and the authenticated statistics controller are registered. This binary does not expose arbitrary shell commands. Do not configure a service to run it directly with closed stdin: the daemon owns its lifecycle.

The upstream engine is GPL-3.0-or-later with its own notices and naming terms. Distribute corresponding worker/engine/dependency source and build instructions with worker binaries; the packaging script prepares a source bundle. See the repository's licensing documentation before distributing a release.
