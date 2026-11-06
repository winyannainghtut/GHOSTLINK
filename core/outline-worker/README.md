# Ghostlink managed tunnel worker

`ghostlink-tunnel` is the GPL-3.0-or-later companion process that carries Ghostlink's VPN traffic. It links pinned, **unmodified** [sing-box](https://github.com/SagerNet/sing-box) 1.14.4 and [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) v3.1.20260828 libraries; it changes lifecycle integration, not protocol or cryptographic code. The Rust service (`ghostlinkd`) owns it and remains a separate MIT process.

## Interface

```text
ghostlink-tunnel version          # exact identity the service requires
ghostlink-tunnel check -c FILE    # validate a generated configuration
ghostlink-tunnel run -c FILE      # run until a stop message or stdin EOF
```

The service writes every configuration to private storage. The worker:

- emits only fixed, credential-free JSON events on stderr (`started` with the observed TUN address, `failed` with a code, `closed`); upstream logs stay disabled;
- calls the engine's graceful `Close()` on a stop message, on stdin EOF (parent died) or on SIGINT/SIGTERM, with a 10-second bound;
- refuses to start a TUN whose name or addresses collide with an existing interface;
- ignores `SIGPIPE` on Unix, so a broken status pipe cannot interrupt shutdown.

Do not run it as a service with a closed stdin: the daemon owns its lifecycle.

## Registered components

- **Inbounds:** TUN; the authenticated mixed proxy used for the health check; Shadowsocks, used only by the interoperability tests.
- **Outbounds and endpoints:** Shadowsocks, VLESS (REALITY/TLS via uTLS), direct, sing-box's WireGuard endpoint and Ghostlink's `amneziawg` endpoint (`internal/awg`).
- **Other:** the DNS transports Ghostlink uses, and the authenticated statistics controller.

Nothing executes shell commands. See [protocol design](../../docs/architecture/protocols.md) for the `amneziawg` endpoint.

## Build and test

```text
go build -mod=readonly -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -o ghostlink-tunnel.exe .
go vet  -tags with_gvisor,with_utls,with_wireguard ./...
go test -tags with_gvisor,with_utls,with_wireguard ./...
```

`go.mod` pins the Go toolchain and engines, and `go.sum` records checksums. The tests include interop runs against upstream amneziawg-go, a stock WireGuard client and a sing-box REALITY server.

## Licensing

sing-box is GPL-3.0-or-later with its own notices and naming terms; amneziawg-go and the WireGuard forks are MIT. Distribute the corresponding source with any worker binary. `scripts/package-worker-source.ps1` builds the source bundle that every release includes. See the repository's [licensing notes](../../docs/security/licensing.md).
