# Protocols and split tunneling (v0.2.0)

How Ghostlink supports Shadowsocks, VLESS-REALITY, WireGuard and AmneziaWG, and how split tunneling is applied. The Outline key decision is in [outline-access-keys.md](outline-access-keys.md); the original OpenVPN-era record is in [decision-record.md](decision-record.md).

## One worker, one generated configuration

Every protocol except the optional OpenVPN backend runs in the managed worker (`core/outline-worker`), which links unmodified sing-box 1.14.4. The daemon builds one sing-box configuration per connection in `core/vpn-engine/src/worker_session.rs`:

| Kind | Generated as | Tag |
|---|---|---|
| Shadowsocks | `shadowsocks` outbound | `proxy` |
| VLESS | `vless` outbound with `tls.utls` and `tls.reality` | `proxy` |
| WireGuard | sing-box native `wireguard` endpoint | `proxy` |
| AmneziaWG | Ghostlink `amneziawg` endpoint (below) | `proxy` |

- **Routing target:** `route.final` is always set to `proxy` explicitly, because sing-box only falls back to endpoints when `final` names one.
- **DNS:** WireGuard profiles with a `DNS =` resolver use it over UDP through the tunnel. Every other profile uses DNS-over-HTTPS to 1.1.1.1 through the tunnel.
- **Partial `AllowedIPs`:** a WireGuard profile that doesn't route everything becomes the TUN's `route_address` list, so only those prefixes enter the tunnel.
- **Build tags:** `with_gvisor` for the userspace stacks, `with_utls` for REALITY, `with_wireguard` for the endpoint.

`core/vpn-engine/src/access.rs` is the single entry point that turns a credential into an `Outbound`. It is used both when importing (to validate) and when connecting (to re-validate the sealed original).

## AmneziaWG endpoint

sing-box has no AmneziaWG support. Rather than fork it, `core/outline-worker/internal/awg` registers a new endpoint type, `amneziawg`, that reuses sing-box's WireGuard plumbing around unmodified **amneziawg-go v3** (`github.com/amnezia-vpn/amneziawg-go/v3`, MIT):

- **Network stack:** sing-box's exported gVisor stack device (`transport/wireguard.NewDevice`). Its `tun.Device` method set matches amneziawg-go's exactly, except for the `Event` type, which a small adapter converts.
- **Client sockets:** a bind adapted from sing-box's `ClientBind`. It sends through sing-box's dialer, so UDP binds to the physical interface and never loops back into the TUN. **It must not rewrite packet bytes.** sing-box's original overwrites bytes 1–3 for Cloudflare WARP's "reserved" field, which is exactly where AmneziaWG's magic headers sit.
- **Server sockets:** amneziawg-go's standard bind on `listen_port`. Incoming flows go to sing-box's router, with each peer's `user` attached, so `auth_user` rules apply to WireGuard/AmneziaWG users the same way as to Shadowsocks and VLESS users.
- **Configuration safety:** obfuscation values are written through amneziawg-go's UAPI from an allowlist of parameter names. Values containing `=`, CR/LF or NUL are refused, so a config cannot inject other UAPI settings.
- **Plain WireGuard:** the same endpoint with zero obfuscation parameters interoperates with a stock WireGuard client. The client side still uses sing-box's native endpoint for plain WireGuard.

Interop tests in `internal/awg` run against the real upstream peer:
- upstream amneziawg-go with legacy, 2.0 and zero parameters;
- an upstream AWG 2.0 client against our server;
- a stock WireGuard client against our server;
- per-user rules;
- a mismatched header, which must fail.

## Import formats

| Format | Parser | Notes |
|---|---|---|
| `ss://`, `ssconf://` | `outline.rs` | Modern AEAD only; dynamic keys over verified HTTPS to public hosts, pinned DNS, no redirects, 64 KiB cap |
| `vless://`, Xray JSON | `vless.rs` | `security` must be `reality` or `tls`; flow empty or `xtls-rprx-vision`; transport TCP/raw only; uTLS fingerprints map `hellochrome_*` to `chrome` |
| `.conf` | `wireguard.rs` | One `[Peer]`; AmneziaWG keys map to UAPI names; `HeaderProtectionKey` base64 → hex and requires S1–S4 ≥ 12; `RandomTrailers`/`DisableCookies` → `true`/`false`; legacy `J1`–`J3`/`Itime` ignored |
| `vpn://` | `amnezia.rs` | `vpn://` + base64url(4-byte big-endian length + zlib(JSON)). Containers `amnezia-awg2`, `amnezia-awg`, `amnezia-wireguard` and `amnezia-xray` are supported. `last_config` is a JSON *string*; its `config` text goes through `wireguard.rs` |

Always rejected:
- `.conf`: `PreUp`/`PostUp`/`PreDown`/`PostDown`, `Table`, `FwMark`, `SaveConfig`, unknown keys and malformed keys.
- `AdvancedSecurity = on`: amneziawg-tools reports it as EINVAL in userspace mode.
- Amnezia keys containing `userName`/`password`: these are full-access keys carrying the server's SSH login.
- Amnezia API/subscription keys.

## Split tunneling

The policy lives in the daemon:
- the global policy in `Store.routing_policy`;
- per-server overrides in `StoredProfile.routing_override`, which survive a `--replace` import.

It is owner-only and validated by `core/vpn-engine/src/split.rs`. The generated route rules are, in order:

1. `sniff`, so protocol (DNS) and site names (TLS SNI, HTTP Host, QUIC) are known;
2. the health proxy is pinned to `proxy`, because otherwise "only" mode would let the health check succeed without the tunnel;
3. IPv6 from the TUN is rejected;
4. DNS is hijacked;
5. the policy rules: bypass sends matches to `direct`, "only" sends them to `proxy`. App rules use `process_name`/`process_path` with `find_process`.

`final` is `proxy`, or `direct` in "only" mode. Bypassed sites resolve through the local resolver; in "only" mode, listed sites resolve through the tunnel.

"Keep LAN direct" is an `ip_is_private` rule, not a TUN route exclusion. Excluding RFC 1918 from the TUN would also exclude the TUN's own 172.28.85.0/30 DNS address. The `direct` outbound binds to the physical interface through `auto_detect_interface`.

Limits: OpenVPN profiles ignore the policy, and site rules cannot see names that are hidden (ECH, hard-coded IPs). The real-engine test `split_tunnel_rules_route_by_ip_and_site` checks full, bypass-by-IP, bypass-by-site (via Host sniffing) and "only" routing, and that the health probe stays in the tunnel.

## Process notes

- The worker ignores `SIGPIPE` on Unix (`sigpipe_unix.go`). A broken status pipe returns an error instead of killing the worker before its graceful engine shutdown.
- Status events are fixed JSON codes; upstream logs stay disabled so no credential or address reaches the daemon.
