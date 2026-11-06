# Outline access-key update

The user's 2026-10-30 clarification makes Outline-compatible access keys and an Outline-style client UI the primary experience. `ss://` keys contain Shadowsocks credentials; they cannot authenticate an OpenVPN connection. Existing OpenVPN support remains an optional backend.

Inspected Outline Apps `ce518e8c058d4db9100ec27d15bc071a246a2274`, Outline SDK `45e87213a473ff573378eb5f42081f71aff76664`, their Apache-2.0 licenses, access-key/config parsers, desktop VPN/routing services, and UI tokens. Their code confirms static SIP002/legacy keys, dynamic `ssconf://` HTTPS retrieval, server cards, rename/remove/details, and platform-specific routing. No Outline logos or product names are reused as Ghostlink branding.

## Desktop engine decision

Updated 2026-11-06: use the separate Ghostlink managed tunnel worker in `core/outline-worker`, linking unmodified, pinned sing-box 1.14.4 libraries for native TUN and Shadowsocks transport. The earlier standalone CLI process was replaced because forcibly ending it on Windows cannot establish graceful route/DNS cleanup. The worker holds a private stdin control pipe: an explicit stop, parent EOF, or termination signal cancels the engine and calls its bounded `Close()`. JSON lifecycle events contain fixed codes and an OS-observed interface address; a proxy-only process cannot invent a VPN address. Cleanup failure blocks reconnect until investigated.

The Rust daemon checks the worker version, owns a private temporary configuration, verifies local controller/proxy listener ownership before sending credentials, and requires a real proxied HTTPS health check before connected state. The Outline SDK reference VPN CLI is Linux-only; Outline Apps adds its own Windows routing service and older TAP stack. This process boundary retains typed configuration and upstream protocol/cryptographic code. It provides wire compatibility with standard Outline keys; it does not embed Outline's SDK. The worker has GPL and corresponding-source obligations documented separately.

Only modern AEAD methods are accepted. `ss://` SIP002, plain percent-encoded credentials and legacy whole-key base64 are parsed. Dynamic `ssconf://` URLs use verified HTTPS, pinned public DNS resolution, no redirects and a 64 KiB response limit. Static ss:// and legacy JSON responses are supported; advanced YAML transports, prefixes and plugins are explicitly rejected. Dynamic keys are re-fetched at connect so provider rotations take effect.

Keys are submitted through a private GUI IPC command or CLI stdin/file, never a shell argument. The daemon seals them with DPAPI on Windows and protects Linux state with root-only permissions. Profile lists, status and audit logs contain metadata only. Access-key output/reveal is deliberately absent.

No connection is marked established merely because a process exists. The native engine must finish TUN startup and an HTTPS request through its credential-protected local proxy must succeed. Connection monitoring clears connected state when health checks fail. Routed-traffic, DNS leak, IPv6 leak and crash recovery still need administrator/device validation; no persistent kill-switch guarantee is made.
