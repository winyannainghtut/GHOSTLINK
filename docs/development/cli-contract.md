# CLI / local API v1

Transport: one newline-delimited UTF-8 JSON request and response per local IPC connection; maximum frame 2 MiB. The Rust enums in `packages/shared-contracts/src/lib.rs` are the authoritative request model. Unknown fields/actions and unsupported schema versions are rejected. Response and status JSON schemas are checked by process integration tests.

Success:

```json
{"schema_version":1,"success":true,"data":{"status":"disconnected","profile":null,"server":null,"vpn_ip":null,"protocol":null,"connected_duration_seconds":0,"bytes_received":0,"bytes_sent":0,"receive_bytes_per_second":0,"send_bytes_per_second":0,"last_error":null}}
```

Failure:

```json
{"schema_version":1,"success":false,"error":{"code":"not_found","message":"VPN profile does not exist"}}
```

`connected` is observed engine/interface and health state. `vpn_ip` is a local tunnel interface address, not a public egress IP. Stored server metadata is configuration supplied by the user/provider; it is not a claim that the endpoint was reached. Byte counts and rates are engine counters; unsupported/unmeasured diagnostics are explicitly `not_tested`.

Exit codes: 0 successful command, 1 connection/internal/cleanup failure, 2 invalid input/profile or missing profile, 3 permission denied, 4 service/engine unavailable or unsupported, 5 timeout, 6 busy, 130 interrupted. `doctor` can return exit 4 with a successful diagnostics envelope when no supported engine is installed: request completion and installation health are distinct.

Connection states: `disconnected`, `connecting`, `connected`, `reconnecting`, `disconnecting`, `failed`. Connect/switch are idempotent for an already active selected profile. Switching validates the new profile before disconnecting the old one, and refuses a new start if prior network cleanup could not be verified. Switching has no persistent kill-switch guarantee. `reconnecting` is reported only for a session that was previously verified healthy; a first connection stays `connecting` until it succeeds or times out. If autoconnect fails at service startup with an internal error, the service keeps running and reports `failed` with `last_error: "autoconnect_failed"`.

`routing_policy_get` (optional `profile`) returns the global split-tunneling policy, or a server's override with `follows_global`. `routing_policy_set` takes an optional `profile` and an optional `policy` `{mode: "full"|"bypass"|"only", domains, ip_ranges, apps, lan_direct}`; `policy: null` clears a server override or resets the global policy. Entries are validated and normalized (at most 512 sites and IP ranges, 128 apps), and the change applies at the next connection. Agent tokens are refused for both actions. The CLI exposes them as `ghostlink split show|set|clear`.

## Managed servers

These actions administer [Ghostlink servers](../deployment/ghostlink-server.md). All of them are owner-only: agent tokens are refused.

| Action | Fields | Returns |
|---|---|---|
| `managed_server_add` | `name`, `management_key` (the JSON key text), optional `replace` | `{name, endpoint, server_name, version, added_unix, protocols}` after the server answered with the pinned certificate |
| `managed_server_list` | none | `{servers: [{name, endpoint, server_name, version, added_unix}]}`; never the key |
| `managed_server_remove` | `name` | `{removed}`; the server itself is unchanged |
| `server_call` | `server`, `op` | The server's JSON answer for that operation |

`op` is one of these typed operations (`{"op": "<name>", ...}`). There is no raw HTTP:

- `info`
- `update {patch}`
- `users_list`
- `user_create {change}`
- `user_update {user, change}`
- `user_delete {user}`
- `keys_list {user}`
- `key_create {user, protocol, import_as?, auth?, server_address?, remote_identifier?, local_identifier?}`: `auth` and the identifiers only for `ikev2` (`eap` or `certificate`) and `ipsec` (`certificate` or `psk`); those keys can't be imported here
- `key_profile {user, key, prompt_password, on_demand}`: an IKEv2/IPsec key's Apple configuration profile, answered as a string
- `key_delete {user, key}`
- `rules_get`
- `rules_set {rules}`
- `metrics`
- `live`: speeds, open connections, online users, server health
- `stats {range, user?}`: `range` is `24h`, `7d`, `30d` or `90d`
- `clients {user?}`: addresses users connected from
- `key_qr {user, key, format, content?}`: `format` `svg` or `text`; `content` `auto`, `key` or `conf`. Answered as a string.
- `kit {user}`: the HTML connection kit, answered as a string
- `mesh_info`: [mesh](../deployment/mesh.md) settings, node counts and open invites
- `mesh_update {patch}`: `patch` takes `enabled`, `cidr` (only before the first node joins), `name` and `ping`
- `mesh_invite_create {invite}`: `invite` takes `tags`, `uses`, `expires_hours`, `relay`, `approval` and `note`. The answer carries the secret `invite` and the join `command`, once.
- `mesh_invite_list`, `mesh_invite_delete {invite}`
- `mesh_node_update {node, change}`: `change` takes `name`, `tags`, `status` (`active` or `disabled`), `relay`, `approved_routes` and `masquerade`
- `mesh_node_delete {node}`
- `mesh_rules_get`, `mesh_rules_set {rules}`: each rule is `{from, to, protocol, ports}`. `from`/`to` are `*`, `tag:NAME` or `node:NAME`; `protocol` is `tcp`, `udp`, `icmp` or `any`; `ports` are like `5432` or `8000-8100`.
- `mesh_topology`: nodes and links for the map (online state, path `direct`/`relay`/`down`, latency, traffic)

User, key, invite and node IDs must be decimal. Mesh names and tags are lower-case letters, digits and hyphens; the service checks rule selectors, protocols and port syntax before calling. `protocol` is `amneziawg`, `wireguard`, `vless`, `shadowsocks`, `ikev2` or `ipsec`. `update` also takes `rotate_ipsec_psk`. With `import_as`, the new key is also saved as a VPN server on this device. The answer then carries `imported` (the profile summary) or `import_error`, and the key is never lost.

The service makes these calls without holding its main lock, so a slow server never delays status, connect or disconnect. It keeps one pinned connection per managed server and reuses it, so polling `live` every few seconds does not repeat the TLS handshake. Replacing or removing the server drops the connection. A management key is parsed strictly:
- only `apiUrl` and `certSha256` are allowed;
- the URL must be plain `https` with a 16–128 character URL-safe secret path and no query;
- the pin must be 64 hex digits.

The key is sealed in service state. Parse errors are fixed messages that never echo the key.

Extra error codes:

| Code | Meaning | Exit code |
|---|---|---|
| `server_unreachable` | No answer in time | 1 |
| `server_identity_mismatch` | The certificate did not match the pin; nothing was sent | 1 |
| `server_error` | The server failed, or sent a malformed or oversized (> 1 MiB) answer | 1 |
| `unsupported` | The address answered but is not a Ghostlink server, for example an Outline server | 4 |

A server's own validation message comes back as `invalid_request` (exit 2), and its `404` comes back as `not_found` (exit 2).

CLI: `ghostlink server install-help | add | list | remove | info | set | users list|add|update|remove | keys list|create|remove|qr|kit|profile | rules show|set | usage | live | stats | clients | mesh show|enable|disable|invite|invites|revoke|nodes|node|remove|rules`. `server mesh invite --output FILE` writes the join command to a NEW private file and leaves it out of the answer. `server mesh rules --rule "FROM TO PROTOCOL [PORTS]"` (repeatable) replaces the rules, and `--clear` removes them. `server mesh node --node ID` takes `--name`, `--tags`, `--status active|disabled`, `--relay on|off`, `--routes CIDR,…|none` and `--masquerade on|off`. `server set` also takes `--site-stats on|off`, `--history-days`, `--site-days`, `--history-max-mb`, `--rotate-ipsec-psk` and `--default-speed-limit MB/s|none`. `server users add` and `server users update` take `--speed-limit MB/s|none|default`: megabytes per second (10^6 bytes, 0.001 to 1250, download and upload alike), `none` for no limit whatever the server's default (`speed_limit_bps: -1`), or `default` (`0`). They map to `UserChange.speed_limit_bps` and `ServerPatch.default_speed_limit_bps`, in bytes per second. The Outline import (`POST /import/outline`) is not an operation of the service: it runs on the server host (`sudo ghostlink-server migrate-outline`), and AI agents cannot reach it. `keys kit --output FILE` writes a NEW private file. `keys create --protocol ikev2|ipsec` takes `--auth`, `--server-address`, `--remote-id` and `--local-id`, and refuses `--output`/`--import`. `keys profile --key ID --output FILE [--prompt-password] [--on-demand]` saves the Apple profile to a NEW private file. The management key is read with `--key-file` or `--key-stdin` only. `keys list` hides key material unless `--show-keys` is given. `keys create` prints the key, unless `--output FILE` (a NEW private file, plus `FILE.conf` for WireGuard and AmneziaWG) or `--import` is used. The CLI never overwrites an existing file.

`access_key_import` and `profile_import` take an optional `replace` boolean (default `false`). Without it, an existing ID returns `invalid_request` (exit 2) instead of overwriting the saved credential. The CLI exposes it as `--replace` on `key add` and `profile import`.

The client has a configurable total wait (default 75 seconds). A timeout or Ctrl+C stops the client wait, not an accepted service operation. Use status to determine actual state, and disconnect to request cleanup. `--no-wait` is suitable for a controller that polls status itself.

Keys and certificate material are write-only inputs. Agent token issuance is an internal private IPC exception: the CLI consumes the one-time secret into a new protected file, removes it from printed JSON and returns `token_saved: true`. No standard status, metadata or audit response returns a credential. The `sha256` fingerprint of an access key is keyed with a per-installation secret, so it cannot be used to test password guesses.

MCP read tools are available only with an issued agent token. Connection tools additionally need a control grant and server `--allow-control`. Profile import, agent grants, split tunneling, server administration, arbitrary shell commands and arbitrary engine configuration are never MCP tools.
