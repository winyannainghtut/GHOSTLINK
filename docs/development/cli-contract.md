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

`access_key_import` and `profile_import` take an optional `replace` boolean (default `false`). Without it, an existing ID returns `invalid_request` (exit 2) instead of overwriting the saved credential. The CLI exposes it as `--replace` on `key add` and `profile import`.

The client has a configurable total wait (default 75 seconds). A timeout or Ctrl+C stops the client wait, not an accepted service operation. Use status to determine actual state, and disconnect to request cleanup. `--no-wait` is suitable for a controller that polls status itself.

Keys and certificate material are write-only inputs. Agent token issuance is an internal private IPC exception: the CLI consumes the one-time secret into a new protected file, removes it from printed JSON and returns `token_saved: true`. No standard status, metadata or audit response returns a credential. The `sha256` fingerprint of an access key is keyed with a per-installation secret, so it cannot be used to test password guesses.

MCP read tools are available only with an issued agent token. Connection tools additionally need a control grant and server `--allow-control`. Profile import, agent grants, arbitrary shell commands and arbitrary engine configuration are never MCP tools.
