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

Connection states: `disconnected`, `connecting`, `connected`, `reconnecting`, `disconnecting`, `failed`. Connect/switch are idempotent for an already active selected profile. Switching validates the new profile before disconnecting the old one, and refuses a new start if prior network cleanup could not be verified. Switching has no persistent kill-switch guarantee.

The client has a configurable total wait (default 75 seconds). A timeout or Ctrl+C stops the client wait, not an accepted service operation. Use status to determine actual state, and disconnect to request cleanup. `--no-wait` is suitable for a controller that polls status itself.

Keys and certificate material are write-only inputs. Agent token issuance is an internal private IPC exception: the CLI consumes the one-time secret into a new protected file, removes it from printed JSON and returns `token_saved: true`. No standard status, metadata or audit response returns a credential.

MCP read tools are available only with an issued agent token. Connection tools additionally need a control grant and server `--allow-control`. Profile import, agent grants, arbitrary shell commands and arbitrary engine configuration are never MCP tools.
