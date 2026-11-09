# Ghostlink Code Review

**Review date:** November 9, 2026 (Asia/Singapore)  
**Reviewed version:** v0.8.3  
**Reviewed commit:** `6ad3b229ad0d59dc8e7e33596c278be848de1558`  
**Findings:** 2 P1 findings and 4 P2 findings

This report records the earlier review of the clean v0.8.3 checkout. Subsequent working-tree changes have not been assessed by this report. Source links point to the reviewed commit so their locations remain stable.

The review focused on server protocol configuration, port validation, mesh access control, desktop administration flows, IPC authorization, and health reporting. Findings describe correctness and security issues rather than style preferences. No production source changes were made as part of the review.

## Findings at a Glance

| ID | Priority | Finding | Evidence | Previously documented |
| --- | --- | --- | --- | --- |
| F1 | P1 | Docker rule ordering can bypass mesh access rules | Source inspection and existing repository notes | Yes |
| F2 | P1 | A pending administration operation can continue against a different server | Reproduced with mock transports using the real API module | No |
| F3 | P2 | Port ownership checks do not distinguish TCP from UDP | Reproduced with local listeners and the server API | No |
| F4 | P2 | Swapping dashboard and VPN protocol ports fails | Reproduced with a running local dashboard and Shadowsocks listener | No |
| F5 | P2 | Mesh address changes trigger unnecessary VPN engine restarts | Reproduced by changing the interface-address provider and observing engine reloads | Yes |
| F6 | P2 | The UI can display “Live” while the VPN engine is down | Source inspection; existing backend tests cover engine startup failure | Yes |

**P1:** Address promptly because the issue can bypass access restrictions or mutate the wrong server.  
**P2:** Fix in a planned development cycle because the issue causes incorrect behavior, connection disruption, or misleading operational status.

## F1 — Docker Rule Ordering Can Bypass Mesh Access Rules

**Priority:** P1  
**Status:** Previously documented, still present in the reviewed version

### Source

- [hostfw.go:116 — EnsureJumps](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/hostfw/hostfw.go#L116)
- [hostfw.go:129 — HasJumps](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/hostfw/hostfw.go#L129)
- [meshagent/agent.go:252 — keepFirewall](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/meshagent/agent.go#L252)

### Trigger and Cause

The mesh agent inserts its firewall jumps at the beginning of their chains when those jumps are missing. Later checks use `iptables -C`, which verifies that a rule exists but does not verify its position.

If Docker starts or restarts after the mesh agent and inserts accepting rules ahead of Ghostlink's jumps, the periodic check still reports success. Traffic accepted by an earlier rule never reaches the mesh access rules.

### Impact

Mesh nodes can reach published container ports even when mesh access rules should deny that traffic. The intended destination checks exist, but rule ordering can prevent them from running.

### Evidence and Limits

Confirmed through source inspection and the existing outstanding-issue notes in `agent.md`. A Linux/Docker runtime reproduction was not performed during this review.

### Recommended Fix

Integrate mesh filtering into an appropriate Docker enforcement path, such as `DOCKER-USER`, or otherwise guarantee that mesh restrictions run before accepting rules. Account for other firewall managers rather than repeatedly competing for the first rule position.

Add a Linux integration test that starts the mesh agent, starts or restarts Docker, and verifies that a denied published port remains unreachable.

## F2 — A Pending Administration Operation Can Continue Against a Different Server

**Priority:** P1  
**Status:** Newly identified in this review

### Source

- [api.ts:141 — Global mutable transport](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/ui/admin/api.ts#L141)
- [api.ts:150 — API dispatch through the current transport](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/ui/admin/api.ts#L150)
- [NewClient.tsx:78 — Sequential client and key creation](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/ui/admin/views/NewClient.tsx#L78)
- [ServersIRun.tsx:116 — Transport replacement when opening a workspace](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/ui/desktop/src/views/ServersIRun.tsx#L116)

### Trigger and Cause

The administration API resolves a global `transport` separately for each request. The new-client flow first awaits client creation and then sends a second request to create that client's key.

While the first request is pending, the administrator can close the sheet, leave server A, and open server B. Opening B replaces the global transport. When A's request completes, the next request uses B's transport.

### Reproduction

A mock-transport check imported the real `ui/admin/api.ts` module, delayed the first response, replaced the transport, and then released the response. The observed request sequence was:

```text
A: POST /users
B: POST /users/1/keys
```

### Impact

One user action can create a client on A and attempt to create its key on B. If the same numeric client ID exists on B, the operation can issue a key for the wrong client on the wrong server.

### Recommended Fix

Scope the transport to the workspace, for example through React context. Capture the same server-bound transport for every request in a multi-step operation. Also cancel or invalidate pending UI work when its workspace is unmounted.

Add a regression test that switches workspaces between the client-creation and key-creation responses and verifies that no request reaches the second server.

## F3 — Port Ownership Checks Do Not Distinguish TCP from UDP

**Priority:** P2  
**Status:** Newly identified in this review

### Source

- [render.go:474 — heldPorts](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/render.go#L474)
- [api.go:399 — Port availability checks](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/api.go#L399)

### Trigger and Cause

`heldPorts()` returns a `map[uint16]bool`, so it records only a port number. The validation code treats any recorded number as already owned by Ghostlink and skips its bind check, regardless of transport.

TCP and UDP can legitimately share a port number. Owning UDP port N does not establish ownership of TCP port N.

### Reproduction

1. Run WireGuard on UDP port N with an active key.
2. Configure disabled VLESS to use TCP port N.
3. Bind TCP port N with another local program.
4. Enable VLESS, then request its first key.

Observed results:

```text
Enable VLESS:          HTTP 200
Create first key:      HTTP 500
```

The enable operation succeeds because the existing WireGuard listener causes the TCP availability check to be skipped. The conflict is discovered only when key creation starts the VLESS listener.

### Impact

The server reports that a protocol was enabled successfully even though it cannot start its listener. Administrators encounter a delayed internal error during key creation.

### Recommended Fix

Track ownership by `(transport, port)` and skip availability checks only for the matching transport. Add regression coverage for an owned UDP port with a conflicting external TCP listener, and the inverse case.

## F4 — Swapping Dashboard and VPN Protocol Ports Fails

**Priority:** P2  
**Status:** Newly identified in this review

### Source

- [api.go:399 — Exemption for previously held ports](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/api.go#L399)
- [service.go:272 — Engine application before state persistence](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/service.go#L272)
- [main.go:186 — Dashboard update after the saved change](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/cmd/ghostlink-server/main.go#L186)

### Trigger and Cause

A single server patch moves the dashboard to the current Shadowsocks port and Shadowsocks to the current dashboard port.

Validation allows the previously held ports, but the engine is restarted before the dashboard listener is moved. Shadowsocks therefore attempts to bind the port that the dashboard still holds. The post-save dashboard hook is never reached because engine startup fails first.

### Evidence

Reproduced using a running local dashboard and an active Shadowsocks listener. The patch returned HTTP 500 with a TCP bind conflict.

### Impact

An otherwise valid port swap cannot be completed atomically. The implementation's allowance for previously held ports does not cover the dashboard's separate listener lifecycle.

### Recommended Fix

Coordinate listener release, engine startup, dashboard startup, and rollback within one change operation. If atomic swaps are intentionally unsupported, reject them explicitly with an actionable validation error.

## F5 — Mesh Address Changes Trigger Unnecessary VPN Engine Restarts

**Priority:** P2  
**Status:** Previously documented; reproduced again in this review

### Source

- [render.go:298 — serverAddresses](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/render.go#L298)
- [service.go:134 — startEngine](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/service.go#L134)

### Trigger and Cause

The host-address enumeration treats addresses in `100.64.0.0/10`, including the default mesh range `100.96.0.0/16`, as public host addresses and adds them to the explicit destination blocks.

These ranges are already blocked by the existing internal-range rules. Adding or removing a mesh address nevertheless changes the serialized engine configuration. The periodic engine check then restarts the engine.

### Evidence

A regression check changed the interface-address provider to include `100.96.0.1` and called the engine check. The observed engine reload counter changed:

```text
Before adding mesh address: 2
After adding mesh address:  3
```

This used a simulated interface-address change with a real local engine; it did not join a real mesh.

### Impact

Mesh join, leave, or agent restart can interrupt existing VPN connections even though the effective destination restrictions have not changed.

### Recommended Fix

Exclude addresses already covered by the unconditional internal blocks from the explicit host-address list. Preserve engine restarts for address changes that actually require a new restriction.

## F6 — The UI Can Display “Live” While the VPN Engine Is Down

**Priority:** P2  
**Status:** Previously documented, still present in the reviewed version

### Source

- [health.go:26 — Backend engine_error field](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/core/outline-worker/internal/server/health.go#L26)
- [api.ts:93 — UI Health type](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/ui/admin/api.ts#L93)
- [Island.tsx:80 — Status indicator](https://github.com/winyannainghtut/GHOSTLINK/blob/6ad3b229ad0d59dc8e7e33596c278be848de1558/ui/admin/Island.tsx#L80)

### Trigger and Cause

The server deliberately keeps its management API running when the VPN engine cannot start, such as when another process holds a required port. The backend exposes the reason through `health.engine_error`.

The UI Health type omits this field. The status indicator uses enabled protocols and API staleness to choose its presentation, so a responsive management API with an enabled protocol can still produce a green “Live” indicator while the engine is down.

### Impact

Administrators receive a misleading operational status and no visible explanation for failed VPN connections.

### Evidence and Limits

Confirmed through the backend-to-UI code path. The existing Go tests exercise engine startup failure while keeping the API available; those tests passed. A live GUI reproduction was not performed during this review.

### Recommended Fix

Include `engine_error` in the UI contract and display an engine-failure status and actionable error message in both the dashboard and the desktop administration views.

## Verification Performed

| Check | Result |
| --- | --- |
| UI TypeScript typecheck | Passed |
| UI tests | 19 passed |
| Rust workspace tests | 51 passed; 6 opt-in traffic tests ignored |
| Desktop Rust tests | 2 passed |
| Go test suite with the required build tags | Passed |
| Process integration tests using fresh debug builds | 19 passed |
| Additional review regression checks | 4 checks exposed the expected failures: F2, F3, F4, and F5 |

The additional checks were kept outside tracked production source and used a Go overlay or mock transports. Their assertion failures demonstrate the reviewed defects; they are separate from the passing standard test suites.

Representative commands:

```powershell
# From ui/
npm run typecheck
npm test

# From the repository root
./scripts/cargo.ps1 test --locked --workspace
./scripts/cargo.ps1 test --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
./scripts/cargo.ps1 build --locked --workspace
npm test

# From core/outline-worker/
go test -tags with_gvisor,with_utls,with_wireguard ./...
```

For the final process-test run, `GHOSTLINK_TEST_SERVER` pointed to a freshly built, isolated server executable.

## Verification Limits

- The six opt-in Rust traffic tests were not executed.
- Linux/Docker firewall behavior was assessed through source and repository notes, without starting Docker or changing the host firewall.
- Real-device full-tunnel routing, DNS/IPv6 leak behavior, the Windows MSI, and Apple-device profiles were not tested.
- The review did not modify production source or commit any changes.
- Findings F1, F5, and F6 were already listed as outstanding issues in the reviewed `agent.md`.

## Resolution in v0.8.4

Added after the review, when the fixes shipped. The CHANGELOG's 0.8.4 section and the verification ledger have the details.

| ID | Fix | Tests |
| --- | --- | --- |
| F1 | The mesh agent also keeps its FORWARD jumps first in Docker's `DOCKER-USER` chain, which Docker checks before its own accept rules and never changes (`hostfw`, `Jump.Docker`); it adds them within 30 s of Docker making the chain, and starts after `docker.service` at boot. The IPsec component's jump gets no copy, because its chain counts speed limits and a packet would pass it twice; that limit is recorded in `agent.md`. | `TestDockerCopies`; `tests/mesh/e2e.sh` puts Docker's chains ahead of the agent's and checks that a denied published port stays unreachable |
| F2 | No shared transport: each server's views get their own API from their `StoreProvider` (`bindApi`, `useApi`), so every request of an action goes to the server it started on. | `ui/tests/api.test.mjs`; a desktop GUI check that holds A's answer back while B is opened |
| F3 | Held ports are tracked per transport (`heldPort{network, port}`), and the bind check is skipped only on the matching transport. | `TestHeldPortsCountPerTransport`, both directions |
| F4 | Explicitly refused, with what to do instead (move the dashboard first, then the protocol), because the dashboard moves only after the engine restarts. | `TestSwappingTheDashboardPortTakesTwoChanges` |
| F5 | Host addresses inside the always-blocked internal ranges are left out of the explicit blocks, so a mesh address coming or going changes nothing. | `TestMeshAddressesDoNotChangeTheEngine` |
| F6 | `engine_error` is in the UI's `Health` type; the Island shows *VPN engine down*, and its panel and the Overview show the error, in the dashboard and the desktop app. | The desktop GUI check, with a real engine failure, in two finishes |
