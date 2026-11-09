# Ghostlink v0.8.4 Follow-up Code Review

**Date:** November 10, 2026 (Asia/Singapore)  
**Reviewed commit:** `05daf2ad32e9083251281d644c89af7e3b9378be`  
**Comparison:** v0.8.3 (`6ad3b22`) to v0.8.4 (`05daf2a`)  
**Open findings:** One residual P1 security issue and one additional P2 correctness issue

The review checked the six findings from [the previous review](code-review-2026-11-09.md), the implementation and regression tests for their fixes, and the new low-port capability handling. The working tree was clean when the review started. No production source changes were made.

## Findings

### R1 — P1: Docker startup still exposes a temporary mesh ACL bypass, and admitted connections can outlive the repair

**Classification:** Residual issue in the F1 fix; not a newly introduced regression.  
**Evidence:** Source inspection. Linux/Docker packet behavior was not exercised locally.

**Source:**

- [meshagent/agent.go:253 — Periodic firewall repair](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/core/outline-worker/internal/meshagent/agent.go#L253)
- [hostfw.go:130 — Discovering Docker's chain](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/core/outline-worker/internal/hostfw/hostfw.go#L130)
- [meshagent/render.go:110 — Accepting established forwarded connections](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/core/outline-worker/internal/meshagent/render.go#L110)
- [tests/mesh/e2e.sh:170 — Waiting for the Docker-chain repair before testing denial](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/tests/mesh/e2e.sh#L170)

The new `DOCKER-USER` copies address the persistent ordering problem once installed. However, if Docker starts after the mesh agent, its accepting rules can take effect before the agent discovers the new chain. `keepFirewall()` waits at least 30 seconds between checks, so enforcement is restored asynchronously rather than continuously. Actual repair timing also depends on the agent's sync loop.

During that interval, a node denied by the mesh ACL can initiate a connection to a published container port. Repairing the jumps does not necessarily end that connection: `GHOSTLINK-MESH-FWD` accepts `RELATED,ESTABLISHED` traffic before evaluating destination allow rules. The connection can therefore remain usable after repair. This persistence is an inference from the rendered rule ordering, not a locally observed Docker session.

`After=docker.service` helps when both services start at boot, but it does not cover Docker being installed or started later. The new end-to-end test reproduces late creation of Docker's chains, then waits for repair before testing denied traffic; it does not test access during the interval or retain an unauthorized connection across the repair.

**Recommended action:** Preserve a fail-closed mesh enforcement path while Docker installs or replaces its forwarding rules. Also address connections admitted during any enforcement gap. Extend the Linux test to attempt a denied connection immediately after Docker's rules take precedence, retain that connection, and verify both initial denial and behavior after repair.

### R2 — P2: A stopped engine's configured ports are still treated as currently owned

**Classification:** Additional failure-recovery case missed by the F3 fix; not established as a v0.8.4 regression.  
**Evidence:** Reproduced against the current server with a local TCP listener and a Go test overlay.

**Source:**

- [render.go:505 — heldPorts](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/core/outline-worker/internal/server/render.go#L505)
- [api.go:343 — Taking the pre-change ownership snapshot](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/core/outline-worker/internal/server/api.go#L343)
- [api.go:409 — Skipping the availability check for an owned port](https://github.com/winyannainghtut/GHOSTLINK/blob/05daf2ad32e9083251281d644c89af7e3b9378be/core/outline-worker/internal/server/api.go#L409)

Tracking ownership by `(transport, port)` fixes the original TCP/UDP confusion. However, `heldPorts()` still derives engine-owned listeners from the saved configuration, through `s.inbounds()` and `s.endpoints()`. It does not establish whether the engine successfully started and actually owns those sockets.

When startup fails because another process holds a configured port, the management API remains available. An administrator can then submit a change that reassigns that occupied port to another protocol. The old configuration makes the port appear owned, so its availability check is skipped.

**Reproduction:**

1. Start a server with an active Shadowsocks key on TCP/UDP port N while another program holds TCP N. Confirm that the engine is down and the management API is available.
2. Submit one patch that disables Shadowsocks, moves its reserved port to a free port M, and enables VLESS on TCP N without any VLESS keys.
3. Request the first VLESS key.

**Observed result:**

```text
Configuration patch:   HTTP 200
First VLESS key:       HTTP 500
```

The patch succeeds because the occupied port is incorrectly considered owned, and an enabled protocol with no keys creates no listener. The conflict is discovered only when the first key requires VLESS to start.

**Expected result:** Reject the patch with HTTP 400 and an occupied-port explanation before saving it.

**Recommended action:** Base the bind-check exemption on live engine ownership. At minimum, do not exempt configured engine listeners while the engine is down. Keep separately managed listeners distinct, and add this startup-failure/reassignment case to the port-validation tests.

## Disposition of the Previous Six Findings

| Previous finding | v0.8.4 assessment | Basis |
| --- | --- | --- |
| F1: Docker ordering bypass | Partially resolved; R1 remains | `DOCKER-USER` copies close the persistent bypass after installation. Late Docker startup still leaves an enforcement interval. |
| F2: Requests crossing server workspaces | Resolved in the reviewed code | `bindApi()` captures a transport; each workspace supplies its own context and keyed store. All three new API tests pass. |
| F3: TCP/UDP ownership confusion | Original case resolved; R2 is an additional edge case | Ownership is keyed by transport and port. The new two-direction conflict test passes. Ownership while the engine is down still needs correction. |
| F4: Dashboard/protocol swap returns an engine error | Resolved through explicit validation | The unsupported single-change swap now returns an actionable HTTP 400. The documented staged move is covered by a passing test. |
| F5: Mesh addresses restart the engine | Resolved in the reviewed code | Addresses covered by internal blocks are excluded from the dynamic explicit host-address list. The regression test passes. |
| F6: UI says Live while the engine is down | Resolved in the reviewed code | The UI contract includes `engine_error`; the Island and Overview render the failure. Both UI bundles rebuild identically. A new live GUI check was not performed in this review. |

## Low-Port Capability Handling

The new Linux account transition, capability reduction, re-execution, port-floor detection, and package startup flags were inspected. No additional actionable defect was identified in those code paths during this review.

Linux/amd64 `go vet` passed for the server command, host firewall, and server packages. This is static validation: the root-to-service-account transition, ambient capability inheritance, and binding port 443 inside the packaged Docker container were not executed locally.

## Verification Performed

| Check | Observed result |
| --- | --- |
| Go suite with `with_gvisor,with_utls,with_wireguard` | All packages passed; server package completed in approximately 159 seconds |
| Rust workspace tests | 51 passed |
| Desktop Rust tests | 2 passed |
| UI TypeScript typecheck | Passed |
| UI tests | 22 passed |
| Dashboard and desktop production builds | Passed; generated bundles produced no tracked changes |
| Process integration suite with fresh debug binaries and server | 19 passed |
| Opt-in encrypted-traffic and worker tests | All 6 passed with a freshly built v0.8.4 worker and the pinned sing-box peer |
| Linux/amd64 `go vet` for the changed server and firewall areas | Passed |
| `release-version.mjs --tag v0.8.4` | Passed; reported `0.8.4` |
| Additional R2 regression check | Failed as expected, exposing the HTTP 200 followed by HTTP 500 behavior |

The R2 check used a Go overlay kept outside tracked source. The assertion failure is separate from the passing standard suites.

The six opt-in tests exercise proxy-mode protocol traffic, worker configuration, split routing, and worker lifecycle. They do not establish full-device VPN routing or leak prevention.

## Limits

- No Docker daemon, Linux network namespaces, or host firewall were started or changed.
- The mesh end-to-end shell test and packaged Linux capability checks were read but not executed locally.
- No real-device full-tunnel, MSI upgrade, phone, or Apple profile checks were performed.
- The installed Ghostlink app and service were not used for development tests.
- Existing known limits concerning IPsec firewall ordering, coordinator firewalld setup, and package upgrade coverage were not counted as new findings.
- The only tracked addition from this review is this report; production source was left unchanged.

## Resolution in v0.8.5

Added after the review, when the fixes shipped. The CHANGELOG's 0.8.5 section and the verification ledger have the details.

| ID | Fix | Tests |
| --- | --- | --- |
| R1 | Two guard chains in the `mangle` table (`GHOSTLINK-MESH-GUARD-IN` and `-FWD`, jumped to from INPUT and FORWARD for `glmesh0`) apply the same rules as the filter chains to every packet a peer sends, except replies (`--ctdir REPLY`) and ICMP errors (`RELATED`): RETURN when allowed, DROP otherwise. Docker's accept rules are in the `filter` table, so they can't run ahead of the guards, and there is no window while the agent notices Docker. A connection let through during any gap in the rules (a full firewall reload) ends as soon as the guards are back, because established connections from the mesh are checked again on every packet. The filter chains and the `DOCKER-USER` copies stay as a second layer. | `TestFirewallRules` (the guards' rules, that they end with DROP and never accept established traffic); `tests/mesh/e2e.sh`: with the agent paused right after Docker's rules come first, the node without a rule is refused at once and the one with a rule still reaches the published port; with the agent paused and all its jumps removed, a connection opened then carries data, and stops once the agent has put its rules back |
| R2 | `heldPorts` reads the engine's ports from the configuration the engine runs (`Engine.Running`), and counts none while it is down; the API, dashboard and mesh listeners stay separate. | `TestAnEngineThatIsDownHoldsNoPorts` (the review's reproduction: refused with 400, not accepted with 200; with the old rule put back it fails); `TestHeldPortsAreThoseThatListenNow` (none while the engine is down) |
