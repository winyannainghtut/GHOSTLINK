# v0.8.6 handoff: IKEv2 DNS and live traffic findings

Reported: 2026-11-10 (Asia/Singapore, UTC+8). Affected release: **0.8.5**.
Source inspected: **cb78ddc2f37c1df93608fd4949187cb4081248e1**, on main.
Intended recipient: Claude agent implementing the fixes for **0.8.6**.

## Requested work

| ID | Priority | Problem | Evidence status |
| --- | --- | --- | --- |
| IKE-01 | P1 | iPhone connects to IKEv2, but ordinary websites fail because DNS replies do not reach the client correctly | Reproduced on the user's running Ubuntu server and iPhone; changing the client's route preferred source restored websites |
| IKE-02 | P2 | IKEv2 live traffic is displayed incorrectly during traffic testing | Reported by the user; source inspection identifies a sampling mismatch to reproduce and fix |

This is a findings document. Implementation and release validation remain outstanding. Read [agent.md](../../agent.md) and [CLAUDE.md](../../CLAUDE.md) before changing the code.

Public and underlay server addresses below are normalized to TEST-NET values. Product pool addresses and the observed DNS listener port are retained. Example identities are anonymized. The normalized commands describe the investigation; their addresses must not be copied into a production fix.

## IKE-01: connected IKEv2 session cannot resolve websites

### Impact and environment

The iPhone successfully authenticates, receives an IPv4 address, and shows the VPN as connected. A direct IP HTTPS request works, while websites requiring DNS fail. This makes the connection appear usable even though ordinary browsing does not work.

Observed environment:

- Ghostlink server 0.8.5; sing-box 1.14.4; amneziawg-go 3.1.20260828.
- Ubuntu Linux with Docker host networking and interface ens5; private underlay behind a public-address NAT.
- iPhone using a Ghostlink-generated IKEv2 profile and EAP-MSCHAPv2.
- IKEv2 pool 10.79.0.0/20; gateway/DNS address 10.79.0.1; client 10.79.0.2.
- Ghostlink DNS listener: TCP and UDP port 23666 on the wildcard address.
- Container resolver configuration: nameserver 127.0.0.53, using the host's systemd-resolved stub.

The exact Ubuntu/iOS versions, CPU architecture, and installation history were not captured.

### Observed evidence

1. Authentication and the IPv4 CHILD_SA succeeded. The component reported running=true and connections=1. Representative log lines, with the identity anonymized:

       EAP method EAP_MSCHAPV2 succeeded, MSK established
       authentication of 'phone-user@ghostlink' with EAP successful
       assigning virtual IP 10.79.0.2 to peer 'phone-user@ghostlink'
       CHILD_SA gl-ikev2{4} established ... TS 0.0.0.0/0 === 10.79.0.2/32

   The accompanying "no virtual IP found for %any6" message concerns the unavailable IPv6 lease. It did not prevent the IPv4 session or direct-IP HTTPS from working.

2. The user opened https://1.1.1.1/cdn-cgi/trace on the iPhone with the VPN connected and confirmed that its text appeared.

3. IPv4 forwarding was enabled. The first FORWARD rule jumped to GHOSTLINK-IPSEC-FWD, ahead of Docker's chains. The IPsec POSTROUTING MASQUERADE rule had nonzero packet/byte counters. This rules out disabled forwarding or a missing NAT rule as the immediate explanation; counters alone do not establish correct return traffic.

4. DNS requests reached the intended redirect and input accept rules:

       GHOSTLINK-IPSEC-PRE:
         417 packets / 28458 bytes
         UDP source 10.79.0.0/20, destination port 53, inbound IPsec policy
         DNAT to 10.79.0.1:23666

       GHOSTLINK-IPSEC-IN:
         1489 packets / 102K bytes
         ACCEPT UDP source 10.79.0.0/20 to 10.79.0.1:23666
         with inbound IPsec policy

       ss:
         UDP *:23666, owned by ghostlink-server
         TCP *:23666, owned by ghostlink-server

   NAT counts represent tracked flows rather than every packet, so the NAT and filter counts need not match.

5. The host resolved example.com successfully. A wider packet capture also showed the application querying 127.0.0.53, systemd-resolved querying the underlay DNS server, and valid upstream DNS answers returning. Thus, this was not simply a broken host/upstream resolver.

6. Packet captures showed repeated requests from 10.79.0.2 to 10.79.0.1:53, including repeated A and HTTPS queries. The captures did not directly establish the decrypted reply's source address at the iPhone; retain that distinction when describing the root cause.

7. The route lookup selected the server's underlay address as its preferred source. Normalized output:

       10.79.0.2 via 192.0.2.1 dev ens5 table 220 src 192.0.2.10

### Workaround confirmed by the user

While the existing VPN session stayed connected, the user replaced only the route for the current client's virtual IP, keeping the gateway/interface and changing its preferred source to the IKEv2 gateway. Normalized operation:

    sudo ip route replace 10.79.0.2/32 via 192.0.2.1 dev ens5 src 10.79.0.1 table 220

The user then retried example.com and google.com and confirmed: **"Website တွေ ပွင့်လာတယ်"** (the websites opened).

The corresponding normalized rollback is:

    sudo ip route replace 10.79.0.2/32 via 192.0.2.1 dev ens5 src 192.0.2.10 table 220

Only the current session was verified after this workaround. Reconnect, rekey, service/container restart, reboot, and other devices were not verified. The manual route may be replaced by strongSwan or removed when the session ends, and must not become the shipped fix.

### Technical assessment and code pointers

The successful route-only change strongly isolates **DNS reply source-address selection**. The current design redirects DNS to a pool gateway while the direct inbound listens on a wildcard socket. A reply sent without retaining the request's local destination can select the underlay source from table 220 instead of the gateway expected by the DNS/NAT flow. Packet-level confirmation of the original and corrected replies should be included in the regression test.

Relevant code:

- [internal/server/render.go](../../core/outline-worker/internal/server/render.go), lines 44-51 and 136-138: wildcard listenAddress and the direct IPsec DNS inbound; routeRules around lines 235-241: pool-only DNS hijacking.
- [internal/ipsecagent/firewall.go](../../core/outline-worker/internal/ipsecagent/firewall.go), Rules around lines 117-127: pool-gateway DNS DNAT, input acceptance, and outbound MASQUERADE.
- [internal/ipsecagent/render.go](../../core/outline-worker/internal/ipsecagent/render.go), Render: advertises the pool gateway as the client's DNS server.
- [internal/ipsecagent/iface_linux.go](../../core/outline-worker/internal/ipsecagent/iface_linux.go): gateway addresses on glipsec0 or loopback.
- Pinned upstream sing-box 1.14.4, protocol/direct/inbound.go: NewPacket, preparePacketConnection, and directPacketWriter.WritePacket; common/listener/listener_udp.go: wildcard UDP socket and reply writer. Inspect the cached dependency locally; keep upstream dependencies unmodified.

### Required fix and acceptance criteria

1. Make DNS replies retain the appropriate local destination/source identity so reverse NAT and the client's expected DNS endpoint remain correct, regardless of the preferred source in strongSwan's route. Choose a robust implementation after reproducing the packet path.
2. Preserve DNS site-block enforcement, the pool-only listener access restriction, and server isolation. Do not bypass Ghostlink DNS using a public resolver or relax firewall policy to hide the failure.
3. Keep the main server unprivileged. Avoid global routing/source-selection changes and hard-coded host addresses, interfaces, ports, client IPs, or table numbers as the application fix.
4. Add a Linux regression test with separate client/server network namespaces, a real underlay route, a pool-gateway DNS destination different from the route's preferred source, and a controlled upstream resolver. It must fail on 0.8.5 and pass with the fix.
5. Verify successful A, AAAA, and HTTPS/SVCB DNS responses over UDP and TCP; blocked-name responses; DNS to another resolver address being redirected; and rejection of sources outside the pools. An AAAA response is a DNS test, not a claim that IPv6 tunneling is supported.
6. Assert the DNS response's source IP/port as observed by the client. A blocked-name NXDOMAIN test or successful host lookup alone is insufficient.
7. Cover reconnect/rekey, multiple concurrent clients, different underlay interfaces/addresses, component/server restarts, and reboot or an equivalent packaged lifecycle test. Check IKEv1/IPsec too because it shares the DNS path.
8. Repeat a real iPhone browsing/download check without the manual route workaround. Record device/OS versions and which checks were actually executed.

### Existing coverage gap

[TestIPsecDNSListener](../../core/outline-worker/internal/server/ipsec_test.go), around line 612, tests a loopback listener/source and blocked-name NXDOMAIN. It does not model a wildcard reply to a separate routed client whose preferred source differs from the pool gateway.

[tests/ipsec/interop.sh](../../tests/ipsec/interop.sh), check_tunnel around lines 124-130, tests HTTP/NAT and blocked-name DNS/redirect behavior in namespaces. Extend it to assert successful upstream resolution and response source identity under the problematic preferred-source route. These tests were inspected for this report; they were not executed during this investigation.

## IKE-02: IKEv2 live traffic does not display correctly

### User report and confidence

The user additionally reports that **IKEv2 live traffic is not displayed correctly during traffic testing**. Include this as a separate 0.8.6 fix item.

No screenshot, timestamped /live responses, transfer byte count/duration, or measured display values were supplied. The affected view and the exact symptom (zero readings, spikes, delay, wrong magnitude, or swapped direction) have not been independently established. Do not present a specific waveform or measured discrepancy as an observed user result.

Source inspection nevertheless identifies a concrete sampling mismatch that should be reproduced first.

### Code evidence and leading hypothesis

| Stage | Current behavior | Location |
| --- | --- | --- |
| IPsec agent | Publishes cumulative CHILD_SA counters roughly every 5 seconds during normal operation; settings changes can trigger extra reports | [ipsecagent/agent.go](../../core/outline-worker/internal/ipsecagent/agent.go), Serve around lines 115-121 and cycle around line 359 |
| Counter extraction | Reads bytes-in and bytes-out from strongSwan VICI CHILD_SAs | [ipsecagent/status.go](../../core/outline-worker/internal/ipsecagent/status.go), child and ParseSAs |
| Server polling | Calls monitor.Sample every second, then recordIPsec on every fifth tick | [server/service.go](../../core/outline-worker/internal/server/service.go), Run around lines 387-408 |
| Counter ingestion | Calculates CHILD_SA counter deltas and passes the entire delta to AddExternal at ingestion time; the stored per-child timestamp is not used to normalize a live rate | [server/ipsec.go](../../core/outline-worker/internal/server/ipsec.go), recordIPsec around lines 210-282 |
| Shared monitor | AddExternal adds the delta to cumulative counters; Sample exposes the difference since the previous one-second sample as the rate | [server/monitor.go](../../core/outline-worker/internal/server/monitor.go), Sample around line 440 and AddExternal around line 564 |
| UI | Polls /live every second and displays its rates in server/client readouts and charts | [ui/admin/store.tsx](../../ui/admin/store.tsx), around lines 88-106; [Overview.tsx](../../ui/admin/views/Overview.tsx); [Clients.tsx](../../ui/admin/views/Clients.tsx); [Island.tsx](../../ui/admin/Island.tsx) |

**Inference to verify:** five seconds of IPsec bytes can land in one one-second monitor bucket, producing several zero readings followed by an inflated spike. Because Sample runs before recordIPsec, the newly ingested bytes appear on a later sample. Independent agent/server polling phases can add delay.

Illustrative model, not a measurement from the user's device: a steady 1,000,000 B/s transfer reported in 5,000,000-byte batches can appear as 5,000,000 B/s for one tick and zero on surrounding ticks. Its longer-term total may still be correct. Cumulative usage accuracy must be checked separately from live rate accuracy.

### Required investigation and acceptance criteria

1. Reproduce the user's symptom after DNS works. Record the affected app/dashboard view and version, /live every second, component report timestamps/counters, and a controlled transfer's bytes and elapsed time.
2. Test download and upload separately, then simultaneously, with asymmetric known rates. Verify direction: strongSwan server bytes-in is client upload; server bytes-out is client download.
3. Compute live throughput using the actual measurement interval or another explicitly defined rate window. Keep byte accounting exact and independent of any display smoothing. Faster polling alone is insufficient unless all intervals and delayed reports are handled correctly.
4. Add deterministic tests for five-second reports versus one-second samples, offset polling phases, repeated/unchanged reports, irregular/delayed timestamps, multiple CHILD_SAs/devices per user, and mixed IKEv2 plus other-protocol traffic. A steady transfer must not be represented as repeated false zeros and roughly fivefold bursts merely because reports are batched.
5. Verify rates return to zero after traffic stops, and stale/disconnected reports do not keep an old rate displayed indefinitely. Check first-report baselines, counter resets, rekey, closed-session final counters, component restart, and server restart without double counting or negative rates.
6. Compare per-user rates and server aggregates across /live, the client view, the Island, and the Live 60 s chart; verify minute/hour averages and cumulative usage independently. Retain decimal **B/s, KB/s, MB/s** throughout; API fields ending in _bps are bytes per second.
7. Run a sustained controlled transfer for at least 60 seconds after the initial measurement window, then idle and reconnect. Document the sampling window and an appropriate tolerance for packet overhead and timing jitter instead of claiming exact payload-rate equality.
8. Preserve the existing accounting/restart/closed-session tests in [ipsec_test.go](../../core/outline-worker/internal/server/ipsec_test.go) and [ipsec_review_test.go](../../core/outline-worker/internal/server/ipsec_review_test.go). Add a regression proving the live-rate failure on the old implementation.

The documented "IPsec (not inspected)" traffic category and absence of per-site inspection are existing limitations, not evidence of this live-throughput bug. No claim is made here that usage totals, speed-limit enforcement, or traffic direction were proven wrong on the running server.

## v0.8.6 delivery checklist

- Implement and review IKE-01 and IKE-02, with tests demonstrating the old failures and corrected behavior.
- Run the relevant tagged Go tests and Linux IPsec integration/package checks; run UI build/tests and commit generated UI output if UI code changes.
- Update README, the relevant deployment documentation, CHANGELOG, and the verification ledger with the resulting behavior and actual checks performed.
- Follow the repository's version-bump and release workflow for 0.8.6. Publishing a release requires the maintainer's request under the repository rules.
- Do not copy production keys, identities, or server addresses into fixtures or reports. Keep this investigation's manual route workaround out of the shipped implementation.

Validation status of this document: remote commands and packet captures were run by the user and their output was supplied in chat; the user confirmed the route workaround restored websites. Local source was inspected. No application code, package, tests, or release was changed as part of this findings-only handoff.

## Resolution in v0.8.6

Added after the fixes, in pull request #10. The CHANGELOG's 0.8.6 section and the verification ledger have the details and say what was actually run.

| ID | Fix | What covers it |
| --- | --- | --- |
| IKE-01 | The DNS of IKEv2/IPsec clients is answered by Ghostlink's own inbound, `ghostlink-dns` ([dnsinbound.go](../../core/outline-worker/internal/server/dnsinbound.go)), in place of sing-box's `direct` inbound. It reads the address each UDP request was sent to (`IP_PKTINFO`) and answers from it, so the agent's reverse NAT turns the answer back into one from the resolver the client asked. TCP was not affected. It is IPv4 only, like the pools, and runs unprivileged. Nothing in the firewall, the routes or the host changed, and no address, interface, port or table is written into the code. | The Linux Go tests show the wrong source on a plain socket and the right one on the new listener, with 16 concurrent clients, and through the real engine for A, AAAA and HTTPS over UDP and TCP. `tests/ipsec/interop.sh` (CI): a strongSwan client in a namespace, a route to it that prefers another source than the gateway, the source of every answer checked (`dnsquery.py`), IKEv2 and IKEv1/IPsec, after a reconnect and after restarts. |
| IKE-02 | `recordIPsec` still counts the bytes exactly, and now sets the live rate once per new report: the bytes since the previous report over the time between the two (new `updated_ms` stamp, whole seconds for an older agent), held until the next report is due (twice the window, at most 15 s). The server reads the report every second. `Sample` shows that rate instead of the batch in one second; the online state, the per-minute averages, the usage and the statistics use the exact bytes. | 12 deterministic tests on a virtual clock that fail on the 0.8.5 display; a real server process read once a second (steady `1000000` against `0 0 0 0 5004000 …` on a build of the v0.8.5 tag); the interop download held to a cap for 80 s (CI). |

Acceptance criteria that this release does not meet, or meets only in CI:

- **IKE-01 #4 (a controlled upstream resolver):** the interop test uses the runner's own resolver for answers with data; only blocked-name answers are deterministic.
- **IKE-01 #7 (concurrent clients, reboot):** the interop test connects one client at a time and restarts containers, not the host. The Go test covers concurrent queries.
- **IKE-01 #8 and IKE-02 #1 (a real iPhone, without the manual route):** not done. Check on a device: record the device and iOS versions, browse and download for a minute, and watch the Island and the client's speed.
- **IKE-02 #6 (the apps' views):** not looked at again; they show `/live`, which was read directly.
