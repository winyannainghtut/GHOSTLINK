# Verification ledger

Updated 2026-11-10 (Asia/Singapore). A compiled binary or proxy-only traffic test does not meet the original full VPN platform definition of done.

## Unreleased: forgetting a managed server that does not answer, and the name given when adding one (2026-11-10)

Two bugs of **Servers I run** reported on the Windows app: a server that did not answer could not be removed from the app, and the name typed in *Add server* was shown as "Ghostlink server". The changes are in the Rust service and the app (`ui/desktop`), not in the VPN path.

| Check | Result actually observed |
|---|---|
| Rust unit tests | `labels_are_cleaned` (trimmed, control characters dropped, 64 characters, Burmese kept); `the_name_given_on_this_device_is_kept` (a label is stored and returned by `summary`, a server added without one has none, replacing a key without a label keeps the old one, a new label replaces it, an entry saved by an older version without the field reads as empty). `cargo fmt --check` and `clippy -D warnings` clean |
| Desktop GUI, real service and three real local `ghostlink-server` processes (WebView2 DevTools, an isolated profile, no real clicks) | **41/41 checks**: with A up and B and C switched off, B's card says *Not answering* and A's does not; *Forget Home B* asks first, then B is gone from the card list and from the service while A and C stay; C's page offers *Try again* (with C switched on again it opens C) and *Forget this server* (returns to the list without C); A, which answers, is still forgotten from its own settings; the name typed in the sheet (`ကျွန်ုပ်၏ Home Lab`, Burmese and Latin with a space) is stored as typed under the ID `home-lab` and is the card's title, not the server's own name; no element outside its box and no page error in Obsidian, Daylight and Titanium |
| The same script on the build before the fix | 10 of 16 checks passed; the 6 that failed were those of the missing features |
| Not verified | **The installed Windows app and its service**, which were not touched (the rule is development runs only): the fix reaches it in the next MSI. **A server whose address no longer routes at all:** the local servers were switched off, which fails at once; for an address that swallows packets the card and the page say *Not answering* only after the service's connect timeout (8 s) or request timeout (25 s). **Narrow windows** of the desktop app beyond the layout checks above. A label longer than 64 characters typed into the sheet cannot occur (the field stops at 64); the service cut at 64 is only covered by the unit test |

## v0.8.6 IKEv2/IPsec: DNS answers and live speed (2026-11-10, pull request #10)

From `docs/development/ikev2-findings-v0.8.6-2026-11-10.md`: IKE-01 (an iPhone connected over IKEv2, but websites did not open) and IKE-02 (the live speed of an IKEv2 transfer was wrong). Both change how the VPN behaves, so each has a test that fails on 0.8.5: the live speed was also run against a real server process, and the DNS fix against a real strongSwan client in CI, where a throwaway branch with the 0.8.5 listener put back fails the same tests.

| Check | Result actually observed |
|---|---|
| Go suite | All packages pass (the server package in 186 s), `go vet` on Windows and for Linux amd64 and arm64, `gofmt` clean. Process suite 20/20 (unprivileged), Rust 54 tests, UI 22 tests, `clippy -D warnings` clean |
| IKE-02, unit tests on a virtual clock | 12 tests (`ipsec_rate_test.go`) drive the real `recordIPsec` and `Sample` with the agent's reports as files with their own time stamps: a steady 100 KB/s up and 1 MB/s down reported every 5 s reads exactly that every second after the first window; directions kept (upload only, download only, both); reports on shifted phases and with windows of 6, 3, 6, 5, 5 and 7 s; a report read again changes nothing; the speed falls to zero when the transfer stops and 10 s after the reports stop; two devices and a rekey sum to 1.2 MB/s; other protocols' traffic is shown in its own second on top; the first report after a start sets only a baseline (10 GB before it are not counted); a counter that goes back is never negative; a server restart gives no burst. Byte counts and the per-minute averages are asserted exact. With the 0.8.5 display put back (a report's whole growth in one second), all 12 fail |
| IKE-02, a real `ghostlink-server` process (the Run loop, not hand-driven ticks) | A stand-in agent wrote reports every 5 s for a steady 100 KB/s up and 1 MB/s down; `/live` was read every second. v0.8.6: `1036591` for the first window (the stand-in's first report came a few seconds after its baseline) and `1000000` every second after that, 100000 up, zero within 5 s of the transfer stopping, the server's total equal to the client's, 9/9 checks. A v0.8.5 server binary built from its tag: `0 0 0 0 5004000 0 0 0 0 5001000 …`, 15 zero seconds in 18 and bursts of five times the rate, 5/9 checks |
| IKE-01, the failure and the fix at the socket | `dnsinbound_linux_test.go` (Linux only; run in CI, not on this Windows machine): a plain wildcard socket answers a request sent to 127.0.0.2 from 127.0.0.1, so a client connected to 127.0.0.2 drops the answer (the test skips itself on a host that does not show this); the new listener answers from the address asked, for 127.0.0.1, .2 and .3, from 16 clients at once; through the real engine, with the listener on every address as in production, A, AAAA and HTTPS queries for a blocked name to two gateway addresses over UDP and TCP get NXDOMAIN from the right address. They compile and vet for linux/amd64 and linux/arm64 |
| IKE-01, portable tests (run here) | The existing IPsec DNS test passes on the new listener. New: A, AAAA, HTTPS and SVCB queries for a blocked name over UDP and over TCP get NXDOMAIN, and a source outside the pools gets nothing, over UDP and over TCP |
| `tests/ipsec/dnsquery.py` | It now reports `WRONGSOURCE` for an answer from another address or port than the one asked (it ignored the source before, which is why 0.8.5's test passed while an iPhone got no websites), supports A, AAAA, HTTPS and SVCB, TCP, and counting answers. Run against a throwaway responder here: NXDOMAIN, NOERROR with 2 answers, the type sent, TCP, an answer from another port (`WRONGSOURCE`), and nothing listening (`TIMEOUT`), 8/8 |
| Release CI, on the 0.8.6 commit | `tests/ipsec/interop.sh` with a real strongSwan client in a namespace, and the route to the client preferring another source than the gateway (asserted): for IKEv2 and IKEv1/IPsec, A, AAAA and HTTPS over UDP and TCP to the gateway and to another resolver (redirected), answered from the address asked; real answers for `example.com` from the runner's resolver; again after a reconnect, a restart of the server and a restart of the IPsec component. It also reads `/live` every second during a download held to 300 KB/s for 80 s (`liverate.py`: at most 2 zero seconds, a median within 0.4–1.6 times the cap, no reading above 3.5 times), then zero once idle, then a new connection. `liverate.py` rejects the 0.8.5 pattern and accepts a steady one (checked here) |
| What CI showed (2026-11-10) | On the 0.8.6 commit, the IPsec interop job passed (push and pull request runs): the DNS checks for all four profiles, the step with a reconnect and the restarts of the server and of the component (IKEv2 and IKEv1), and the live rate of a real transfer: `live down_bps over 65 s: median 302960, peak 305760, zeros 0 (cap 300000 B/s)`, then zero once idle. Also passing:  the Go tests on Linux (the desktop job's push and pull request runs), the mesh end-to-end test and the UI build check. On a **throwaway branch with the 0.8.5 DNS listener put back** (the new tests kept; deleted afterwards): the interop job failed at the first DNS check with `A query over udp to 10.79.0.1 for a blocked name: WRONGSOURCE 10.99.0.1:10914`, an answer from the server's underlay address instead of the gateway, as on the iPhone; and the Linux Go test `TestIPsecDNSAnswersFromTheAddressAsked` failed with UDP timeouts for both gateway addresses. The release dry run's Linux Go job failed once on `TestAnEngineThatIsDownHoldsNoPorts` (from 0.8.5): a flaky pick of a random port that the server had reserved for AmneziaWG. It, and `TestABusyPortCanBeMovedAway`, now pick a port the server has not reserved (`unreservedPort`), 10 runs in a row |
| Not verified | **A real iPhone**, with or without the manual route (device and iOS versions are unknown): the cause was found by elimination, and no capture showed the answer at the phone. The interop test is the only proof that a client sees the answers. **Concurrent clients** in the interop test: it has one client container and connects the profiles one after another (the Go test covers 16 concurrent queries to two gateway addresses). **A reboot**: only restarts of the two containers are covered. **A controlled upstream resolver**: the answers with data come from the runner's resolver, so only the blocked-name answers are fully deterministic. IKEv1/IPsec on a real device. The Island, Overview, client list and chart of the apps were not looked at again: they show the `/live` numbers that the real-process check read |

## v0.8.5 The follow-up reviews of 0.8.4 (2026-11-10, pull request #9)

Two reviews: `docs/development/code-review-2026-11-10.md` (R1: the Docker window of the F1 fix, and connections that outlive it; R2: ports counted as held while the engine is down) and `docs/development/rust-code-review-2026-11-10.md` (six findings in the Rust client service, CLI and engine). The first two Rust findings change how the VPN behaves, so they were tested through the real service and the real worker, not only with unit tests.

| Check | Result actually observed |
|---|---|
| Go suite | All packages pass (the server package in 158 s), `go vet` on Windows and for Linux, `gofmt` clean. New: `TestAnEngineThatIsDownHoldsNoPorts`, the review's R2 reproduction, refused with 400. With the old rule put back (held ports from the saved state), it fails with 200, as the review saw. `TestHeldPortsAreThoseThatListenNow` now also checks that an engine that is down holds no ports. `TestFirewallRules` checks the mesh guards: their rules, the DROP at the end, no acceptance of established traffic, and jumps that match `glmesh0` |
| UI, Rust, process suite | UI typecheck, 22 tests and both builds. Rust: `fmt --check`, `clippy -D warnings` with the new lint table (`undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn`), `cargo doc` without warnings, and the tests, both workspaces. Process suite 20/20 against a fresh server, also with `GHOSTLINK_TEST_EXPECT_UNPRIVILEGED=1` after checking the shell was not elevated |
| GUI (WebView2 DevTools, isolated profile, two local servers behind a debug service) | The 0.8.4 check again, 34/34: F2 with the race reproduced, F6 with a real engine failure in two finishes, and Shadowsocks moved to 443 in Network |
| Release CI (passed on the first 0.8.5 commit, `008ecf8`, before the Rust fixes) | `tests/mesh/e2e.sh` on x64: right after Docker's rules come first, with pub's agent paused so it can't react, relay (no rule) is refused at once and nata (with a rule) still reaches the published port. With the agent paused and all its jumps removed, a connection from relay to a published echo service carries data. Once the agent has put its rules back, it stops, and no echo comes back afterwards |
| Rust finding 1: OpenVPN routes that take all traffic | `routes_that_cover_the_internet_are_a_full_tunnel`: `/0`, two `/1`, four `/2`, `vpn_gateway` and a numeric gateway count as full; private routes, one `/1` and `net_gateway` routes stay split; a netmask with gaps is refused; the canonical profile keeps the routes and gets no `redirect-gateway`. New process test through the real service: four profiles imported and listed as `full`/`split`, and on Linux both full ones refused with `permission_denied` without `--allow-full-tunnel` (CI). On Windows it connects nothing, so this machine's routes were not touched. `tunnels_that_cover_every_public_address_are_full` (WireGuard) still passes on the shared coverage function |
| Rust finding 2: a worker that fails early | `tests/worker_exit.rs` drives the real session code with the test binary as a stand-in worker that changes no network settings. An exit with 23 before `started` gives `network_cleanup_unverified`; a reported clean failure keeps its own error; a reported cleanup failure is blocked; a stop during the start ends with no error. With the old rule put back, the exit before `started` gave `outline_engine_exited_check_service_permissions`, as the review saw, and the test failed. The real worker: the unprivileged process test connects through the service and the worker. Its failed TUN start is reported as clean, so a second attempt fails the same way and is not blocked. The six opt-in real-engine tests pass with the 0.8.5 worker and sing-box 1.14.4, including the clean exit on stop and on parent EOF |
| Rust findings 3–6 | `admin_errors_are_standard_errors`; `cargo metadata` reports `rust_version` 1.92 for all six packages; all unsafe blocks documented (Clippy clean on Windows, Linux in CI) |
| Not verified | A real Docker daemon starting after the agent (the test builds Docker's chains as Docker does); the IPsec component, which has no guard (agent.md, known limits); a real worker crash after it changed routes, DNS or the firewall (the stand-in changes nothing); a privileged Linux OpenVPN session; routes an OpenVPN server pushes (agent.md, known limits) |

## v0.8.4 Ports below 1024 and the code review of 0.8.3 (2026-11-10, pull request #8)

Asked for after an Outline import on a real server gave all 16 keys on port 443 new keys. The review is `docs/development/code-review-2026-11-09.md` (F1–F6). The F3, F4 and F5 tests were run against 0.8.3 in a separate worktree and fail there (F4's swap returned 200 there, because the test server runs no dashboard listener; the missing refusal is what fails). F1 and F6 are covered by the end-to-end test and the GUI check below, F2 by both the UI tests and the GUI check.

| Check | Result actually observed |
|---|---|
| Go suite | All packages pass (the server package in 147 s), `go vet` on Windows and for Linux, `gofmt` clean; the server also builds for linux/arm64 and linux/386 (where it refuses `GHOSTLINK_RUN_AS`). New: `TestParseRunAs`; `TestOutlineImportKeepsLowPorts` (keys on 443 and 80 kept, one on UDP 500 refused while IKEv2 is on); a port below the floor refused with its own message; F3 `TestHeldPortsCountPerTransport` (WireGuard on UDP N with another program on TCP N: VLESS refused, and the other way round); F4 `TestSwappingTheDashboardPortTakesTwoChanges` (refused with what to do, then done in two changes); F5 `TestMeshAddressesDoNotChangeTheEngine` (100.96.0.1, 100.64.0.7 and an fd7a:: address leave the engine configuration byte for byte the same); F1 `TestDockerCopies` (only jumps marked Docker get the DOCKER-USER copy). The existing Outline and port tests now pin the floor, because Windows lets anyone bind port 80 |
| UI | Typecheck, 22 tests (3 new, F2: with A's answer held back and B opened meanwhile, both requests of a new client go to A; no shared transport is exported; only a transport that can use keys here offers to) and both builds |
| GUI (WebView2 DevTools, isolated profile, a debug service managing two fresh local servers A and B) | 34 checks. F2 for real: A's answer to the new client held back 5 s, the sheet closed, B opened (B's `info` was call 7, A's `key_create` call 18); both requests went to A, B got none, A has the client with its key and B only Bob. F6 for real: B took A's Shadowsocks port while A was stopped, so A's engine could not start: A's Island says *VPN engine down*, its panel and Overview give the engine's error, nothing outside its box, in Obsidian and Daylight, while B stays *Live*. Then Network took port 443 for A's Shadowsocks (the field now starts at 1): A's engine started, its Island is *Live* again, and Alice's key says `:443`. The 0.8.3 dashboard check (40 checks, three finishes) passes on the new build |
| Process suite and Rust | 19/19 process tests; Rust workspace 51 tests and the desktop app's 2; `release-version.mjs --tag v0.8.4` |
| Release CI (to run) | `linux-package.yml` now checks `user=0:0`, the four added capabilities, `no-new-privileges`, and the running server's `/proc/PID/status` (the account's IDs, no groups, `CapEff`/`CapPrm`/`CapBnd`/`CapAmb`/`CapInh` 0x400, `NoNewPrivs` 1), moves Shadowsocks to 443 and checks TCP and UDP 443 and the key; the Outline smoke test now expects the key on 443 kept and served. `tests/mesh/e2e.sh` adds Docker's chains after the agent: the agent's jumps are first in DOCKER-USER within 45 s, the node without a rule can't reach the published port, the one with a rule still can, and the host is clean after the agent stops |
| Not verified | Docker's own DOCKER-USER handling (the end-to-end test makes the chain as Docker does, without Docker); the capability drop on a real Docker daemon outside CI; the IPsec component's FORWARD jump after a firewalld reload (agent.md, known limits) |

## v0.8.3 New servers run only Shadowsocks (2026-11-09, pull request #7)

Measured first on the real test server (idle, with keys): container memory 11.1 MiB with only Shadowsocks running, 15.1 with VLESS, 18.8 with WireGuard, 22.8 MiB with AmneziaWG too. A protocol without keys starts nothing, so the change is in the defaults: a new server, its hints and the app create Shadowsocks keys. Implemented in three worktrees (Go, UI, scripts and docs) from one plan with a prototype, then cross-checked by a reviewer (5 findings, all fixed) and integrated.

| Check | Result actually observed |
|---|---|
| Go suite | All 8 packages pass (the server package in 145 s), `go vet` on Windows and for Linux, `gofmt` clean. 6 new tests: a new server runs only Shadowsocks; an existing server keeps its switches; turning a protocol on tries its port; a protocol that is off keeps its port; held ports are those that listen now; the commands on a new server. Each fails on the old code, and four single-point mutations of the new port checks are each caught |
| Process suite | 19/19 against a fresh `init` server: only Shadowsocks on, an AmneziaWG key refused, `server set --enable` turns the others on, then their keys work |
| UI | Typecheck, 19 tests (2 new: the Shadowsocks-first pick and the "turned on" text) and both builds, identical to the committed output |
| GUI (WebView2 DevTools, isolated profile, a fresh local server, Daylight, Obsidian and Titanium) | 40 checks: Overview and Network say the WireGuard/AmneziaWG pools are off and a new server runs only Shadowsocks; Network shows only Shadowsocks on; New client and New key start on Shadowsocks and mark the protocols that are off; nothing outside its box. Turning AmneziaWG on from Network: on, and the toast says "Allow UDP <its port> in this server's firewall and your cloud security group"; New client then offers it but still starts on Shadowsocks; turning it off asks first and pauses it |
| Not run here | The installer's `--enable` and the smoke tests in `linux-package.yml` and `ipsec.yml` (Docker; release CI runs them); a refused turn-on in the GUI (covered by the Go tests) |

## A real internet-facing server (2026-11-08, Ghostlink 0.8.2)

The maintainer's test VPS: AWS Lightsail in Singapore, Ubuntu 24.04.4 LTS x86_64, 2 vCPU, 412 MB of memory and 1 GB of swap, behind Lightsail's firewall (ufw off). Clients: a Windows PC with a standalone sing-box 1.14.4 (SOCKS on 127.0.0.1), and the maintainer's own device for AmneziaWG. Server-side steps ran over SSH (`sudo ghostlink-server --json …`, and the management API on the server's own loopback, so the management key never left the server). A temporary client was created and removed, and every changed setting was saved first, restored and compared at the end (`%TEMP%\gl-gui\fulltest.mjs`, `udp-later.mjs` and `dash-real.mjs`, kept outside the repository). 83 checks; the one failure was the test's own (a later UDP packet sent to a name, which is dropped by design) and passed when sent to an address.

| Check | Result actually observed |
|---|---|
| Install and ports | `ghostlink-server` 0.8.2 (package `0.8.2-1`) running. A protocol listens only once a key for it exists: VLESS, WireGuard and AmneziaWG opened their ports with the first key. The dashboard listens on 127.0.0.1 only; the management API answers `404` without its secret |
| Traffic, no limit | Shadowsocks, VLESS-REALITY and WireGuard: the exit address was the server's; 10 MB downloads at 38–53 MB/s, 4 MB uploads at 20–21 MB/s; Shadowsocks UDP (an NTP request) answered. AmneziaWG: checked by the maintainer by hand, works |
| What VPN users can reach (0.8.1) | Through Shadowsocks, VLESS and WireGuard, refused: the dashboard and the management API on the server's loopback, SSH and the management API on its public address, SSH on its private address, the AWS metadata endpoint (169.254.169.254); the last two also for an exempt client. Controls: ordinary sites work, and SSH answers from outside the VPN |
| UDP, packet by packet (0.8.1) | In one Shadowsocks UDP session opened by an NTP request: later packets to other NTP servers by address were answered; to a DNS server (8.8.8.8:53) or the host's resolver (127.0.0.53:53) dropped; to a host name instead of an address dropped (the check needs an address). A session opened by a DNS query was answered by the server's resolver |
| Speed limits (0.8.0) | At 1 MB/s: downloads 1.01–1.02 MB/s and uploads 1.04 MB/s on all three protocols. A change from 1 to 5 MB/s during a 30 MB download applied at once (10.6 s, about 30 s otherwise). The server default (2 MB/s) applied to a client without its own (2.09 MB/s); "no limit" overrides it (45 MB/s) |
| Data limit | With a 20 MB limit at 2 MB/s, a 30 MB download stopped at 24.6 MB and new connections were refused; `user reset` restored access |
| Rules | The client's own: a blocked site and its subdomain, a blocked address and a blocked port refused, other sites, addresses and ports work. A site blocked for everyone refused, but not for an exempt client |
| Online and idle (0.8.1) | Online right after traffic; idle 75 s later with one idle connection still open (an SSH server waiting for the client); an idle WireGuard tunnel stayed online through its keepalives |
| Server commands | Refused: a word an option does not take, a port another program uses (22) or below 1024 (80), a name that differs only in capitals, `10Mbps` and `10Mb/s`. `2MBps` read as 2,000,000 B/s. `key qr` prints a QR code and fails for an unknown key; `kit` writes a 62 KB HTML page; `keys` without `--show` holds no key text |
| Statistics | `stats --range 24h`, `usage` and `clients` (with this PC's public address) report the test client |
| Restart | After `restart`: every client still there, usage saved, keys work, no error in the log |
| Dashboard (SSH tunnel, WebView2 DevTools with an isolated profile) | Signs in with the login link and shows `v0.8.2`. Overview, Clients, Network and the Island at 1280, 1000 and 390 px, in Daylight and Obsidian: nothing outside its box, no page wider than the screen |
| Not tested there | IKEv2/IPsec (the component is not enabled), the mesh (needs more Linux machines), the move from Outline (no Outline on the host), a hostname change, a busy port at start, the BitTorrent and SMTP blocks |

## v0.8.2 Layout fixes (2026-11-08, pull request #5)

Reported on the published 0.8.1: the switches of the Island's protocol list stuck out of its box. An independent review of the fix found the same fault in more places and a few other layout faults, and a skeptic checked each finding again (8 of 10 held). Every check below rendered the real UI in the debug app's WebView2 over DevTools (isolated profile, dummy service endpoint) against a local `ghostlink-server` (`%TEMP%\gl-gui\layout081.mjs` and `layout082.mjs`, kept outside the repository).

| Check | Result actually observed |
|---|---|
| Island protocol list (all three finishes, 1000 and 1280 px) | Before the fix: each row 352.5 px wide in the 340 px panel, every switch 13.5 px past the panel's edge, AmneziaWG's hint not shortened. After: rows 314 px, switches 25 px inside the edge, the hint shortened, the knobs inside their tracks |
| Navigation bar, 1000–1600 px in 8 px steps, in the app's own shell and in the dashboard | No overlap of the motion button or the finish picker with the Island or the view buttons. With 360 px slots the motion button still stood 1.8 px out of its slot; the slots are 368 px |
| Long names, phones and narrow windows (390, 620, 1000 and 1280 px) | A 64-character client name in cards and list and in its sheet (keys and usage), a mesh node waiting for approval named `ubuntu-s-1vcpu-1gb-sgp1-01`, the Network view, the Island: nothing outside its box and no page wider than the screen. Before the last fixes, at 390 px, the Network view made the page 445 px wide, the bar's buttons stuck out by 28 px, and the mesh card's buttons squeezed its summary out of its box |
| UI | Typecheck, 17 tests and both builds, after every change |
| Not rendered | The app's My servers and Servers I run cards and its Connect through list need the local service; they use the same CSS rule (`grid-cols-1`, a shortened title in its own span) |

## v0.8.1 Second full review and a report from a running server (2026-11-08, pull request #3)

Every subsystem was read in full, reviewed again for new defects, checked by a skeptical verifier, fixed area by area in separate worktrees with tests, and merged. What changed is in the CHANGELOG under [0.8.1].

Before the release, five reviewers checked every claim of the CHANGELOG section against the code on `main` and v0.8.0, and a skeptic re-checked each finding: all 27 findings held and were corrected (overstated fixes, missing caveats, two items about code that never shipped). `govulncheck` v1.9.0 found no vulnerabilities (Go 1.26.10).

| Check | Result actually observed |
|---|---|
| UDP reply crash (real binaries, Windows) | One Shadowsocks UDP exchange (an NTP request through the server) against a `main` build before this round (`56ae4a7`) crashed the server for capped and uncapped clients: `panic: buffer overflow: capacity 16384, start 0, need 55` in the Shadowsocks UDP writer. The released v0.8.0 answered. The fixed build answered and stayed up. `TestUDPRepliesKeepTheWritersHeadroom` and `TestShadowsocksUDPThroughTheServer` fail with the same panic without the fix |
| Online and idle (Go) | `TestOnlineFollowsWhatTheClientSends`: an open connection and a small write to the client do not count, an upload or a 16 KB download in a second does; online means seen within 60 s. `TestPeersSeenThroughTheirReceiveCounter`: a keepalive counts, an unchanged, new or reset counter does not, a handshake counts at its own time. `TestMonitoringEndToEnd` reads a real WireGuard client's receive counter |
| Dashboard (WebView2 DevTools, isolated profile and endpoint, local server, real Shadowsocks traffic from Cloudflare's speed endpoint, Daylight) | The Island read `↓ 983 KB/s ↑ 0 B/s` during a capped 1 MB/s download; the off switches of IKEv2 and IPsec had the track `rgba(120, 120, 128, 0.24)`; the list said "Last seen". With one idle TCP connection held open through Shadowsocks (to an SSH server, which waits for the client), the client showed `active: 1, online: false` and **Idle** 70 s after its last traffic; a client that never connected showed Idle; no page errors |
| UDP rules per packet (Go, `guard_test.go`) | Over Shadowsocks, VLESS and WireGuard, 5 of 5 later packets reached a blocked loopback port without the check and none with it |
| TCP and UDP under one cap (Go) | `TestPacerSharesTheCapBetweenTCPAndUDP`: 0 of 146 UDP packets passed while TCP filled the cap before the fix (in the unreleased code of pull request #2), 80 % or more after |
| IKEv2/IPsec (Go) | 14 new tests in `ipsec_review_test.go`: identities for any user name, a refused key left out without blocking the others, renames and pinning, no double counting after a restart or an ended session, settings written only when they change and one at a time, the profile identifier, certificate renewal at start and after a hostname change. Each fix was reverted in turn and its test failed |
| WireGuard and AmneziaWG endpoints (Go, `internal/awg`) | One client UDP socket: an allowed port answered, a blocked port stayed silent, a further allowed port answered (before the fix the blocked port answered). The far side dialing an AmneziaWG client's tunnel address was dropped (before: it reached a loopback web server). Validate-only engines and start/close cycles left no goroutines (before: 160 and 5) |
| Mesh (Go) | Coordinator, protocol, agent and firewall-helper tests pass, including consent, firewall order, routes, pacing of waiting nodes and the long-poll on disable |
| Rust | `cargo fmt`, `clippy -D warnings`, 50 unit tests (CLI 1, contracts 6, engine 41, service 3). The new process tests failed 7 of 19 against the binaries before the Rust fixes |
| Process suite | 19/19 with OpenVPN 2.7.8 and a real local Ghostlink server, none skipped |
| Real-engine tests | 6/6 (`outline_traffic`, `worker_protocols`), including real WireGuard and AmneziaWG traffic with the new rule that refuses flows from the far side |
| Python | 28 tests: the offline provisioning tools (the proxy against sing-box), the Linux maintainer scripts under `sh` and `dash`, the MSI owner logic |
| UI and desktop app | Typecheck, 17 tests and both builds; the Tauri app builds and passes clippy |
| Go suite at the final merge | All packages pass on Windows (the server package in 139 s); `GOOS=linux go vet` passes |

### Not verified

- A real Apple device, `--migrate-outline` on a real Outline, a reconnect after a real connected OpenVPN session, and a routed tunnel on Linux. (A real VPS was tested later; see the section above.)
- `dnf upgrade` of the client and mesh `.rpm` on Fedora/RHEL, and an MSI upgrade with a new `GHOSTLINK_OWNER_SID` (both were checked only by tests of the scripts and logic).
- The mesh across real cloud servers; the race detector (no cgo toolchain on the development machine). (The host addresses the server blocks were checked later on a real host: its public, private and loopback addresses; see the section above.)

## v0.8.1 Review of v0.8.0 after its release (2026-11-08, pull request #2)

Two independent reviews (Go server code; scripts, CI and docs) were checked against the source before fixing. What was fixed is listed in the CHANGELOG under [0.8.1].

| Check | Result actually observed |
|---|---|
| UDP head-of-line blocking (source reading) | Confirmed in sing `common/udpnat/service.go`: each Shadowsocks UDP session is fed with a blocking send into a 64-packet channel from the inbound's read path, so a session that waited held up the others. `TestPolicedPacketConnDropsInsteadOfWaiting`: 1,000 packets of 10 KB at a 100 KB/s cap are read in well under a second, about the burst passes, the rest is dropped, and the buffer keeps its front headroom; unlimited clients lose nothing |
| Pacer (Go) | `TestPacerArithmetic`: a 10 MB chunk waits the full 10 s (no 5 s cut-off), the next chunk waits for the whole debt, a new rate starts with a full bucket. `TestPacerAllow`: policing takes only what the bucket holds. `TestPacerWaitEndsWhenTheLimitChanges`: a 9 s wait ended about 1 s after the limit was removed. `TestSpeedLimitsEndToEnd` still holds 1 MB/s over Shadowsocks and WireGuard |
| IKEv2/IPsec rules (Go) | The `hashlimit` table name is derived from the client and its rate (9 characters plus the direction); a changed rate gives a new name |
| Server commands (Go) | `user speed Alice 10Mbps` and `set --speed-limit 8mbit` are refused |
| Go, UI | The full Go suite passes on Windows; the UI typecheck, `npm test` and both builds pass |
| Host script | `sh -n` and `bash -n` pass locally; shellcheck passes in CI |
| IKEv2/IPsec rate change (CI interop, real strongSwan client) | 1.5 MB took 0.008 s without a cap and 4.37 s at 300 KB/s; with the cap raised to 600 KB/s **on the same connected session**, 1.67 s. Before the fix the kernel kept the first rate |
| Failed Outline import (release CI dry run, x64 and arm64) | With another program holding one of Outline's ports, `migrate-outline` failed after stopping Outline and printed "the import did not go through; Outline is back as it was"; both containers were running again with restart `always`, Ghostlink had no clients and the private copies were gone. The successful migration, the refused second run and the rollback passed after it |
| CI on `fix/review-0.8` | Desktop and local engine verification (Windows and Linux), Web UI, IPsec interop, Mesh end-to-end and the release dry run all pass |

### Not verified

- A real Shadowsocks UDP flood by a capped client next to another client's UDP (the fix is checked by reading the library and by a unit test).

## v0.8.0 Speed limits and the move from Outline (2026-11-08)

| Check | Result actually observed |
|---|---|
| Pacer (Go) | `TestPacerArithmetic`: the bucket starts full (250 KB at 1 MB/s), 500 KB over an empty bucket waits 0.5 s, a refill stops at the burst, one wait is capped at 5 s, unlimited never waits, small caps get 64 KiB (65,536 bytes). `TestPacerHoldsTheRateAcrossConnections`: three connections sharing a 4 MB/s cap moved 6 MiB within -15 % to +30 % of the time the cap allows |
| Speed limits with real clients (Go, `TestSpeedLimitsEndToEnd`, 13 s) | Real sing-box clients against the server. A client capped at 1 MB/s downloaded 3 MB at the cap through **Shadowsocks** and through **WireGuard** (the userspace stack's connections); an unlimited client took under 1.5 s. A 2 MB/s server default capped the others at once, and the capped client kept its own 1 MB/s. "No limit" (-1) overrode the default. The engine reload counter did not change through all of it. -2, 2,000,000,000 and a too-high default got `400` |
| Outline import (Go) | `TestOutlineImportPlan` on 11 Outline keys: main port and cipher by majority; an `aes-256-gcm` key on another port kept its own listener (VLESS moved off that port); new keys, with reasons, for a port below 1024, a cipher mix on one port, the management API's port, an unknown cipher and a password with a newline; names "Key 1" and "alice (2)"; per-key and default data limits; a 0-byte limit imported as turned off; two keys sharing a password noted. Every kept key renders as the exact `ss://` its owner has. The report holds no password. Moving the main port onto an imported key's port is refused. `TestOutlineImportRefusals`: a server with clients, no keys and 501 keys are refused; when every key is below 1024, the import keeps the server's own port and gives everyone a new key |
| Outline keys still work (Go, `TestOutlineImportEndToEnd`) | Outline's **original** `ss://` URLs (two on the main port with chacha20-ietf-poly1305, one on an extra port with aes-256-gcm) carried traffic through real sing-box clients after the import over the API, and the traffic was seen for the right clients. The dry run changed nothing. A second import got `400` |
| Server commands (Go, `TestAdminCommands`) | `user speed` (2MB, default, none), `user add --speed 1.5MB`, `set --speed-limit 500KB/s` and none, the SPEED column, `settings`; bad speeds refused. `import-outline --dir DIR --check` reported 2 clients and the port-80 key, then the import ran and left its input files in place |
| IKEv2/IPsec rules (Go) | `TestSpeedLimitRules`: for a capped identity's sessions, `hashlimit` rules on each virtual IP (download and upload), sharing one name per client; other users' sessions untouched; the chain jumped to before established traffic is accepted. Validation refuses label injection, long labels, rates of 0 or over 1.25 GB/s, bad identities and duplicates. The server's `desired.json` carries the client's four identities and its own limit, then the default, and nothing for "no limit" |
| Rust | `cargo fmt`, `clippy -D warnings` and the workspace tests pass. A new CLI test covers `--speed-limit` parsing (MB/s, none, default, out-of-range values) |
| UI | Typecheck, `npm test` (the request mapping passes with the new fields, which are part of the Rust contract) and both builds |
| Desktop app and dashboard (WebView2 DevTools, isolated profile, local server, real Shadowsocks traffic of 24 MB from Cloudflare's speed endpoint) | <ul><li>**Live:** Maya, capped at 1 MB/s, showed ↓ 983 KB/s to 1.0 MB/s during her downloads.</li><li>**Desktop (through the service and the Rust contract):** chips "1.0 MB/s" and "2.0 MB/s" (the default) on the cards, none on the client with no limit. The client sheet showed Custom 1 MB/s; saving 1.5 reached the server (1,500,000). Server default, then No limit (-1). The server settings' default 2, saved as 3 (`ServerPatch`). New client with 0.5 MB/s (500,000).</li><li>**Dashboard:** rates in KB/s and MB/s, no "bit/s"; the list's Speed limit column (1.0 MB/s, 500 KB/s, "—"); back to the server default; 5000 MB/s refused in the form.</li><li>No page errors in either.</li></ul> |
| IKEv2/IPsec speed limit (CI, `tests/ipsec/interop.sh`, real strongSwan client) | The capped session got its two `hashlimit` rules within seconds of the change. 1.5 MB took 0.011 s without a cap and **4.17 s at 300 KB/s** (about 5 s less the burst). Removing the cap removed the rules |
| Move from Outline (release CI, x64 and arm64, `linux-package.yml`) | A fake Outline: shadowbox's two files in `/opt/outline/persisted-state` (four keys, one on another port with aes-256-gcm, one on port 443), and `shadowbox`/`watchtower` containers with restart `always`, one holding Outline's port. `install-server.sh --package … --migrate-outline --check` reported 4 clients and the port-443 key, while Outline kept running and Ghostlink had no clients. Then `--migrate-outline`: both containers stopped with restart `no`; Ghostlink listened on Outline's port (TCP and UDP) and the extra port; the four clients with names and the default data limit; `keys --show` gave the exact original `ss://` credentials for the main and extra port; the installer listed the extra port; the private copies were gone and Outline's files unchanged. A second migration was refused before touching Outline, and the printed rollback brought Outline back |
| Other CI | Desktop and local engine verification, Web UI and IPsec interop pass. Mesh end-to-end passed on push; on the pull request it failed once in "open mesh: relay reaches natb:8080" (no mesh code changed) and passed when re-run, a timing flake to watch. On one Windows run, the engine's independent Shadowsocks peer exited at startup (`outline_traffic.rs`): the test checked its port on TCP only while the peer also binds UDP. It now picks a port free on both; the six real-traffic engine tests pass locally with sing-box 1.14.4 and the worker |

### Not verified

- A migration from a real Outline server on a real VPS (CI uses Outline's file format and a stand-in container holding its port).
- Apple devices with a speed limit (the CI strongSwan client is checked instead).

## v0.7.0 Frosted-glass UI for the desktop app and the dashboard (2026-11-07)

| Check | Result actually observed |
|---|---|
| Builds | `npm ci --ignore-scripts` (43 packages), TypeScript 7 typecheck, Vite 8 builds of both apps: one script (dashboard 324 KB, desktop 363 KB), one stylesheet and three `.woff2` fonts each. Builds on Windows and in the Linux **Web UI** workflow were byte-identical, so the workflow's check of the committed output passes. Rebuilding from the source zip's `web-ui/` copy gave identical files |
| CSP | The built CSS has no `data:` URLs (fonts are files), there is no `eval`, and `index.html` has no inline script or style (`TestDashboardBuildIsCompleteAndCSPSafe`). No console or CSP errors in either app during the GUI checks below |
| Dashboard, in the isolated WebView2 against a local server (clients, keys, real Shadowsocks traffic of about 18 MB from Cloudflare's speed endpoint through the server, fake mesh nodes) | <ul><li>**Overview:** KPIs live (2–3 online, up to about 1.5 MB/s; address pool 2 of 8,186), the live, 1 h and 24 h charts, health and usage breakdowns.</li><li>**Clients:** six cards with tunnel IPs from the pools; the Idle filter showed 3; the list view.</li><li>**Client sheet:** keys with their actions; usage (bars over the whole period after the sparse-bucket fix) and connected-from.</li><li>**New client:** the next tunnel address shown before creating (10.78.0.3/32), then the QR code and .conf.</li><li>**Network:** protocols with switches and ports, pools, rules for everyone, the mesh map with node details, invites and rules; the Island's protocol panel.</li><li>All three finishes. A frosted card's computed `backdrop-filter` is `blur(40px) saturate(1.5)` (the first build lost it).</li></ul> |
| Desktop app (debug build, isolated dev service and local server) | <ul><li>Add key: a Shadowsocks key became a card.</li><li>The card menu as a frosted popover; split tunneling per server (follow all, then mode and lists); the connection Island with a server switcher.</li><li>**Servers I run → Manage:** the admin views over the service; live KPIs.</li><li>**Use on this device:** profiles went from 1 to 2.</li><li>QR as a `data:` URL; the New client .conf saved to Downloads through `save_download`, containing `[Interface]` (the file was then deleted).</li><li>**Settings** and diagnostics.</li><li>**Full screen:** the nav button set the window full screen (`isFullscreen` true), reverted at once.</li><li>At 2560 px, five cards a row in both apps after the rem-breakpoint fix.</li></ul> |
| Request mapping (`npm test`) | 4 tests: every request the admin views make maps to the expected `server_call` operation, with only fields `ServerOp` declares (read from `packages/shared-contracts`). Dot segments, empty segments, escapes, backslashes, unknown paths and methods are refused. This found and fixed `/users/1/../2/keys` being normalized into `/users/2/keys` |
| API additions (Go) | `TestMinuteAverages`: per-second samples fold into per-minute averages, an hour plus the current minute. `TestAddressPools`: used, capacity 4093 for a /20, next address. Server package tests pass with the new embedded build |
| Dependencies | `npm audit` (all) and `npm audit --omit=dev`: 0 vulnerabilities. The license inventory has the 8 bundled npm packages |

### Not verified

- The redesigned app installed from the MSI. The checks used the debug build.
- Screen readers. Keyboard focus and ARIA roles exist on controls and the map, but have not been audited.
- Very small windows below 620 px.

## v0.6.0 Mesh of Linux servers (2026-11-06)

### Kernel WireGuard end to end (CI, `tests/mesh/e2e.sh`, Ubuntu 24.04)

| Check | Result actually observed |
|---|---|
| Setup | A native coordinator (`ghostlink-server`) on a bridge acting as the internet, with four agents in network namespaces:<ul><li>`relay` and `pub` have public addresses;</li><li>`nata` and `natb` are each behind their own masquerading NAT router (`--random-fully`) with no inbound;</li><li>a LAN namespace sits behind `pub`.</li></ul>All four joined with invites, came online and in sync, and every pair with a reachable side pinged directly over `glmesh0`. `<node>.mesh` names resolved from `/etc/hosts` |
| Relay | `nata` ↔ `natb` had no direct path and were switched to the relay: the topology showed `nata <-> natb  via relay`, and they pinged through it |
| Access rules | With `web → db TCP 5432`, only that port reached `db` from the web node (a Python HTTP listener) and other traffic was refused; clearing the rules opened everything again |
| Shared subnet | The LAN behind `pub` was unreachable until the administrator approved `192.168.50.0/24`, then reachable from the other nodes |
| Disable, remove, stop | A disabled node lost its interface and was unreachable, then came back when enabled. A removed node's agent cleaned up and deleted its state, and its peers dropped it within seconds. A stopped agent exited with no `glmesh0`, firewall chains or `/etc/hosts` block left. The first run found the long-poll was not cancelled on stop (fixed); the next found the check raced the teardown (the test now waits for the process to exit) |

### Packages (release CI, x64 and arm64)

| Check | Result actually observed |
|---|---|
| Mesh agent package (`linux-package.yml`, run 42245192783) | `ghostlink-mesh` .deb/.rpm were built and the version check passed. On the runner, against the server .deb installed in the same job:<ul><li>`mesh enable`, an invite with `--tags ci`, and the **Add node** command (`install-mesh.sh` piped to `sudo bash`, with `--package`) joined `ci-node`. The service was active, the status `active`, the mesh address on `glmesh0`, `ci-node.mesh` resolved, and the coordinator listed it online with tag `ci`.</li><li>`systemctl stop` plus `ghostlink-mesh leave` left no interface, chains or hosts block, and the coordinator had no nodes.</li><li>`install-server.sh --package … --mesh-package …` joined the host as the online relay and listed the mesh TCP and UDP ports.</li><li>`apt-get purge ghostlink-mesh` left the host clean, removed the state and binary, and the coordinator had no nodes again.</li><li>The .rpm lists `/usr/bin/ghostlink-mesh` and the unit, and its scripts run `ghostlink-mesh leave`.</li></ul>Passed on both x64 and arm64 |

### Coordinator and agent (Go, Windows host and CI)

| Check | Result actually observed |
|---|---|
| Coordinator (`TestMeshCoordinator`, real TLS listener) | <ul><li>Enable, then a local invite.</li><li>Join through a client pinned like the agent; a reused invite gave `403`.</li><li>The long-poll waited, and woke at once when a second node joined.</li><li>Rules and route approval reached the configurations; the topology was correct.</li><li>A removed node got `401`; disabling stopped the port.</li></ul> |
| Mesh logic (`internal/mesh`) | <ul><li>Invite expiry, uses and hashing.</li><li>Direct → relay after the grace period → retry; relay re-routing with no overlapping `AllowedIPs`.</li><li>The generation follows content and stays below 2^53.</li><li>Rules compile to per-node sources; subnet conflicts are refused; unsafe configurations are refused.</li></ul> |
| Protocol checks (`internal/meshproto`) | Invites round-trip; damaged ones, `http` URLs, bad pins and tokens with shell characters are refused. Bad names, keys, endpoints, IPv6 and over-wide or special routes are refused, and so are join and sync requests with bad fields |
| Agent (`internal/meshagent`) | Firewall rules per config, the `/etc/hosts` block, and peer changes that keep sessions (update-only, endpoint only when the suggestion changes) |
| Map copies | `TestMeshMapMatchesTheDesktopCopy`: the dashboard's `mesh-map.js` is identical to the app's, and the dashboard loads it |
| Static | Go vet clean. `govulncheck` 1.9.0 (Windows, and `GOOS=linux`): **No vulnerabilities found**. Rust fmt and clippy (`-D warnings`) clean; Rust tests pass, including fixed mesh paths, numeric IDs, rule validation and agent denial of `server_mesh_*` |

### App and dashboard (WebView2 DevTools, isolated profile)

| Check | Result actually observed |
|---|---|
| Setup | The debug app, an isolated dev service and a real local `ghostlink-server`. Mesh enabled with `ghostlink server mesh enable`. Seven fake agents speaking the real join/sync protocol over pinned TLS, so the coordinator computed real paths:<ul><li>a relay, two web nodes and `db` sharing `192.168.50.0/24`;</li><li>two nodes with no endpoints (behind NAT);</li><li>one waiting for approval.</li></ul> |
| Map | The Mesh card read "7 nodes, 1 waiting for approval". The map showed 7 nodes, 14 direct links and 1 relayed link (the two NAT nodes, drawn through the relay), the relay ring, the subnet bubble and the pending node. A node dragged with DevTools input events stayed put across a poll, and its position was saved |
| Node details and actions | `db` showed its address, `db.mesh`, endpoint, agent and the shared subnet. **Approve** made the pending node active. **Add node** returned the `install-mesh.sh --join 'glmesh1:…'` command with its expiry. The rules editor saved `tag:web → tag:db tcp 5432`, confirmed by `ghostlink server mesh rules`. Dark theme checked; no console errors |
| Dashboard | Same server, in the same webview: the **Mesh** view drew 7 nodes, the relayed link and the subnet. Node details worked, and its rules editor added `tag:batch → node:db tcp 5432,6379` (confirmed by the CLI). No console errors |
| Secrets | No invite or invite token appeared in any file the service or server wrote |
| Found and fixed | Configuration generations were 64-bit hashes, which JavaScript (and jq) cannot hold exactly; they are now 53-bit |

### Not verified

- The mesh across real cloud servers and real NAT routers (for example AWS Lightsail plus a home server).
- RPM installation on Fedora/RHEL: inspected only.
- Kernels without WireGuard: refused by the installer; not exercised.
- Long-running relay switching under packet loss; IPv6 (not supported).

## v0.5.0 IKEv2/IPsec for iPhone, iPad and Mac (2026-11-06)

### Real strongSwan interop (CI, `tests/ipsec/interop.sh`)

- **Setup:** observed on GitHub's `ubuntu-24.04` runner (kernel 7.0.0-1017-azure, Docker, iptables-nft).
  - The script installed the built `ghostlink-server` `.deb`, ran `ghostlink-server ipsec enable` and checked the hardening: read-only, `drop=[ALL]`, only NET_ADMIN, NET_BIND_SERVICE and NET_RAW, user `0:<server gid>`, host network, `no-new-privileges`, `ipsec/` mode 770, IPv4 forwarding on.
  - It enabled IKEv2 and IPsec over the API, created keys and downloaded their profiles (`application/x-apple-aspen-config`).
  - `tests/ipsec/client_config.py` turned each profile into a strongSwan client configuration with exactly the profile's addresses, identifiers, credentials, CA, PKCS#12 identity (opened with the embedded password) and algorithms.
  - The client (strongSwan 6.0.7 from the same image) ran in its own network namespace (10.99.0.2), with an "internet" host 198.51.100.10 in another.
- **Each method connected:** IKEv2 EAP-MSCHAPv2, IKEv2 certificate, IPsec certificate + XAuth (Main Mode) and IPsec group key + XAuth (Aggressive Mode). Through each tunnel:
  - HTTP to the internet host worked (NAT);
  - the globally blocked port 8081 was refused;
  - the server's own API (10.99.0.1) was unreachable;
  - DNS for a blocked site returned NXDOMAIN, both from the pool gateway and from another resolver address (redirected);
  - the server counted the connection.
- **Refusals:**
  - a wrong EAP password was rejected;
  - disabling the user ended the live session and refused the certificate (strongSwan log: certificate on hold) and the group key;
  - re-enabling allowed the certificate again;
  - removing the certificate key refused it (revoked in the CRL).
- **Accounting:**
  - usage became non-zero;
  - `/stats` showed `ikev2` and `ipsec` bytes and "IPsec (not inspected)";
  - `/clients` recorded 10.99.0.2;
  - lowering the data limit to the usage ended the session and marked the user over the limit.
- **Logs:** no password appeared in the agent's log.
- **`ipsec disable`:** it left no `GHOSTLINK-IPSEC` chains, no `glipsec0` and no sysctl drop-in.

### Server and agent (Go, Windows host)

- **Profiles (strict plist parser):**
  - required keys per method;
  - unique and stable `PayloadUUID`s;
  - the VPN payload references its PKCS#12, which decodes with the embedded password to a client certificate that verifies against the CA with the ClientAuth EKU, and is absent with `prompt_password`;
  - the CA payload equals the state's CA;
  - a hostile server and user name is escaped and reads back exactly;
  - on demand.
- **Server certificate:** verifies for the IP and an extra remote identifier, and carries the IKE intermediate EKU.
- **NT hash and CRL:** the NT hash matches the RFC 2759 vector. The CRL is signed by the CA; a disabled user's certificate is on hold (reason 6) and lifted on enabling, and a removed key is revoked.
- **Desired state:**
  - it validates and holds NT hashes, never EAP passwords;
  - disabled and over-limit users drop out;
  - `rotate_ipsec_psk` changes the key.
- **Agent:**
  - `swanctl.conf`, firewall rules and pool ranges are rendered as expected, with secrets only in `0s` base64;
  - validation refuses newline or brace identities, `@` forms, short hashes or keys, oversized pools, a non-first gateway, invalid or injected ranges and ports, a low DNS port, wrong PEM types and an unknown version;
  - `list-sa`, `child-updown` and `child-rekey` events parse into status, with final counters;
  - established-but-disallowed SAs are selected for termination.
- **Accounting:** a session that ends between reports is counted once from its final counters.
- **DNS listener:** it answered NXDOMAIN for a blocked name to an allowed source and nothing to others.

### Daemon, CLI and app

- **Node suite:** 19/19. The new steps cover the component check, IKEv2/IPsec key creation (refusing `--import` and a wrong method), the PSK warning, `keys profile --output` (a new private file, never overwriting), no certificate password in key lists, `--rotate-ipsec-psk`, and an agent token refused `key_profile`.
- **App GUI, over WebView2 DevTools with an isolated profile and a local test server:**
  - **Server settings:** shows IKEv2/IPsec toggles ("UDP 500, 4500") and the component state, and saving them turns both on.
  - **Key dialog:**
    - IKEv2 shows auth eap/certificate and the remote identifier, and hides "use on this device";
    - IPsec + group key shows the weak-key warning, and the server's warning appears after creation;
    - key rows show method, identity and address, with **Save iPhone/Mac profile** (and **Profile without password** for certificates).
  - **Saving:** writes a `.mobileconfig` to Downloads containing the VPN payload and the custom remote identifier. The test file was deleted by its exact path.
- **CI:** the desktop workflow (Windows and Ubuntu: Go tests, vet, govulncheck, Rust build, tests, clippy, Node suite) passed.

### Not verified

- Installing and connecting a profile on a real iPhone, iPad or Mac.
- The component on hosts using iptables-legacy, firewalld or ufw, and on a real internet-facing host.
- IPv6 leaks from Apple devices with IPv4-only tunnels.
- arm64 interop until the release workflow's arm64 job runs.

## v0.4.0 Monitoring, server-side admin and dashboard (2026-11-06)

Observed on the Windows development host (unelevated, loopback only). The release CI server test now also runs the admin commands and dashboard checks on Ubuntu with Docker.

### Monitoring with real clients (Go)

An unmodified Shadowsocks client and a WireGuard client reached the server:

- Alice's live download rate was measured above 100 KB/s, and she showed online.
- An open CONNECT tunnel counted as 1 active connection and dropped to 0 after closing.
- Traffic counted under "Web (HTTP)" and "shadowsocks" (Bob's under "wireguard"), with an hourly series.
- With site stats on, Host `www.youtube.com` was counted as "YouTube".
- Client addresses: Alice `shadowsocks 127.0.0.1` from the inbound, Bob `wireguard 127.0.0.1` from the parsed UAPI endpoint.
- History saved and reloaded into a new monitor; turning site stats off removed every stored site

### Rotation

Retention kept exactly 30 daily buckets and removed site totals older than the 10-day site retention. A cap 200 bytes under the full size trimmed site data before breakdowns while keeping all days, and a 400-byte cap was honored. Client records outside 30 days were dropped. A simulated low disk paused detail recording (no detail counters created), and it resumed when space returned

### QR codes and kit

For all four protocols, both the SVG (path parsed back to modules) and the terminal half-block output decoded with an independent decoder (gozxing) to exactly the key or `.conf`. The kit contains every key, one QR code per key and the privacy note, with no script

### Dashboard

Index served with a strict CSP:

- **Auth:** no session 401; wrong token 401; the right token gave a 204 with an HttpOnly, SameSite=Strict cookie; a missing CSRF header 403; a foreign Host 403; the API and kit worked through the dashboard.
- **Ports:** 443, 80, the API port and a protocol port were refused as dashboard ports; moving the port closed the old one; a token reset signed sessions out.
- **Public mode:** TLS 1.3 with the pinned certificate and a Secure cookie; back to private worked.
- **Throttling:** 20 bad tokens returned 429 even for the right token

### Server commands

Against the real API listener:

- **Users and keys:** user add (with a limit), a duplicate-name refusal, key add (key, `.conf` and terminal QR), keys list with and without `--show`, key qr.
- **Rules:** per-user and global rules.
- **Monitoring:** site-stats, settings, top --once, stats, usage, clients.
- **Sharing and dashboard:** the kit; dashboard (tunnel command and link); a `--port 443` refusal; a token reset.
- **Settings and users:** set including the retention cross-check; user limit, disable and remove; JSON output. On Windows the same commands ran against a live local server

### Daemon/CLI (Node, real server)

`server live`, `stats` (and an invalid range refused through IPC), `clients`, `keys qr` (terminal QR), `keys kit` (a new file with keys and QR SVGs), and `set --site-stats on --history-days 60` reflected in `info`. Agents were refused for live and kit; 19/19 process tests passed

### App GUI (WebView2 DevTools, isolated profile)

Server page live panel, per-user online and speed lines, the Stats dialog, the AmneziaWG QR dialog, and Server settings with the monitoring section. **Save connection kit** wrote `Downloads\Alice-vpn.html` (2 QR codes, test keys for the local test server), which was then deleted. The first attempt with a `blob:` download failed in WebView2 and was replaced by a desktop save command

### Web dashboard (in the app's isolated WebView2)

The login link signed in and the fragment was removed. Overview (live cards, chart, server card, empty breakdowns), Users (status, offline, actions), Keys (QR `.conf`/`vpn://`, copy, kit) and Settings (protocols, monitoring, retention, dashboard port note) were inspected

### Static checks

Rust fmt and clippy clean (root and desktop); 33 Rust unit tests passed; Go vet clean; all Go tests passed; `govulncheck` **No vulnerabilities found**; server cross-builds for linux/amd64 and arm64

### Release dry run

The first dry run of this commit built and passed Linux x64 and arm64: client and server packages, the server install, the admin commands and the dashboard checks. The Windows job failed, correctly, at the corresponding-source build check: the bundle copied only `.go`/`.mod`/`.sum`/`.md` files and missed the dashboard pages that the server embeds (`pattern dashboard: no matching files found`). The script now copies every module file except `vendor/` and binaries; the local rerun built from the staged copy.

### Not verified

Health readings on a real Linux host (CPU, memory and network come from `/proc`; unavailable on Windows dev); the dashboard over a real SSH tunnel; public dashboard mode in a browser; top-services accuracy for apps using ECH

## v0.3.1 Windows installed-service fix (2026-11-06)

First real MSI installation, on the user's Windows 11 machine by the user.

| Check | Result actually observed |
|---|---|
| Installed v0.3.0 | The `Ghostlink` service was installed and running as LocalSystem, with the user's SID as owner. `\\.\pipe\ghostlink` existed: owner BUILTIN\Administrators, DACL `D:P(A;;FA;;;SY)(A;;0x12019f;;;<user SID>)`, and a plain pipe connect succeeded. The installed v0.3.0 CLI and app still reported `daemon_unavailable`: the client's identity check opened the SYSTEM process token, which a standard user may not do |
| Fixed client against the real installed service | The rebuilt CLI with the pipe-owner check answered `status` and `doctor` from that SYSTEM service, while the installed v0.3.0 CLI failed side by side. Shortly afterwards the user uninstalled v0.3.0 (16:43), so the fixed desktop app could not also be checked against an installed service |
| Same-user development path | The 19 process tests (service as the same user, pipe owned by that user) passed with the new check |
| Shortcuts | The v0.3.0 MSI's Start-menu shortcut had no icon (`IconLocation ",0"`) and there was no desktop shortcut. The v0.3.1 MSI's Shortcut table has `StartMenuShortcut` and `DesktopShortcut`, both with `Icon_ = Ghostlink.ico`, which is present in the Icon table and set as `ARPPRODUCTICON`. The WiX build validated |
| Not verified | The fixed app installed from the v0.3.1 MSI, and the shortcut icon appearing in Explorer (both need the user's installation) |

## v0.3.0 Ghostlink server and server management (2026-11-06)

Observed on the Windows development host (unelevated, loopback only) unless noted. Release CI results for the server packages are recorded when the release runs.

| Check | Result actually observed |
|---|---|
| Server, real traffic (Go `internal/server`) | Keys issued through the API were turned into **unmodified** sing-box clients, using only the key text, for all four protocols: AmneziaWG (our endpoint), WireGuard (sing-box native client), VLESS-REALITY (local TLS 1.3 handshake target) and Shadowsocks. Each carried HTTP through the server. In each, a per-user blocked site, a global blocked site (`*.Global-Blocked.test`, normalized and matched for `www.` by Host sniffing) and a loopback service on another port were refused. A second user was unaffected by the first user's rule; an exempt user skipped global rules but not the internal block. Usage was counted; a 1-byte limit cut the user off and resetting restored access; disabling a user and deleting a key cut them off; state persisted |
| Server API | Unknown fields, missing or control-character names, bad IPs, ports and sites, unknown protocols, missing IDs, bad hostnames and IP REALITY sites were refused with the right status. A port clash was refused and changed nothing; a disabled protocol could not issue keys. Only the exact secret path worked, and 20 wrong guesses gave `429`. The real listener served TLS 1.3 only, with a certificate matching the printed pin. `init` creates once, keeps the secret, updates the hostname and fails without an address |
| Keys format | Amnezia `vpn://` keys decode in the exporter format (length prefix, zlib, `last_config` with the `.conf` and AWG parameters, no `userName`/`password`). AWG 2.0 parameters drawn 200 times were valid (S1+56≠S2, disjoint header ranges) |
| Daemon/CLI with a **real** `ghostlink-server` (Node suite) | `server add` with the printed key, no overwrite without `--replace`, and list output with neither the secret nor the pin (nor in Windows state). Then: user with a 5 GB limit; an AmneziaWG key created with `--import` became a working profile via the Rust parser; VLESS and WireGuard keys written to new private files (`.conf` imported as `wireguard`), with no overwrite; a printed `ss://` key imported. `keys list` hid key material unless `--show-keys`. Global and per-user rules, usage, disabling WireGuard (key creation then refused) and disabling a user worked. A wrong pin gave `server_identity_mismatch`; `http`, missing-pin and extra-field keys gave `invalid_request` without echoing the secret. Agent tokens were refused for all server actions; the audit log never contained the secret; a stopped server gave `server_unreachable` |
| Pinned client (Rust unit) | With a wrong pin, the TLS server received **zero** application bytes (the secret path was never sent). Outline servers were recognized and refused as unsupported; server error text came back without the key; operations map to fixed paths, with path-traversal IDs and unknown protocols refused |
| Desktop GUI | Debug app against an isolated dev daemon and a real local server, driven over the WebView2 DevTools protocol. Inspected: server list; server page (users with status chips, limit meter, rules summary, ports); keys dialog; per-user rules; server settings; creating a WireGuard key with "Also use it on this device", which then appeared under My servers as "Alice @ Home lab" with its badge; dark and light themes |
| AmneziaWG close race (Linux CI of v0.2.1, `cbc567f`→`02a9d06`) | Hosted CI crashed an AWG 2.0 client worker during graceful stop: nil dereference in sing-box's stack `Write`, called from amneziawg-go's receive goroutine after the TUN closed. Fixed in the TUN adapter; a regression test passes with the fix and panics ("write after close") without it |
| Corresponding source | The v0.2.1 zip was rebuilt from the `v0.2.1` tag with the fixed script: it built every command on Windows inside the script and `ghostlink-tunnel` for linux/amd64 from the unzipped copy, reporting `0.2.1`, with 0 backslash paths. It replaced the incomplete zip in the v0.2.1 draft, and `SHA256SUMS.txt` was refreshed |
| Static checks | Rust fmt and clippy (`-D warnings`) clean; 33 Rust unit tests (29 engine, 4 contracts) and 19 Node process tests passed; Go vet clean; Go tests passed; `govulncheck` **No vulnerabilities found**; server cross-builds for linux/amd64 and arm64 |
| Package spec (local) | nfpm built placeholder server `.deb`/`.rpm`; the `.deb` control has `Depends: docker.io \| docker-ce \| moby-engine \| docker-engine \| podman-docker, passwd`, the three maintainer scripts and a `0755` `/usr/sbin/ghostlink-server` |
| Not verified | The server on an internet-facing VPS; Amnezia's own apps importing our `vpn://` keys; RPM install on Fedora/RHEL; podman; IPv6 inside tunnels; management through a connected full TUN (the bypass rule is unit-tested, not routed) |

## v0.2.1 Linux packages (2026-11-06)

| Check | Result actually observed |
|---|---|
| Linux SIGPIPE fix in CI | The full CI run after the fix (`cbc567f`) passed on Ubuntu 24.04 and Windows 2022, including all real-engine protocol and split-tunnel tests |
| Package spec (local) | nfpm 2.48.0 built a `.deb` and an `.rpm` from the template with placeholder binaries. The `.deb` control has `Depends: libc6 (>= 2.35), libssl3 \| libssl3t64`, a conffile for `/etc/ghostlink/ghostlinkd.env`, postinst/prerm/postrm, root-owned `0755` binaries in `/usr/bin` and `/usr/lib/ghostlink`, and the unit with `/usr` paths and `$GHOSTLINK_FLAGS` |
| Checksum refresh for arm64 files | The idempotent update was exercised locally twice: a stale line was replaced, with no duplicates |
| Release CI (run 42175275443) | On Ubuntu 22.04 x64 and arm64 the `.deb` installed as a real systemd service: the installer set owner UID 1001 from `sudo`, `ghostlinkd` was `active`, and `ghostlink status`/`doctor` answered as that user. Purge removed it. The `.rpm` passed `rpm -qip/-qlp/--scripts`. The draft had all 10 files. A cosmetic dpkg warning about `/usr/lib/systemd/system` was fixed in v0.3.0 |
| Same commit, CI workflow | Failed on Ubuntu: the AmneziaWG close race recorded under v0.3.0 (the release workflow does not run that test) |

## First hosted CI run of v0.2.0 (2026-11-06)

- **What failed:** on GitHub's Ubuntu runner, two new real-engine tests failed; the Windows job was cancelled by the matrix.
- **Cause:** the test helper dropped the worker's stderr pipe after the first event, so the worker's final event write raised **SIGPIPE** on Linux and killed it; Windows has no SIGPIPE. The split test's first tunneled request also outran its short retry budget under parallel load.
- **Fixes:**
  - the worker now ignores SIGPIPE on Unix, so a broken status pipe can never interrupt the engine's graceful close (a product hardening, not only a test fix);
  - the tests drain worker events for the worker's lifetime and report its failure code;
  - the split test waits for the tunnel through the always-tunneled health proxy before checking routes;
  - CI runs these tests one at a time.
- **Local result:** all three pass serially on Windows. The Linux result is pending the next CI run.

## Client split tunneling (2026-11-06)

| Check | Result actually observed |
|---|---|
| Real worker routing (proxy-only, loopback) | Full mode kept everything in the tunnel; bypass by IP (`127.0.0.1/32`) and by site (`bypass.test`, matched for `www.bypass.test` via HTTP Host sniffing) went direct while other sites stayed tunneled; "only" mode tunneled the listed range and sent the rest direct; the **health probe stayed in the tunnel** in "only" mode |
| Rust unit tests | 22 engine tests passed (new: policy normalization/rejection, bypass/only rule rendering) |
| Daemon/CLI process suite | 18 passed (new: set/show/clear globally and per server, normalization, invalid entries rejected, override kept across `--replace`, agent tokens refused) |
| Desktop GUI | Settings card summarized a CLI-set policy; the dialog loaded and saved it; a per-server override was created from the server menu and confirmed via CLI (screenshots inspected) |
| Not verified | Process (app) matching and full-TUN routing need an elevated test; domain rules against ECH traffic |

## WireGuard, AmneziaWG, VLESS-REALITY and Amnezia import (2026-11-06)

Observed on the Windows development host, unelevated; all traffic tests are loopback and proxy-only.

| Check | Result actually observed |
|---|---|
| AmneziaWG endpoint (`internal/awg`) vs **upstream amneziawg-go** | Real HTTP through the tunnel with legacy AWG, AWG 2.0 (H ranges, I1 chain, header protection key) and zero-parameter WireGuard; a mismatched H1 failed the handshake |
| Server role | Upstream amneziawg-go AWG 2.0 client and a stock WireGuard client (sing-box native endpoint) both reached a web server behind our endpoint; `auth_user` rules blocked only the named peer's user |
| VLESS-REALITY | Client outbound as generated by Rust carried HTTP through a sing-box REALITY server borrowing a local TLS 1.3 handshake; a wrong short ID was refused |
| Generated configs | All seven kinds (WireGuard full/split, AWG legacy/2.0, VLESS-REALITY/TLS, Shadowsocks) accepted by the real worker `check`, with and without the TUN inbound |
| End-to-end engine test | `.conf` → Rust parser → generated config → worker client → worker server → loopback web server, for WireGuard, legacy AWG and AWG 2.0; both workers stopped cleanly on stdin EOF |
| Daemon/CLI process suite | 17 passed, including `.conf`/`vpn://`/`vless://` imports, `PostUp`/`Table`/plaintext-VLESS rejection, full-access `vpn://` refusal without echoing the SSH password, and no key material in list output or sealed state |
| Rust unit tests | 19 engine + 2 contracts passed (new: WireGuard/AWG parser, VLESS parser, `vpn://` decoder incl. decompression caps) |
| Dependency scan | `govulncheck` found two advisories newly reachable via uTLS (brotli, klauspost/compress); after updating both, **No vulnerabilities found** |
| Desktop GUI | Debug app launched against an isolated dev daemon; three test servers rendered with AmneziaWG/WireGuard/VLESS badges and imported display names (screenshot inspected) |
| Not verified | A full-TUN connection with any new protocol (needs administrator), and Amnezia's own apps importing keys exported by Ghostlink (server phase) |

## After the Ghostlink rename and review fixes (2026-11-06)

Observed on the same Windows development host, unelevated.

| Check | Result actually observed |
|---|---|
| Autoconnect startup failure (before the fix) | Reproduced with an isolated dev daemon: with autoconnect enabled, an engine-start error made the daemon exit 1, and `autoconnect disable` returned `daemon_unavailable` |
| Rust fmt / clippy | Root and desktop `fmt --check` clean; root clippy `--all-targets -D warnings` clean |
| Rust unit tests | 12 passed (2 contracts + 10 engine); 3 real-engine tests ignored as designed |
| Daemon/CLI/MCP process suite | 16 passed on debug binaries and again on release binaries. New: failed autoconnect keeps the service reachable and reports `autoconnect_failed`; crash leftovers removed at startup; import refuses to overwrite without `--replace`; fingerprint is not a plain credential hash |
| Real-engine tests | 3 passed with the renamed worker (`Ghostlink tunnel worker 0.1.0; sing-box 1.14.4`) against the independent sing-box 1.14.4 peer |
| Go worker | vet and test passed; Windows build passed; linux/amd64 and linux/arm64 cross-builds passed (not executed on Linux) |
| Python provisioning | 2 passed on Python 3.12 and Python 3.13 after `provision.py` switched to absolute System32 `whoami.exe`/`icacls.exe`; a bare `whoami` had resolved to Git's GNU tool |
| Windows packaging | Release Rust, desktop and worker builds passed. The MSI compiled, linked and validated after a quoting fix in `build-windows.ps1`. The MSI tables show ProductName `Ghostlink`, version 0.1.0, a new UpgradeCode and service `Ghostlink` with the renamed arguments; the portable ZIP and the worker source bundle were also produced. Installation still not executed |
| Release workflow | `release.yml` parses; version/tag check and publish file-collection logic exercised locally. Not yet run on GitHub-hosted runners; no tag pushed and no release created |
| Linux service | Unit now includes `CAP_CHOWN`; still not run on Linux |

## Earlier results (before the rename)

| Check | Result actually observed |
|---|---|
| Windows Rust root workspace | Builds; unit tests pass; clippy with warnings denied passes |
| Current Rust unit tests | 12 passed, including actual TCP listener process ownership and DPAPI storage |
| Daemon/CLI/MCP process suite | 14 passed using actual named pipes and subprocesses (16 after the rename; see above) |
| Real Shadowsocks interoperability | HTTP traversed a local encrypted server/client; incorrect password did not reach a live destination; controller denied missing authorization |
| Managed worker lifecycle | Explicit stop and parent-stdin EOF both produced graceful close and removed the real listener |
| Startup failure cleanup | Invalid engine configuration left no plaintext outline.json |
| Unelevated Outline TUN start | Rejected with failed state and no VPN IP; disconnect completed; temporary config removed (explicit unprivileged test enabled) |
| Native desktop runtime | Launched; empty state and access-key dialog inspected; a test key was imported through the GUI and confirmed via CLI; light/dark views inspected |
| Windows release / MSI | Optimized binaries and MSI built; WiX linking/package validation passed; installer execution and elevated service lifecycle are not verified |
| Release process suite | The same 14 tests passed again against final optimized CLI/service/MCP/worker binaries, including the unelevated TUN failure case |
| Worker corresponding source | Vendored source staging built successfully with Go 1.26.10 and the published flags; version command passed. Vendored builds omit module checksum build metadata, so byte-identical reproduction is not claimed |
| Wintun provenance | Embedded amd64 DLL matched official 0.14.1 bytes; Authenticode valid, WireGuard LLC |
| Dependency scans | npm audit: zero known vulnerabilities; govulncheck 1.9.0: no vulnerabilities after dependency updates; OSV Rust lock scan: 3 matches representing 2 unresolved Linux GUI/build dependencies (see security report) |
| Offline server provisioning | Two Python integration tests passed: distinct Outline keys/config/removal and real OpenSSL CA issuance, server-only bundle, CRL revocation |
| Linux | Managed Go worker cross-compiled for linux/amd64; Rust daemon/GUI and runtime remain unverified |
| Terraform | 1.14.6 init with backend disabled and validate passed; AWS provider 6.72.0 lock recorded; no plan/apply or cloud changes |
| Android / iOS | Not implemented or compiled; native toolchains/signing/devices required |
| Full-device routing / DNS / IPv6 / crash recovery | Not verified; requires authorized privileged network tests |

Commands:

```powershell
./scripts/cargo.ps1 test --locked --workspace
./scripts/cargo.ps1 clippy --locked --workspace --all-targets '--' -D warnings
npm test
$env:GHOSTLINK_TEST_SING_BOX = 'D:\ghostlink\.tools\sing-box\sing-box-1.14.4-windows-amd64\sing-box.exe'
$env:GHOSTLINK_TEST_OUTLINE_WORKER = 'D:\ghostlink\target\debug\ghostlink-tunnel.exe'
./scripts/cargo.ps1 test --locked -p ghostlink-engine --test outline_traffic '--' --ignored --nocapture
```

The ignored test suite contains three real-engine tests and is run explicitly with those paths. Keep `'--'` quoted through the PowerShell wrapper. Use a separately obtained, pinned standalone sing-box executable for the independent peer and the built managed worker for lifecycle tests.

`GHOSTLINK_TEST_EXPECT_UNPRIVILEGED=1` enables the TUN-start failure check inside the Node suite. Set it only after verifying the test process is unelevated; it intentionally attempts native startup and must not be enabled on a privileged shared machine. Standard tests otherwise do not replace OS routes.

GUI menu polling was found to recreate controls every refresh and has been changed to preserve unchanged server cards. Native inspection confirmed the menu remained open across refreshes. A second defect clipped the lower menu items at the card edge; the CSS fix was rebuilt, launched and visually verified with all four actions visible. Server details and Settings were also inspected. Narrow-window layout, service-recovery notice and tray/uninstall verification remain pending. Test fixture keys were removed from development state; no real access credential was used.

Security scan scope and remaining findings are recorded in [the dependency report](../security/dependencies.md). Scan databases change; rerun before a release.
