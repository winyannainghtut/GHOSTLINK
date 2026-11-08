# Changelog

All notable changes to Ghostlink. Versions follow [semantic versioning](https://semver.org/); pre-1.0 releases are unsigned pre-releases. The release workflow copies a version's section into its GitHub release notes.

## [Unreleased]

## [0.8.1] - 2026-11-08

Fixes on top of 0.8.0: what was reported on a running server, what a review of 0.8.0 found, and what a second, full review of the code found. Upgrade servers: this release closes ways for VPN users to reach the server's own services and its network (*Server: what VPN users can reach*), and a way for a compromised server to get hold of any directory on its host (*The state and root*). See *Changed* for what behaves differently after an upgrade.

### Fixed

Reported on a server running 0.8.0:

- **Online and idle:** a client that had disconnected could show as online for many minutes, for example after switching WireGuard or AmneziaWG off. Its connections stay open on the server for a while, and remote services keep writing to them, which counted as activity.
  - **Now:** a client is online while it sends something at least once a minute, and shows as idle within about a minute of disconnecting.
  - **What counts:** a new connection, an upload, a substantial download, a WireGuard/AmneziaWG keepalive (the keys the server issues send one every 25 s, so idle but connected WireGuard and AmneziaWG clients stay online) or an IKEv2/IPsec session that is up. The server now checks WireGuard and AmneziaWG peers every 5 s instead of every 30 s.
  - **Clients view:** the "Last handshake" column and card field are now "Last seen", which is what they show.
- **Off switches in the Daylight finish:** an off switch was almost invisible, white on white, and more so when disabled (IKEv2 and IPsec without the IPsec component). Off switches now have a visible track in every finish.
- **Live speed in the Island:** the dashboard's and the app's capsules showed both rates in MB/s with two decimals, so anything under 5 KB/s read 0.00. Each rate now has its own unit (B/s, KB/s, MB/s or GB/s), with room for it, so the capsule keeps its width.

Found by a review of 0.8.0 after its release:

- **Speed limits:**
  - **UDP:** a capped client's Shadowsocks UDP above its rate could hold up other clients' Shadowsocks UDP on the same port. UDP that a capped client sends is now dropped above the rate instead of delayed, on Shadowsocks, VLESS, WireGuard and AmneziaWG alike; apps such as QUIC slow down when packets are lost. UDP sent to the client is still delayed. While the client's TCP upload fills the cap, its UDP still gets a share of it, and TCP slows down instead.
  - **Many connections:** a client with many connections could get several times its cap, then stall. A single wait was cut off at 5 s; it now lasts as long as the cap requires.
  - **Changes:** a new limit now takes effect at once, also for connections already waiting.
  - **IKEv2/IPsec:** a changed limit now applies to sessions that are already connected. The kernel kept a `hashlimit` table's first rate.
  - **Concurrent changes:** two changes at the same moment could leave the older limits in force.
- **`migrate-outline`:**
  - **Failure or interruption:** if a step fails or the command is interrupted (Ctrl+C, a lost SSH session), Outline is put back exactly as it was: each container's restart policy, and running only if it was running.
  - **After the import is saved:** if a later step fails, Outline stays stopped instead of starting on Ghostlink's ports.
  - **Printed commands:** the rollback uses the saved policies, and the clean-up command quotes an absolute path.
  - **Check hint:** `--check` repeats `--outline-dir` in its hint.
- **Outline import:**
  - **Ports:** keys on UDP 4500 while IKEv2/IPsec is on get a new key instead of failing the import. Keys on the IKEv2/IPsec DNS port now get a new key also while IKEv2/IPsec is off, so turning it on later still works. New ports are never picked on an imported key's port.
  - **Management key:** a failure to rewrite it after a saved import is reported as a note rather than as a failed import.
  - **Notes:** the note about two keys sharing a password is now accurate, and the check no longer prints a port number that the import picks anew.
- **App and dashboard:** they can again save a client's settings on a server older than 0.8.0. `speed_limit_bps` is now sent only when it changed.
- **Speed units:** `sudo ghostlink-server user speed NAME 10Mbps` (bits) is refused. It was read as 10 MB/s, eight times what was meant.
- **Installer:**
  - `--outline-dir` without `--migrate-outline` is refused.
  - `--migrate-outline --check` says that `--ipsec`, `--mesh` and `--open-firewall` wait for the real run.
  - `--hostname` says that it overrides Outline's address.
- **Tests and CI:**
  - The Outline smoke test also checks a failed import that must put Outline back, and fails on the installer's exit status.
  - The engine's real-traffic test takes its Shadowsocks peer's port from the system's free UDP ports first and then checks TCP, with more tries: on the Windows runners, ports free on TCP are often in reserved UDP ranges, and the TCP-first check failed.

Found by a second, full review of the code:

- **Server: what VPN users can reach.**
  - **UDP after the first packet:** the server checked a UDP session only by its first packet. A key holder could send the rest of a Shadowsocks, VLESS, WireGuard or AmneziaWG session to the server's loopback, its private network, the server itself, or an address or port the rules block. Every later packet to another address is now checked against the same address and port rules. WireGuard and AmneziaWG also give each UDP destination its own session.
  - **The server's own addresses:** VPN users could reach every service on the host through its public IPv6 address or its other addresses, or through its public address when the hostname is a DNS name, past host firewall allowlists. Every public address on the host is now blocked, and the dashboard port is blocked on every address, like the API port.
  - **Exempt clients on WireGuard and AmneziaWG:** the global rules could still block an exempt client's UDP, and ping skipped a client's own blocks and was not counted in its usage.
- **Server: running.**
  - **A busy port at start:** if another program held one of the VPN ports, the server restarted over and over and no server command could fix it. The management API, the dashboard and the server commands now start anyway; the VPN engine is tried again every 30 s, and `GET /live` reports `health.engine_error`. `setup` (which every upgrade runs) and the installer then finish and say the server is running, and `status`, the app and the dashboard do not show the problem: if nobody can connect, check `sudo ghostlink-server logs`.
  - **Port changes:** a port below 1024, or one another program uses, is refused when it is set, also for a protocol without keys and for the dashboard, instead of failing later.
  - **Memory:** with WireGuard or AmneziaWG on, each change that restarted the engine (adding, removing or disabling clients or keys, rule edits, a lifted data limit) left one or two network stacks and their threads in memory until the server restarted.
  - **Container log:** the VPN engine logged the names users looked up (blocked sites too) and the addresses they could not reach. The engine's own log is now off; the log holds only the server's own warnings and errors.
  - **Hostname change:** a saved change now reports success even if the management key file cannot be rewritten; the error is logged with the command to run.
- **Server: speed limits, usage and statistics.**
  - **Usage:** traffic that could not be saved, for example on a full disk, is now kept and saved later instead of being lost.
  - **Statistics:** the per-client totals for the last 24 hours and 7 days also included the whole first day. They now cover the range, like the chart.
  - **Site statistics:** names that are not valid DNS names (a client can send tens of kilobytes) count as "Other sites", and sites with no traffic for a day are dropped from memory.
  - **History settings:** `set --history-days` below 30 no longer needs `--site-days` as well. The history size limit and the low-disk threshold are in MB of 1,000,000 bytes, as the server shows them.
  - **Deleted clients:** their last addresses and traffic no longer come back into the history.
  - **Connection kit:** no empty QR code for IKEv2/IPsec keys.
  - **Outline import:** the report and the guide say that Outline's data limits count the last 30 days, while Ghostlink counts usage from the move on and never resets it by itself. The port of a mesh that is turned off is kept free for it.
- **IKEv2/IPsec.**
  - **User names:** a user with an IKEv2/IPsec key got an identity the IPsec component refuses when their name, after dropping every character other than Latin letters, digits, `-`, `_`, `.` and spaces, began with `-`, `_`, `.` or a space: for example `_bob`, `.x`, "📱 Phone", or a name in Burmese, Cyrillic or Chinese with a space in it ("Иван Петров"). A one-word name in those scripts already got the valid `user-ID@ghostlink`. The server then wrote no settings at all, for anybody: new keys, disabled and removed users, data limits and speed limits no longer reached the component, and sessions stayed connected. The default identity now always starts with a letter or digit (`user-ID@ghostlink` when nothing in the name is usable), and a key the component would refuse is left out instead of blocking everyone.
  - **Renaming a user:** a key now keeps the identity it was created with. Before, a rename locked the user out of every IKEv2/IPsec key that used the default identity (a key created with its own local identifier was not affected), and a certificate key could not be repaired. Existing keys keep the identity they have now, with one exception: a key whose default identity the component had refused (see *User names*) takes the new default, whatever its sign-in type. A certificate key whose certificate names another identity (such a key, or a key of a user renamed under 0.8.0) gets a new certificate, and the old one is revoked. Send the profile again for each of these keys, and for the keys of a user renamed under 0.8.0 that use the default identity: they stay locked out until then.
  - **Usage:** after a restart or an upgrade of the server, every connected session's whole total so far was added to the user's usage a second time, and could trip a data limit. A session that was ended because the user was disabled, over the limit or had the key removed was also counted twice about half the time.
  - **Online state:** a client that had left stayed online for up to four minutes. Its closed session was reported again every 5 s for a minute, and the server then still counted a client as online for three minutes after it was last seen.
  - **Settings:** the server rewrote the component's settings after every saved change, including the usage accounting every 30 s, and the component reloaded strongSwan and its firewall each time. It now writes only when something changed for the component, one write at a time.
  - **Server certificate:** it is checked when the server starts, and `setup --hostname` (and the installer's `--hostname`) reissue it for the new address. A server restarted more often than once a day never renewed it.
  - **Profiles:** the profile identifier names the server by its CA instead of its name, so two servers with the same name no longer replace each other's profile on a device.
  - **IPsec component:** it checks the firewall settings also when IKEv2 and IPsec are both off, refuses address pools outside private space, ends the sessions of removed or disabled users before it touches the firewall, and shows a failure to apply speed limits in `ipsec status`.
- **Server commands, setup and the installer.**
  - **The state and root:** `sudo ghostlink-server` no longer follows a symlink in `/var/lib/ghostlink-server`, which the server's own account controls. A compromised server could have made `setup` (run on every upgrade) or `ipsec enable` give any host directory to that account and mount it into the IPsec component, or made `migrate-outline` copy Outline's keys elsewhere.
  - **Upgrades and `setup`:** the running server is stopped before setup changes its state, instead of being killed afterwards, so it saves its last usage and history and cannot write its old address over a new `setup --hostname`. If setup fails before the new container starts, the old server starts again. `remove` stops it the same way, and the previous version's images are removed in the same run.
  - **Leftover words:** a command with options refuses a word that none of its options takes, instead of ignoring it, and `user enable`, `disable`, `reset` and `remove` take one name. `user add Alice --exempt false --limit 5GB` turned `--exempt` on and dropped the limit. Commands without options, such as `users`, `usage` and `settings`, still ignore extra words.
  - **Speed units:** `10Mb/s`, `10Mb` and `10 mb` (bits, with a lower-case b) are refused like `10Mbps`; `2MBps` is accepted.
  - **`key qr`** with an unknown key or a bad `--content` fails instead of exiting 0.
  - **`--json`:** `set` and `site-stats` print the settings after the change, and `dashboard` its port, mode, login token and address.
  - **`kit` and `profile`:** with the server or Docker down, they left an empty file that blocked the next try. The file is created anew, never through a symlink.
  - **`status`** labels the address and each service's port, including the ports of keys from Outline.
  - **`mesh join-here --port N`** tells the other nodes port N, not 51820.
  - **Installer:** `--reinstall` reinstalls the version already installed; server packages of pre-release versions are named so the installer finds them; `--add-swap` says when no swap file is needed; if the migration fails after the import was saved, the installer still prints the management key and the ports.
- **Mesh.**
  - **Container ports:** ports a node publishes for Docker or Podman containers, and Kubernetes NodePorts, could not be reached over the mesh. They now follow the node's access rules, as long as the agent's firewall rules come before Docker's in the FORWARD chain. Docker puts its rules first when it starts after the agent (at boot, for example), and can do so when it restarts or creates a network; every node then reaches the published ports whatever the rules say, until `sudo systemctl restart ghostlink-mesh` puts the agent's rules first again.
  - **Relayed pairs:** two nodes that need the relay lost their connection for about 90 seconds every 16 minutes, when the coordinator tried the direct path blindly. They now test the direct path in the background and switch to it only once it works.
  - **A node coming back** after a few minutes away could have all its links sent through the relay for 15 minutes.
  - **Firewall:** the agent sets up its firewall before the interface, so a firewall error leaves the node off the mesh instead of open to it; it puts its rules back within about 30 seconds after a firewall reload removed them; and it uses the iptables backend the host uses, also at boot (on hosts with the legacy backend, relayed and subnet traffic stopped after a reboot).
  - **Forwarding consent:** a node made a relay from the app forwarded traffic without its operator's consent on hosts where IPv4 forwarding was already on (Docker hosts). A relay invite's command now includes `--relay`.
  - **Routes:** a node on the same LAN as a shared subnet lost its route to its own LAN, and the route did not come back when the mesh was removed. A node now leaves another node's subnet out of the mesh when it is on that network, already has a route for exactly that subnet, or reaches a peer at an address in it. Its status and the map name the subnets it leaves out.
  - **A subnet router's own address** in the subnet it shares (often the gateway or DNS) was unreachable from the mesh.
  - **Turning it off:** `mesh disable` closed the port before nodes heard about it, so most kept their links.
  - **Waiting nodes:** a node waiting for approval, or disabled, asked the coordinator again at once, over and over.
  - **Map traffic:** each direct link's traffic was counted twice.
  - **firewalld:** on Fedora, RHEL, Rocky and Alma, firewalld refused all mesh traffic but ping and SSH. `install-mesh.sh --open-firewall` now also puts the mesh interface in firewalld's trusted zone, and without that option the installer says what to run. Upgrading the agent does not change firewalld, and the coordinator's own node (`install-server.sh --mesh` or `mesh join-here`) gets neither the change nor the hint. On nodes set up earlier and on the coordinator's node, run `sudo firewall-cmd --permanent --zone=trusted --change-interface=glmesh0 && sudo firewall-cmd --reload`.
  - **Installer:** without `--join` it installs or upgrades the agent only, as the guide says; running the join command again upgrades the agent; it works on bash before 4.4 (Amazon Linux 2); and the invite can come from `GHOSTLINK_MESH_INVITE`, which keeps it out of the process list.
  - **Packages and agent:** an rpm upgrade left the agent stopped; an interface deleted under the agent is created again; `leave` keeps IPv4 forwarding on when Docker or similar software may need it; an `/etc/hosts` replaced by another program is reported with how to recover.
  - **API:** `PATCH /mesh` with a new network turned a mesh that was off back on.
- **App and dashboard.**
  - **Deletes in Servers I run:** revoking a key, removing a client and rejecting or removing a mesh node showed "Incompatible service response" although the server had done it; the matching `ghostlink server …` commands exited with an error.
  - **Client sheet:** closing a QR code (Done, Escape or a click beside it) also closed the client, and lost what was typed under New key.
  - **Edits being reset:** a client's Rules tab, and a mesh node's tags and shared subnets, went back to the saved values on every refresh.
  - **Mesh access rules:** a list of ports such as "5432, 8000-8100" can be typed; the comma or space disappeared as it was typed.
  - **Messages over sheets:** messages shown while a sheet was open were blurred under it and could not be read.
  - **Certificate password:** "Without password" showed the profile's password only in a message that disappeared after 3 seconds. It now stays in a sheet with a Copy password button.
  - **Server not answering:** the last live readings stayed on screen as if they were current. The Island now says "Server not answering", and clients are no longer shown online.
  - **Overview:** the 24 h chart and the day and week cards refresh every minute; they were fetched only when the view opened.
  - **Older servers:** opening Network or the Island's protocol list for a server older than 0.5.0 left the window blank.
  - **Ports of imported Outline keys** are listed in Network and the Island, so you can open them in the firewall.
  - **Client settings:** a speed limit below 0.001 MB/s, set with the server's commands, blocked saving the client's other settings; half-typed numbers such as "2e" silently removed a data limit or the default speed limit; Reset usage asks first and changes nothing else.
  - **Usage chart:** west of UTC, every daily bar was labelled a day early.
  - **WireGuard on Windows:** some downloaded .conf files had names longer than WireGuard for Windows and AmneziaWG accept. The app also saved copies as "name (1).conf", whose space they refuse; it now saves "name-1.conf". In the dashboard the browser still names a second copy itself (Chrome and Edge: "name (1).conf"), so rename it before importing it.
  - **Dashboard sign-in:** opening the login link again in the same tab did nothing, and a failed sign-in left "Connecting to the server…" on screen.
  - **The app:** a failed connection explains why in words instead of an internal code; Servers I run shows each server's current name and version; a second server named in another script (Burmese, Thai, Chinese…) is no longer refused; "Use on this device" works for long client names; an action taken while a connection was starting or stopping says to try again; Add key and Add server no longer reopen their sheet; errors while saving a file are no longer empty; the tray's Open Ghostlink restores a minimized window.
  - **Keyboard and screen readers:** a client opens from the keyboard in the list; sheets are announced by their title; New client, Add access key, Rename server and Add a server put the focus in their first field.
  - **Smaller fixes:** Enter in New client follows the Create button's rules; Turn on mesh no longer reports success after a failure; the map keeps dragged positions when a node joins; numbers no longer read "1000 KB/s"; the app asks the local service for its saved servers every 5 s instead of every second, and both apps stop polling while hidden.
- **Connections on this device.**
  - **PCs with Hyper-V, WSL or Docker:** when a Hyper-V or WSL switch, a Docker network or the LAN covered 172.28.85.0/30, every Shadowsocks, VLESS, WireGuard and AmneziaWG connection failed with a permissions or driver error. Only an address inside the tunnel's own range stops a connection now.
  - **Connections into the device:** with WireGuard or AmneziaWG, the server, or another client of a server that forwards between clients, could open connections into the device through the tunnel; in "only" mode or with the LAN kept direct they reached the device's own services and network. They are now refused.
  - **OpenVPN reconnects:** after a dropped connection (Wi-Fi lost for longer than the server's ping timeout, sleep, a server restart), an OpenVPN connection stayed "reconnecting" until you disconnected by hand, while traffic left outside the VPN. It now reconnects by itself, and a first attempt can move on to the profile's next `remote`. While it reconnects, traffic still leaves outside the VPN: there is no kill switch.
  - **OpenVPN profiles:** `proto tcp` (also `tcp4` and `tcp6`) is accepted as the TCP client it means; `auth SHA384`/`SHA512` and the `redirect-gateway` flags `ipv6`, `bypass-dhcp` and `block-local` are kept instead of being replaced; a private key that starts with an `EC PARAMETERS` block is accepted.
  - **OpenVPN start failures** left the plaintext profile, with its private key, and the management password in the service's private folder until a later connection or a restart. They are removed at once.
  - **Network cleanup:** if the tunnel worker could not confirm its cleanup while a connection attempt was being stopped, the next connection went ahead anyway. It is now blocked with `cleanup_unverified`, like other cleanup failures.
  - **Repeated connect:** `ghostlink connect` or the agent tool `vpn_connect` for the server already in use fetched dynamic keys and checked the profile again, and could report an error while the tunnel stayed up.
  - **Autoconnect at startup:** a refused attempt (for example a dynamic key whose server could not be reached before the network was up) showed a plain "Disconnected". It now shows `autoconnect_failed`, and the service log names the reason.
  - **Linux full tunnel:** a WireGuard or AmneziaWG profile whose AllowedIPs cover every public IPv4 address in pieces (`0.0.0.0/1, 128.0.0.0/1`, or an "exclude private IPs" list) counted as split and passed the `--allow-full-tunnel` safeguard for SSH access.
  - **Keys:** a Ghostlink `ss://` key whose name was longer than 80 characters could not be added; names are now cut to 80 characters, for every key format. A dynamic key ending in a bare `#` is accepted, and a dynamic key is no longer fetched from a 6to4 or Teredo address, which can hide a private IPv4 address.
  - **Split tunneling:** full mode no longer turns on process lookups for apps kept from an earlier mode.
- **CLI and the local service.**
  - **Agent tokens:** `ghostlink agent revoke` with a name that has no grant (for example in different capitals) reported success and left the real grant working. `agent grant` into an existing token file used to replace the grant and leave the saved token invalid.
  - **CLI:** `server keys create --output FILE` checks `FILE.conf` before the key is created; `--stdin` and `--key-stdin` respect `--timeout`; commands that save a file refuse an answer without the expected content; `ghostlink key --help` lists every key format.
  - **Service:** a failed IPC connection no longer stops the service and its tunnel; a change that would make the saved state too large to load at the next start is refused; two servers added at the same time cannot pass the 32-server limit; `ghostlink info` lists every engine; import answers say whether the server became the default; a re-keyed managed server is reported as `server_identity_mismatch` also while other calls run.
  - **Local API:** requests that add fields to actions without fields (for example `{"type":"status","x":1}`) are refused, as documented.
- **Packages and releases.**
  - **Windows owner:** installing a newer version with `GHOSTLINK_OWNER_SID` now changes who may control the Ghostlink service; the installer kept the previous owner whatever was given.
  - **Linux service after an upgrade:** upgrading the `ghostlink` package no longer turns `ghostlinkd` back on after you disabled it.
  - **RPM upgrades** of the client or the mesh agent no longer leave `ghostlinkd` or the agent stopped until the next reboot.
  - **Owner on Linux:** an owner written as `GHOSTLINK_OWNER_UID="1000"`, with spaces around `=` or with a Windows line ending, is kept; it was replaced by the user who ran sudo.
  - **Release checksums:** `SHA256SUMS.txt` lists every file of a release, also after the workflow runs again, and a published release is never changed by the workflow. A draft is made only after the Windows and Linux x64 jobs (builds, package tests and IPsec interop) and the desktop, local engine and web UI checks passed; the mesh end-to-end test is not one of them.
  - **Builds:** license notices of dependency versions no longer used are gone; the Windows tunnel worker is built with `CGO_ENABLED=0`, as the corresponding-source instructions say; files in the Linux `.tar.gz` no longer keep group-write permission.
- **Earlier server paths (the offline Outline-compatible proxy, OpenVPN PKI and playbooks).**
  - **Offline proxy, destinations:** a key could reach the server's loopback services, its private network and the cloud metadata endpoint through the proxy. The generated configuration now blocks the same loopback, private, CGNAT, link-local (cloud metadata) and multicast ranges as the Ghostlink server, but of the server's own addresses only those that keys give as an IP address: with a DNS name, as in the guide's example, or through another of the host's addresses, such as its IPv6 address, a key can still reach the host's own services through the proxy. Run `provision.py render` and deploy the new `config.json`.
  - **Offline proxy, IPv6 and errors:** new setups listen on IPv4 and IPv6; a failed `add` no longer leaves a key file that blocks the name; errors say what went wrong; on Windows, a folder other accounts can open is refused.
  - **OpenVPN CRL:** every CRL expired after 30 days, and the OpenVPN server then refused every client. CRLs now last 10 years; on a server set up earlier, run `pki.py crl`, make a new bundle and deploy it once.
  - **OpenVPN PKI:** a mistyped passphrase or a missing OpenVPN during `server` left files that blocked every retry; renewing the server certificate keeps the tls-crypt key; on Windows the PKI folder, profiles and bundles are private to your account, except on drives that keep no permissions (FAT or exFAT, as on many USB sticks).
  - **Playbooks:** the Outline playbook extracts sing-box as root-owned files; both restart a service when only its unit file changed; the OpenVPN playbook's rules drop client-to-client traffic and traffic to private ranges and cloud metadata.
  - **Terraform draft:** the instance metadata hop limit is pinned to 1.
- **Documentation and tests.**
  - **Secrets on the server:** the IPsec settings file `desired.json` holds XAuth passwords, the group key and the server's private key, so it is a secret. Profiles install the server's CA as a root certificate without name constraints; protect `state.json` accordingly.
  - **Known limit:** WireGuard and AmneziaWG profiles that route only some ranges, such as a home LAN, cannot pass the connection health check and fail after the connection timeout. Keys the Ghostlink server issues route everything and are not affected.
  - **CI:** on Windows, the process tests' step checked only its last command, so failures were hidden; it now checks every command. A test that made an expired certificate failed with OpenSSL 3.4 and later. Many smoke checks written as `a && b` ignored a failing `a`; each part now fails the check on its own. The offline proxy is tested against sing-box.
  - **Tests on Windows:** the server's end-to-end test could pick a port that Windows reserves for IPv4 only, and then failed to start Shadowsocks. The port check now also tries the IPv4 wildcard. In tests it checks only the loopback address they listen on, so Windows Defender Firewall no longer asks about every test run.

### Changed

What behaves differently after an upgrade:

- **Online state:** open connections no longer keep a client online; it has to send something at least once a minute. The WireGuard and AmneziaWG keys the server issues send a keepalive every 25 s, and an IKEv2/IPsec session counts while it is up, but Shadowsocks and VLESS have no keepalive: a client on them that is connected but sends nothing for a minute shows as Idle, so a server moved from Outline may show fewer clients online than before. This applies to the app, the dashboard, `ghostlink-server top` and `GET /live`. In the Clients view, "Last handshake" is now "Last seen".
- **WireGuard and AmneziaWG NAT:** each UDP destination now gets its own session on the server, so calls and games see a stricter (symmetric) NAT on these two protocols. A later UDP packet to a blocked address is refused, and one to another DNS server is answered by the server's own resolver, like any DNS query.
- **Shadowsocks and VLESS UDP:** a later packet in a UDP session to a blocked address or to another DNS server (port 53) is dropped.
- **WireGuard and AmneziaWG on this device:** connections that the far side of the tunnel opens to this device (the server, or another client of a server that forwards between clients) are refused. In "only" mode or with the LAN kept direct they used to reach the device's own services, for example SSH over the VPN, and its LAN.
- **Host addresses:** the server reads the host's addresses every 30 s and restarts the VPN engine when a public one appears or goes away, which briefly disconnects users. Addresses in 100.64.0.0/10 count, the mesh's default 100.96.0.0/16 included, so this happens when the server's own mesh node joins or leaves (and can happen when `ghostlink-mesh` restarts), and when the host gets a new temporary IPv6 address.
- **Mesh forwarding needs consent:** a node made a relay without `--relay`, `--advertise-routes` or `allow-forwarding` stops forwarding after the upgrade until its operator runs `sudo ghostlink-mesh allow-forwarding && sudo systemctl restart ghostlink-mesh`.
- **Stricter commands:** server commands with options refuse words they do not take, and `user enable|disable|reset|remove` take one name; `ghostlink agent revoke` of an unknown name exits with an error; `ghostlink agent grant` refuses an existing token file.
- **Linux full tunnel:** WireGuard and AmneziaWG profiles that cover every public IPv4 address in pieces need `--allow-full-tunnel`, like other full-tunnel profiles.
- **OpenVPN:** `auth SHA384`/`SHA512` and `redirect-gateway ipv6|bypass-dhcp|block-local` are now honoured, so a profile that only worked because SHA256 was forced may now fail against its server.
- **IKEv2/IPsec profiles:** the identifier of a profile changes once, so a device that installs a refreshed profile keeps the old one too; remove it once.
- **Upgrades:** `setup` stops the server cleanly before it changes the state, so an upgrade takes a few seconds longer.
- **Logs and history:** the VPN engine's own log is off, and the packaged server has no setting to turn it on: only a server started by hand with `ghostlink-server serve --log-level warn` (or `error`, `info`, `debug`) logs it. The history size limit is 20,000,000 bytes by default, so a file between that and 20 MiB is trimmed at its next save.

## [0.8.0] - 2026-11-08

### Added

- **Speed limits per client.** One cap per client in bytes per second (for example 2 MB/s), for download and upload alike, shared by all of the client's keys and devices.
  - **Default for everyone:** an optional server default applies to every client without a limit of its own. A client can also have **no limit**, whatever the default.
  - **Live:** a change applies within a second to open connections, with no engine restart and nobody disconnected.
  - **Every protocol:** Shadowsocks, VLESS, WireGuard and AmneziaWG are paced in the server's relay loop, a token bucket per client and direction. IKEv2/IPsec sessions are policed by the IPsec component's firewall (`hashlimit` rules on each session's address, shared by a client's sessions).
  - **Everywhere you manage the server:**
    - the client's Settings, New client and Server settings in the app and the dashboard, plus a chip on client cards and a column in the list;
    - `sudo ghostlink-server user speed NAME 2MB|none|default`, `user add --speed`, `set --speed-limit` and a SPEED column in `users`;
    - `ghostlink server users add|update --speed-limit MB/s|none|default` and `ghostlink server set --default-speed-limit MB/s|none`;
    - the API: `speed_limit_bps` and `effective_speed_limit_bps` on users, `default_speed_limit_bps` on the server.
- **Move from Outline.** `install-server.sh --migrate-outline` (or `sudo ghostlink-server migrate-outline`) takes over an Outline server on the same machine. Guide: [docs/deployment/migrate-from-outline.md](docs/deployment/migrate-from-outline.md).
  - **Clients:** every access key becomes a client with the same password, port and cipher, so the `ss://` keys people already use keep working. Names, data limits (per key or Outline's default), paused keys, the server's name and its address come along.
  - **Ports:** keys on other ports than the main one keep theirs, each extra port with its own Shadowsocks listener. Ghostlink's VLESS, WireGuard and AmneziaWG ports move out of the way if they clash. Keys that cannot be kept (ports below 1024, a port the management API, dashboard, mesh or IKEv2/IPsec DNS listener uses, a cipher mix on one port) get a new key, and the report lists them.
  - **Check first:** `--check` shows what would happen, without a password, while Outline keeps running.
  - **Atomic, with a way back:** the import is one change. If it fails or is interrupted, Outline is put back as it was. When it works, Outline is stopped and kept from restarting, its files stay as a backup, and the rollback command is printed.
  - **API:** `POST /import/outline` with Outline's two files and `dry_run`; `GET /server` reports `shadowsocks_extra_ports`.
  - **Inside the container:** `ghostlink-server admin import-outline --dir DIR [--check]` imports two files from a directory the server can read; `migrate-outline` runs it for you.

### Changed

- **Speeds are in bytes per second everywhere** (B/s, KB/s, MB/s, GB/s, decimal like data sizes), including live monitoring in the app, the dashboard, the Island and `top`. They were shown in bits per second before. The API's `*_bps` fields were already bytes per second.
- The users table of `sudo ghostlink-server users` has a SPEED column, and `settings` shows the default speed limit and any extra Shadowsocks ports.
- The installer lists the extra Shadowsocks ports of keys imported from Outline among the ports to allow.
- `--add-swap` is listed in the server guide's installer options.

## [0.7.0] - 2026-11-07

### Added

- **A new look: frosted glass.** The server dashboard and the desktop app are rebuilt on one component library: React, TypeScript, Tailwind CSS and Lucide icons, built with Vite (`ui/`).
  - **Materials:** frosted, translucent surfaces with crisp edges, generous rounded corners and pill controls, over three slow, faint glass waves.
  - **Waves:** the background control sets them to Subtle, Calm or Still, and they are still when the system asks for reduced motion.
  - **Finishes:** three of them, Obsidian, Titanium and Daylight.
  - **Type:** labels in sentence case; a monospace face only for addresses, keys and ports; steady tabular figures for every live number.
  - **Fonts:** Plus Jakarta Sans and JetBrains Mono, both self-hosted, so the pages load nothing from outside.
- **Dashboard and the app's "Servers I run":** the same views, with the same features as before plus:
  - **Live capsule:** a floating navigation bar with a Dynamic Island-style capsule that shows live state and opens a switch for each protocol.
  - **Overview:** a bento of KPIs (active tunnels, live throughput, uptime, address pool), plus a throughput chart for the last 60 seconds, hour or 24 hours.
  - **Clients:** cards or a list, with search, Online/Idle/Paused filters and an access switch. Each shows its tunnel IP, last endpoint, last handshake and live speed, with quick QR, .conf, copy and revoke actions.
  - **New client:** shows the next free tunnel address before creating; then the server issues the key and the sheet shows the QR code and the .conf at once.
  - **Network:** protocols with switches and ports, the address pools, the rules for everyone and the mesh map, in one place.
- **Full window:** both apps use the whole window. On wide screens, client and server cards go up to five a row and the protocol tiles to one row. The desktop app has a full-screen mode: F11 or the button in the navigation bar, with Escape to leave.
- **Desktop app:** My servers has a connection hero with a large power control, live speed and server cards with a menu. The Island shows the connection and switches servers. Settings now has the finish and motion controls.
- **API:**
  - `GET /server` reports `address_pools` (WireGuard and AmneziaWG subnets: in use, capacity, next address);
  - key summaries carry their tunnel `address`;
  - `/live` adds an hour of per-minute averages (`minutes`).

### Changed

- The dashboard (`internal/server/dashboard`) and the desktop UI (`apps/desktop/ui`) are now build output of `ui/`, committed so the Go module and the Tauri app build without Node. The new **Web UI** workflow rebuilds both and fails if the committed files differ. A Go test checks the embedded dashboard is complete and CSP-safe.
- The desktop app maps the admin views' requests onto the local service's typed operations through one table. A test checks the table against the Rust contract, and paths that are not plain are refused.
- The desktop shell can save `.conf` files to Downloads.
- The worker corresponding-source zip includes the UI source (`web-ui/`), and the license inventory and server image include the notices of the bundled npm packages and fonts.

## [0.6.0] - 2026-11-06

### Added

- **Ghostlink mesh: a private network between your Linux servers.** Every server you add gets a mesh address (`100.96.0.0/16` by default) and reaches the others over kernel WireGuard, across clouds, data centres and home networks. Guide: [docs/deployment/mesh.md](docs/deployment/mesh.md).
  - **Coordinator:** the Ghostlink server hands out addresses, keys, paths and access rules on its own TLS 1.3 port (pinned like the management API). Nodes get changes within about a second.
  - **Agent:** the new `ghostlink-mesh` package (.deb/.rpm, x64 and arm64) runs a hardened systemd service. It sets up `glmesh0`, firewall chains and `<node>.mesh` names, and reports handshakes, traffic and latency. The node's private key never leaves it.
  - **Direct links, relay fallback:** pairs connect directly; a pair that can't (for example two nodes behind NAT) goes through a relay node, and direct is retried later.
  - **Tag-based access rules** (`tag:web → tag:db tcp 5432`), enforced by each receiving node. A new mesh allows everything until the first rule.
  - **Shared subnets (site-to-site):** a node offers a subnet behind it (`--advertise-routes`), and the administrator approves it. It is masqueraded by default.
  - **Easy setup:**
    - `install-server.sh --mesh` makes the server the coordinator and its first node (the relay).
    - **Add node** in the app gives a one-line command for each new server: `install-mesh.sh --join 'glmesh1:…'`. Invites are single-use and expire after 24 hours by default; they can carry tags, a relay role or an approval step.
  - **Live map** in the app (**Servers I run → Manage → Mesh**) and the dashboard (**Mesh** view):
    - it shows nodes and links: direct, through the relay, or down, with latency and traffic;
    - nodes can be dragged; node details let you approve, tag, share subnets, set the relay, disable or remove;
    - it also has Add node and an access-rules editor.
  - Everywhere you manage the server: `sudo ghostlink-server mesh …` (including `join-here`), `ghostlink server mesh …` in the CLI, and the dashboard. AI agents cannot use mesh operations.
  - Linux servers only for now; Windows servers and the Ghostlink app on Windows as a mesh node will follow.
- **One-command server install:** `curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash`.
  - It picks the `.deb` or `.rpm` for the distribution and CPU, installs Docker if needed and verifies the package against the release checksums.
  - It prints the management key and the ports to open.
  - Options: `--hostname`, `--ipsec`, `--mesh`, `--open-firewall` (only for an active ufw or firewalld), `--version`, `--package` and `--mesh-package` for offline installs.
  - Running it again upgrades.
  - On servers with under 1 GB of memory and swap (for example the smallest AWS Lightsail plans) it stops before installing, because the kernel would kill the installation; `--add-swap` adds a 1 GB swap file. It also finishes an installation that was interrupted.

### Fixed

- `sudo ghostlink-server --json users` (and the other admin commands) failed with a usage message, although the guide documents it; the host command now passes `--json` through.
- A test of the engine's listener-ownership check could fail at random on Linux, when the PID it used as "another process" was one of the test's own threads.

## [0.5.0] - 2026-11-06

### Added

- **iPhone, iPad and Mac with no app:** the server can serve Apple's built-in VPN types and hand out configuration profiles (`.mobileconfig`):
  - **IKEv2** (`NEVPNProtocolIKEv2`) with username and password (EAP-MSCHAPv2) or a certificate;
  - **IPsec** (`NEVPNProtocolIPSec`, IKEv1) with a certificate or a shared group key, plus an XAuth password. Certificates are the default; group keys come with a warning.
  - Per key: server address, remote identifier and local identifier.
  - Profiles install in Settings and keep credentials in the Keychain. They can leave out the certificate password (`--prompt-password`) or connect on demand.
- **IPsec component** (`sudo ghostlink-server ipsec enable|disable|status|logs`): strongSwan 6 in a second container shipped inside the server package.
  - **Isolation:** the main server stays unprivileged and writes validated settings for `ghostlink-ipsec-agent`, which runs with only the network capabilities IPsec needs and applies them to strongSwan, its own firewall chains and a gateway interface.
  - **Limits:** data limits, usage, live speed, online state and "connected from" work for IKEv2/IPsec users. Disabled, removed and over-limit users are cut off within seconds, and their certificates are put on hold or revoked.
  - **Rules:** blocked addresses and ports, mail blocking, always-blocked internal ranges and DNS-based site blocks apply.
- **Internal CA** per server (RSA 3072) with automatic server-certificate renewal and a CRL.
- **Everywhere you manage the server:**
  - IKEv2/IPsec keys and profile saving in the app (**Save iPhone/Mac profile**), the CLI (`ghostlink server keys create --protocol ikev2 …`, `keys profile`), the dashboard and server commands (`key add NAME ikev2 …`, `profile NAME ID --output FILE`);
  - `set --rotate-ipsec-psk` everywhere;
  - connection kits explain how to install profiles.
- **Corresponding source** for the IPsec component's GPL packages (Alpine recipes and upstream sources) is published with each release.

### Fixed

- A QR-decoding test could fail at random on synthetic images. It now falls back to reading the clean bitmap directly.
- The dependency notice inventory missed Go modules only the Linux server links (netlink, nftables, nfqueue, dbus); it is now generated for Linux too, and the server images carry those notices.

## [0.4.0] - 2026-11-06

### Added

- **Server monitoring:**
  - live speed per user, open connections, who is online, and the last 2 minutes of server traffic;
  - server health: CPU, memory, disk, network, uptime;
  - traffic types (Web, QUIC/video, DNS, calls, BitTorrent, SSH, remote desktop, other) and protocols used, per user and in total;
  - usage history: hourly for 7 days and daily for 90;
  - the addresses users connected from: Shadowsocks/VLESS sources, and WireGuard/AmneziaWG endpoints from the engine.
- **Top services per user**, opt-in and off by default:
  - totals per service (YouTube, Netflix, TikTok…) or site;
  - kept 30 days, never page addresses or times;
  - turning it off deletes them.
- **Automatic rotation of recorded traffic:**
  - age-based retention (configurable);
  - a hard size limit for the history file (default 20 MB; oldest detail goes first);
  - a low-disk guard that pauses detailed recording below 500 MB or 5 % free.
- **Manage on the server:** `sudo ghostlink-server users | user | key | keys | kit | rules | usage | stats | clients | top | settings | set | site-stats | dashboard`.
  - These go through the server's own API on loopback.
  - Users can be named.
  - `key add` prints a QR code in the terminal, and `top` shows live speeds.
- **Web dashboard** on its own port, never 443:
  - **Private by default:** loopback only, reached through an SSH tunnel.
  - **Opt-in public mode:** HTTPS on that port.
  - **Sign-in:** a login link with the token after `#`, then an HttpOnly SameSite=Strict session, a CSRF header, a Host check against DNS rebinding, and throttling.
  - **Pages:** overview, users, keys with QR codes, statistics, rules and settings.
- **QR codes** for every key, as SVG for the app and dashboard or text for terminals. WireGuard/AmneziaWG keys offer both `.conf` (WireGuard/AmneziaWG apps) and `vpn://` (AmneziaVPN).
- **Connection kit:** one self-contained HTML page per user with all of their keys, QR codes and per-app instructions (Outline, WireGuard, AmneziaWG/AmneziaVPN, v2rayNG/Hiddify/Streisand/Shadowrocket, Ghostlink).
- **Ghostlink app:**
  - a live panel on each server page;
  - live speed and online state per user;
  - a statistics dialog per user and for the whole server;
  - QR codes and **Save connection kit** (saved to your Downloads folder, never overwriting);
  - monitoring settings.
- **CLI:** `ghostlink server live | stats | clients`, `server keys qr | kit`, and `server set --site-stats on|off --history-days --site-days --history-max-mb`.

### Changed

- User names on a server are now unique (ignoring case), so they can address users.
- The service reuses one pinned connection per managed server, so live updates don't repeat the TLS handshake.

## [0.3.1] - 2026-11-06

### Fixed

- **Windows: the app and CLI could not reach the installed service.**
  - **Symptom:** after installing the MSI, every request failed with "Cannot reach the authorized local Ghostlink service".
  - **Cause:** before talking to the service, the client checks who is serving its pipe, so a fake service cannot receive your keys. It did that by opening the service process's token, and Windows does not let a standard user open a SYSTEM process's token.
  - **Fix:** the client now checks the pipe's owner, which any client may read. It must be SYSTEM, Administrators (the owner a SYSTEM service gives its objects) or your own account, and an ordinary process cannot fake any of these.
  - **Testing:** development tests ran the service as the same user, which hid this.
- **Windows: the Start-menu shortcut had no icon.** Windows Installer shows an icon on these shortcuts only when the icon's ID ends in `.ico`.
- **Windows: no desktop shortcut.** The MSI now adds a desktop shortcut too.

## [0.3.0] - 2026-11-06

### Added

- **Ghostlink server**, Outline-style.
  - **What it runs:** AmneziaWG (2.0), WireGuard, VLESS-REALITY and Outline-compatible Shadowsocks in one hardened Docker container.
  - **Packages:** `ghostlink-server` `.deb` and `.rpm` for x64 and arm64, with the image inside, so no registry is needed.
  - **First install:** prints a management key.
  - **Upgrades:** keep users, keys and rules.
  - **Admin command:** `ghostlink-server` on the host (`setup`, `show-key`, `status`, `logs`, `restart`, `stop`, `remove`).
- **Users and keys:**
  - users with data limits and usage counters;
  - keys per protocol: `ss://`, `vless://`, `.conf`, and Amnezia-format `vpn://` for WireGuard and AmneziaWG;
  - disable a user, reset usage.
- **Server traffic rules:**
  - block sites, IP ranges, ports, BitTorrent and outgoing mail, for everyone or per user;
  - exempt a user from the rules for everyone;
  - always-on blocks for loopback, private, link-local, CGNAT, multicast and cloud-metadata destinations, the API port and the server's own IP;
  - all DNS is answered by the server, so site blocks hold.
- **Manage servers from Ghostlink:**
  - **App:** a new **Servers I run** view with users, keys (copy, copy `.conf`, use on this device), rules, usage and server settings;
  - **CLI:** `ghostlink server add|list|remove|info|set|users|keys|rules|usage|install-help`;
  - **Security:** the management key is sealed in the service, and the certificate is pinned inside the TLS handshake (TLS 1.3, rustls);
  - **While connected:** management calls go around the tunnel and never block the service.
- Process test with a real local `ghostlink-server` covering every management action, plus server tests with unmodified clients for all four protocols.
- Release CI builds the server image natively on x64 and arm64. It installs the server `.deb` with Docker, then checks the certificate pin, the API, key creation, container hardening, upgrade and purge.

### Fixed

- **AmneziaWG crash on disconnect (Linux CI, any OS):**
  - **What happened:** a peer could write one last packet into the userspace network stack after it was closed, crashing the worker during a graceful stop.
  - **Server impact:** the server would have hit the same race on every configuration change.
  - **Fix:** the TUN adapter now refuses writes once closing starts, and waits for writes already in flight.
- **Corresponding source:** the zip now contains the whole Go module (it lacked `internal/awg` in v0.2.0 and v0.2.1, so it could not build). The packaging script builds from the staged copy before zipping, and uses `/` in zip paths.
- **Debian unit path:** the client `.deb` installs its systemd unit under `/lib/systemd/system`, so `apt purge` no longer warns about `/usr/lib/systemd/system`.

### Changed

- The worker and server share one version constant (`core/outline-worker/internal/version`), which the release check reads.

## [0.2.1] - 2026-11-06

### Added

- **Linux `.deb` and `.rpm` packages** (x64 and arm64), alongside the `.tar.gz`:
  - they install to `/usr/bin` and `/usr/lib/ghostlink`, with the systemd unit in `/usr/lib/systemd/system`;
  - the installer fills in `GHOSTLINK_OWNER_UID` from the user who ran `sudo` and starts the service;
  - upgrades keep your settings;
  - removing the package stops the service, and `apt purge` also deletes saved servers and keys.
- **`GHOSTLINK_FLAGS`** in `/etc/ghostlink/ghostlinkd.env` passes extra service flags. Set `GHOSTLINK_FLAGS=--allow-full-tunnel` to enable full-tunnel routing on Linux without a systemd override.
- **Release smoke test:** CI installs the `.deb` on Ubuntu (x64 and arm64), checks the service runs and answers `ghostlink status`/`doctor`, then purges it. It also inspects the `.rpm`.

### Fixed

- **Linux:** the tunnel worker now ignores `SIGPIPE`. Previously, if the service's end of its status pipe had closed (for example after a service crash), the worker's next status write could kill it before its graceful shutdown finished, which could leave routes behind.
- The real-engine tests keep draining worker output, wait for the tunnel to come up before checking split-tunnel routing, and run one at a time in CI. They failed on GitHub's Linux runners for v0.2.0.

### Documentation

- Rewrote the README.
- Added this changelog and a protocol design note.
- GitHub release notes now include the version's changelog section.

## [0.2.0] - 2026-11-06

### Added

- **WireGuard** and **AmneziaWG** connections (legacy and 2.0 obfuscation: junk packets, S1–S4, header ranges, I1–I5, header protection), from `.conf` files or Amnezia `vpn://` keys.
- **VLESS with REALITY** (and TLS), including XTLS Vision, from `vless://` links or Amnezia XRay keys.
- **Amnezia `vpn://` import** for AmneziaWG, WireGuard and XRay connection keys.
- **Split tunneling**: bypass or "only these" by site, IP range or app, plus a keep-LAN-direct option. Set globally or per server, in the app (Settings and each server's menu) or with `ghostlink split show|set|clear`.
- Desktop app: **Import a file…** for `.conf` files, protocol badges on server cards, and a calm style for success messages.
- Interop tests against upstream amneziawg-go, a stock WireGuard client and a sing-box REALITY server, plus end-to-end traffic tests through the real worker.

### Changed

- The tunnel worker identifies as `Ghostlink tunnel worker 0.2.0; sing-box 1.14.4; amneziawg-go 3.1.20260828` and builds with `with_gvisor,with_utls,with_wireguard`.
- The connection health check is pinned to the tunnel and sniffing runs first, so DNS hijacking and site rules see protocol and site names.

### Security

- `.conf` script hooks (`PreUp`/`PostUp`/`PreDown`/`PostDown`), `Table`, `FwMark`, unknown keys and `AdvancedSecurity = on` are rejected.
- Plaintext VLESS, insecure TLS and `xhttp`/mKCP transports are refused.
- Amnezia "full access" keys that carry the server's SSH login are refused, and the credential is never stored or echoed.
- `vpn://` decompression is capped at 1 MiB.
- Updated `github.com/andybalholm/brotli` (1.2.7) and `github.com/klauspost/compress` (1.20.2) after `govulncheck` found advisories newly reachable through uTLS.

### Fixed

- The release version check pointed at a renamed source file and would have failed the release build.

## [0.1.0] - 2026-11-06

### Added

- Ghostlink (renamed from MyVPN): new ghost icon, binaries `ghostlink`, `ghostlinkd`, `ghostlink-mcp` and `ghostlink-tunnel`, `GHOSTLINK_*` variables and a new MSI upgrade code.
- Release workflow: Windows x64 MSI and portable ZIP, Linux x64/arm64 archives, the GPL worker source bundle, checksums and a draft pre-release on `v*` tags.

### Fixed

- A failed autoconnect at start-up no longer stops the service.
- The Linux service unit gains `CAP_CHOWN`.
- Engine events no longer stall the service's main loop.
- OpenVPN forced kills are flagged as unverified cleanup.
- Crash leftovers are removed at start-up.
- Imports refuse to overwrite an existing server without `--replace`.
- Access-key fingerprints are salted.
- Build-script fixes for Git Bash (`link.exe`) and paths with spaces.

[Unreleased]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/winyannainghtut/GHOSTLINK/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/winyannainghtut/GHOSTLINK/releases/tag/v0.1.0
