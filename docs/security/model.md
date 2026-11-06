# Security model and current limits

The local OS account is the main trust boundary. Windows named pipes use an explicit protected DACL and reject remote clients; clients use identification-only impersonation QoS and verify who created the pipe from its owner. The owner must be SYSTEM, BUILTIN\Administrators (the default owner for objects a SYSTEM service creates) or the client's own account. An unprivileged process cannot create an object owned by any of these, so a squatted pipe is refused. The previous check opened the server process token, which standard users may not do for a SYSTEM service. Linux sockets restrict permissions and validate peer credentials. One configured owner can manage this personal VPN. Agent tokens constrain the MCP path; they do not isolate a hostile process already running as the same trusted user.

Privileged code accepts typed operations. Engine executable paths and privilege policy are administrator configuration, not IPC fields. OpenVPN input is reconstructed with a strict allowlist. Outline input accepts specific access-key formats and modern AEAD ciphers; it cannot inject shell arguments, plugins or arbitrary sing-box configuration. Dynamic key fetches require verified public HTTPS destinations, pin DNS resolution, reject redirects and bound response size.

WireGuard and AmneziaWG `.conf` files are parsed with an allowlist: script hooks (`PreUp`, `PostUp`, `PreDown`, `PostDown`), `Table`, `FwMark`, `SaveConfig`, unknown keys and malformed keys are rejected, and obfuscation values are re-checked by the worker so they cannot inject other settings. `vless://` links must use REALITY or TLS; plaintext VLESS and insecure TLS are refused. Split tunneling is owner-only (agent tokens cannot read or change it). Bypass and "only" rules deliberately send some traffic outside the tunnel; the connection health probe is always pinned to the tunnel so a broken tunnel can never be reported as connected. Site rules depend on observing names (SNI, HTTP Host, QUIC, DNS) and are not a privacy guarantee. Amnezia `vpn://` keys are decompressed with a 1 MiB cap, and "full access" keys that carry the server's SSH login are refused outright, without storing or echoing the credential.

Windows secrets are encrypted with user-scoped DPAPI under the daemon identity, in ACL-protected storage. A service runs as SYSTEM; development mode uses the developer account. Private directories reject symlinks/reparse points and untrusted owners. Linux uses root-private mode-0600 files; an OS encrypted vault for Linux credentials is not implemented. The OpenVPN backend rejects username/password and encrypted-private-key workflows until that storage path exists.

The managed tunnel worker links upstream protocol and cryptographic libraries without modification. It receives only generated private configuration, emits fixed JSON events instead of raw engine logs, verifies interface existence, and calls the upstream graceful close on a stop message or parent-pipe EOF. The Rust daemon verifies OS process ownership of loopback proxy/controller listeners before sending random per-session local credentials. Configuration is removed on startup failure, cancellation and shutdown. A forced close or reported cleanup failure blocks another connection and returns `cleanup_unverified`.

These mechanisms reduce specific failures; they do not certify the platform definition of done. Full routing, DNS/IPv6 leaks, crash recovery, network changes and installed service shutdown still require privileged network tests. A persistent kill switch, approval queue, signed update channel and verified mobile implementation are not present. IPv6 is currently routed to the Outline TUN and rejected by policy; IPv6 server transport and split/full tunnel behavior need real network verification.

**Managed servers (client side).** A management key gives full control of a Ghostlink server.
- **Storage and visibility:** it is accepted only by the owner (never agents), sealed like access keys, and never returned in lists, status or audit entries. The CLI reads it from a file or stdin only.
- **Pinning:** the service connects with rustls, TLS 1.3 only. The certificate is checked against `certSha256` inside the handshake, and the handshake signature is still verified, so a peer that only copied the public certificate cannot pass. A test confirms that with a wrong pin the server receives no request bytes, which means the secret path is never sent.
- **Request shape:** requests are typed operations mapped to fixed paths with decimal IDs. There are no redirects or proxies, answers are capped at 1 MiB, and calls time out after 25 s.
- **Routing:** while a VPN connection is up, the management APIs of servers this device administers are routed around the tunnel. The Ghostlink server refuses its own API port to VPN users.
- **Desktop views (v0.7.0):** the app's "Servers I run" pages share the dashboard's views, but reach the server only through the local service's typed operations. `ui/desktop/src/routes.ts` is the whole mapping: anything else, and any path with dot segments, empty segments, escapes or backslashes, is refused in the app. The service then validates each operation and builds fixed paths with decimal IDs, as before.

**Ghostlink server.**
- **Container:** a container with no capabilities, a read-only root and `no-new-privileges`, running as a dedicated unprivileged host account that owns only `/var/lib/ghostlink-server` (mode 0700).
- **Networking:** it uses host networking like Outline. So every user's traffic first passes always-on blocks for loopback, private, link-local, CGNAT, metadata and multicast ranges, the API port and the server's own IP address. Names are resolved on the server before those blocks apply.
- **Management API:** TLS 1.3 only, with a self-signed P-256 certificate. All paths sit under a random 128-bit secret prefix compared in constant time. An address is refused after 20 wrong guesses in a minute, and request bodies are strictly validated.
- **What the server stores:** the server keeps every user's key material in its state, so keys can be shown again. Protect the host and its backups accordingly.
- **Logs and first install:** logs contain warnings and errors only, not traffic. On first install the server may contact `api.ipify.org` and `ipv4.icanhazip.com` to learn its public IP; set the hostname yourself to avoid that.

**Server administration and the dashboard.**
- **Server commands:** `sudo ghostlink-server` admin commands run inside the container and use the management API on loopback, with the management key's pin. Only root on the host can run them.
- **Dashboard port:** the dashboard has its own port (not 443, never shared). By default it listens only on 127.0.0.1, so it is reachable only through an SSH tunnel; VPN users cannot reach host loopback.
- **Public mode:** opt-in; HTTPS (TLS 1.3) with the pinned self-signed certificate.
- **Sign-in:**
  - a 128-bit login token, stored in the server state like the management secret and sent after `#` so it is never in a request line;
  - an HttpOnly, SameSite=Strict, in-memory 12-hour session;
  - a required custom header on API calls (CSRF);
  - a Host check against DNS rebinding;
  - throttling after 20 bad tokens per minute;
  - `--reset-token` revokes every session.
- **Page hardening:**
  - a strict CSP (self only; images from blob/data), `frame-ancestors 'none'`, no external resources, and no user data inserted as HTML;
  - since v0.7.0 the page is a React build with self-hosted fonts, and a test checks the embedded build has one script and one stylesheet, flat names, no inline code, no `eval` and no outside URLs.

**IKEv2/IPsec for iPhone, iPad and Mac (optional component).**
- **Privilege split:**
  - The main server never gains privileges. It writes a declarative settings file (`ipsec/desired.json`, mode 0640, readable only by its own group) and reads back a status file.
  - `ghostlink-ipsec-agent` runs in a second container as root in that group with only `NET_ADMIN`, `NET_RAW` and `NET_BIND_SERVICE`, a read-only root, `no-new-privileges` and only the `ipsec` directory mounted.
  - The agent re-validates every field: identities, CIDRs, ports, NT hashes, PEM types, version. Algorithms are fixed in its code, and settings never reach a shell. It changes only its own `GHOSTLINK-IPSEC-*` chains and the `glipsec0` interface, and removes them when it stops.
  - A compromised server process can therefore change who may connect, but cannot add arbitrary firewall rules or strongSwan options.
- **Credentials:**
  - EAP-MSCHAPv2 passwords reach strongSwan only as NT hashes. An NT hash is still equivalent to the password for MSCHAPv2, so `desired.json` is a secret, like the server state.
  - XAuth passwords and the IPsec group key are passed as they are, because strongSwan needs them.
  - The CA's private key stays in the server state and is never given to the agent.
- **Certificates:**
  - a private RSA-3072 CA (20 years), with server certificates of 825 days carrying the IKE EKU, renewed automatically, and client certificates of 5 years;
  - removed keys are revoked in a CRL that is reissued daily (7-day validity);
  - certificates of disabled or over-limit users are put on hold in the same CRL, and strongSwan refuses them;
  - the agent also ends established sessions whose identity is no longer allowed.
- **Profiles are secrets:**
  - A `.mobileconfig` carries the user's password or a PKCS#12 with an embedded random password. It can be saved without that password (the device then asks for it).
  - Profiles are unsigned: there is no Apple Developer certificate yet, so iOS shows "Unverified".
  - The profile installs the server's CA so the device can check the server certificate. iOS does not trust a profile-installed root for websites unless someone turns that on in Settings → General → About → Certificate Trust Settings, which nobody should do for this CA. Keep its key safe, because anyone holding it could issue VPN server certificates these devices accept.
- **Weak option:** IPsec with a shared group key uses IKEv1 Aggressive Mode. Every holder of the group key can impersonate the server to other PSK users, and a passive observer can attempt offline guessing of the group key. It is off unless a PSK key exists, and the API returns a warning with every such key.
- **Not inspected:** IKEv2/IPsec traffic is forwarded by the kernel. Only the rules for everyone (addresses, ports, SMTP, DNS-based site blocks), the always-blocked ranges and data limits apply. Per-user rules, BitTorrent blocking and traffic classification do not. IPv6 is not tunnelled.

**Mesh of Linux servers (v0.6.0).**
- **Who controls what:** the Ghostlink server coordinates the mesh. It decides each node's address, peers, paths and firewall rules, so whoever holds its management key controls the mesh. It does this from its unprivileged container: it never touches a node's network itself.
- **Coordinator API:** the mesh API has its own TCP port, never reachable by VPN users (refused like the management API). It is TLS 1.3 with the same certificate, which agents pin from the invite, so no CA is trusted. Failed authentication is rate-limited per address, and request bodies are bounded and strictly validated.
- **Credentials:**
  - an invite carries a 128-bit token, single-use and 24-hour by default, stored only as a SHA-256 hash and shown once;
  - joining gives a node a 256-bit secret, also stored as a hash, sent as a bearer token over the pinned connection and compared in constant time;
  - a node's WireGuard private key is generated on the node, kept in `/var/lib/ghostlink-mesh/node.json` (0600, root) and never sent.
  - The CLI writes invites only to new private files (`invite --output`); AI agent tokens cannot use any mesh operation.
- **The agent (`ghostlink-mesh`)** runs as a systemd service limited to `CAP_NET_ADMIN` and `CAP_NET_RAW`, with `ProtectSystem=strict`; it can write only its state directory, `/etc/hosts` and `/run`. It re-validates every configuration before applying any of it:
  - keys, addresses inside the mesh network, routes outside it, endpoints, names and protocols;
  - no two peers may claim overlapping addresses, and no peer may claim the node's own address;
  - nothing reaches a shell.
  - It changes only `glmesh0`, its own `GHOSTLINK-MESH-*` chains (matching only `glmesh0`), routes it tags with its own protocol number, and a marked block in `/etc/hosts`. Stopping or leaving removes all of them.
- **Forwarding needs local consent:** a node forwards traffic, as a relay or for shared subnets, only if its own operator allowed it (`--relay`, `--advertise-routes` or `allow-forwarding`). The coordinator cannot turn a node into a router by itself. Shared subnets need both the node's offer and the administrator's approval.
- **Relays read relayed traffic:** a relay decrypts and re-encrypts traffic between two nodes that cannot connect directly. Use only your own servers as relays. Direct pairs are encrypted end to end between the two nodes.
- **Access rules** are enforced by each receiving node's firewall. Replies to allowed connections always pass, and ping does unless turned off. A compromised node can send anything, but its peers accept only what the rules allow from its mesh address.
- **Not provided:** IPv6 in the mesh, Windows nodes, and NAT hole punching (two nodes behind NAT use the relay). The `/etc/hosts` names are a convenience, not authentication.

**Monitoring data.** The server keeps per-user usage, traffic-type and protocol totals, and the last 20 connecting addresses per user (30 days) on the server only.
- **Top sites/services:** off by default. They are totals per service per day (never URLs or times), kept 30 days, and deleted at once when turned off.
- **Rotation:** age limits, a hard size cap with a documented trimming order, and a low-disk guard that pauses detail recording below 500 MB or 5 % free.
- **Exposure:** the history file is 0600 in the 0700 state directory. Connection addresses identify people's networks: share the dashboard login link and management key only with administrators.

Do not commit state, PKI, access keys, token files or build tools. Keep offline CA backups encrypted and separate from server backups. The optional OpenVPN PKI bundle explicitly excludes CA and client private keys. Update CRLs on the server after revocation and before their expiry.
