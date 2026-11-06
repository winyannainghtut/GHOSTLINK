# Ghostlink server

A self-hosted VPN server in one Docker container, in the style of Outline: installing it prints a **management key**, and whoever holds that key manages the server. You can manage it three ways, with the same features in each:

- the Ghostlink app or CLI (`ghostlink server …`);
- commands on the server itself (`sudo ghostlink-server …`);
- a web dashboard served by the server.

- **Protocols:** AmneziaWG (2.0 obfuscation), WireGuard, VLESS with REALITY, and Outline-compatible Shadowsocks. Each can be turned off or moved to another port.
- **Users and keys:** create users, then issue keys per protocol. A key works in Ghostlink and is meant for other clients too: `ss://` for Outline apps, `vless://` for Xray-based apps, `.conf` for WireGuard/AmneziaWG apps, and an Amnezia-format `vpn://` for AmneziaWG/WireGuard.
- **Traffic rules:** block sites, IP ranges, ports, BitTorrent and outgoing mail, for everyone or one user. A user can be exempted from the rules for everyone.
- **Usage and limits:** per-user data counters and data limits; users who reach their limit are cut off until the limit is raised or the counter is reset.
- **Monitoring:**
  - live speed per user, open connections and who is online;
  - traffic types (web, QUIC video, calls, BitTorrent and so on) and the protocols used;
  - optional top services per user;
  - the addresses users connect from, and server health;
  - history that rotates itself so it never fills the disk.
- **Sharing:** QR codes for every key (phones scan instead of pasting), and a one-page connection kit per user with all their keys and app instructions.
- **Delivery:** a `.deb` or `.rpm` that **contains the container image**. No registry or internet download is needed to install it.

## Requirements

- Linux x64 or arm64 with Docker (Debian/Ubuntu `docker.io` or `docker-ce`, Fedora/RHEL `moby-engine` or `docker-ce`). `podman-docker` may work but is not tested.
- A public IP address or DNS name that clients can reach.
- Firewall or cloud security-group rules for the server's ports (see [Ports](#ports)).

## Install

```sh
sudo apt install ./ghostlink-server_<version>-1_amd64.deb     # or _arm64.deb
sudo dnf install ./ghostlink-server-<version>-1.x86_64.rpm     # or .aarch64.rpm
```

The installer:

1. Starts Docker if it is installed as a systemd service.
2. Creates the `ghostlink-server` system account and `/var/lib/ghostlink-server` (mode 0700, owned by that account).
3. Loads the bundled image (`docker load`) and removes images from older versions of the package.
4. On first install, creates the server: random ports, new keys for every protocol, a self-signed TLS certificate and a random 128-bit API secret.
5. Starts the container and prints the management key:

```json
{"apiUrl":"https://203.0.113.10:23456/Wq9…","certSha256":"3F0A…"}
```

To find the public address on first install, the server asks `https://api.ipify.org` and `https://ipv4.icanhazip.com` for its IP. To use a DNS name, or to avoid those requests, set it yourself:

```sh
sudo GHOSTLINK_SERVER_HOSTNAME=vpn.example.com apt install ./ghostlink-server_<version>-1_amd64.deb
# or, after installing:
sudo ghostlink-server setup --hostname vpn.example.com
```

If setup cannot finish (for example, Docker is not running), the package still installs and tells you to run `sudo ghostlink-server setup`.

## Connect the app

1. Copy the management key into a private file on your computer (or keep it ready to paste).
2. In the Ghostlink app choose **Servers I run → Add server** and paste it, or run:

   ```sh
   ghostlink server add --name home --key-file management-key.json
   ```

Ghostlink checks that the server answers with the pinned certificate, then seals the key in the local service. The key is never shown again, and it is never given to AI agents.

Then add users and keys:

```sh
ghostlink server users add --server home --name Alice --data-limit-gb 50
ghostlink server keys create --server home --user 1 --protocol amneziawg --output alice-awg.txt
ghostlink server keys create --server home --user 1 --protocol vless --import alice-here   # also use it on this device
ghostlink server rules set --server home --block-site ads.example --block-bittorrent --block-smtp
ghostlink server usage --server home
```

In the app, **Servers I run → Manage** has the same actions. **Keys** lets you copy a key or a `.conf`, or **Use on this device**.

## Manage on the server

Everything the app can do also works over SSH on the server. Users can be named instead of numbered, and changes apply live:

```sh
sudo ghostlink-server users                          # users, usage and status
sudo ghostlink-server user add Alice --limit 50GB    # also: user enable|disable|remove|reset|rename|limit|exempt
sudo ghostlink-server key add Alice amneziawg        # prints the key, the .conf and a QR code to scan
sudo ghostlink-server keys Alice [--show]            # key text only with --show; key qr|remove NAME ID
sudo ghostlink-server kit Alice --output alice.html  # one private page with all of Alice's keys, QR codes and app help
sudo ghostlink-server rules set --block-site ads.example --block-bittorrent --block-smtp
sudo ghostlink-server rules set --user Alice --block-port 6881-6889
sudo ghostlink-server usage | stats [Alice] [--range 24h|7d|30d|90d] | clients [Alice]
sudo ghostlink-server top                            # live speed per user; Ctrl+C quits
sudo ghostlink-server settings | set --hostname H --enable P --disable P --port vless=8443 ...
sudo ghostlink-server site-stats on|off              # top services per user (off deletes them)
sudo ghostlink-server dashboard                      # web dashboard: tunnel command and login link
```

These run inside the container (`docker exec`) and call the server's own management API on loopback with the same certificate pin as the app. Only root on the host can use them. Add `--json` after `ghostlink-server` for machine-readable output.

## Web dashboard

The dashboard is a browser page served by the server on **its own port**. That port is never 443, and never shared with the VPN or API ports. It's random by default; choose one with `--port`.

```sh
sudo ghostlink-server dashboard              # prints the SSH tunnel command and your login link
sudo ghostlink-server dashboard --port 8443  # move it to another port (1024-65535, not 443)
sudo ghostlink-server dashboard --reset-token  # new login link; signs everyone out
```

- **Private (default):** it listens only on the server's `127.0.0.1`. On your computer, run the printed `ssh -N -L 8080:127.0.0.1:<port> you@server` and open the printed `http://127.0.0.1:8080/#t=…` link. SSH encrypts the connection, so the browser shows no certificate warning, and nothing is exposed to the internet.
- **Public (opt-in):** `sudo ghostlink-server dashboard --public` serves it over HTTPS (TLS 1.3, the server's self-signed certificate) on that port. The browser warns about the certificate; compare the SHA-256 fingerprint it shows with the one the command prints. Allow the port only from your own address if you can. `--private` switches back.
- **Signing in:**
  - The login link carries the token after `#`, so it is never sent in a request line or kept in server logs.
  - The page exchanges it for a session cookie (HttpOnly, SameSite=Strict, 12 hours).
  - Requests also need a dashboard header (protection against cross-site requests) and must name `127.0.0.1`/`localhost` (or, when public, the server's address) as the host, which stops DNS rebinding.
  - 20 wrong tokens in a minute block that address for the rest of the minute.
- **Pages:**
  - Overview: live traffic chart, online users, server health, today's users, traffic types, protocols, top services.
  - Users: live speed, usage and limits; keys with QR codes, copy and kit download; per-user statistics and rules.
  - Rules for everyone.
  - Settings.

## Monitoring and privacy

What the server records, all of it stored only on the server in `/var/lib/ghostlink-server/history.json` (mode 0600):

| Record | Detail | Kept |
|---|---|---|
| Live | Speed per user (each second), open connections, online state, last activity | In memory, last 2 minutes |
| Usage over time | Bytes up/down per user per hour, and per day | Hourly 7 days; daily 90 days (`set --history-days`, 7–365) |
| Traffic types | Bytes per kind: Web (HTTPS/HTTP), QUIC (video, Google), DNS, Calls (STUN/DTLS), BitTorrent, SSH, Remote desktop, other TCP/UDP | With the daily records |
| Protocols used | Bytes per protocol a user connected with | With the daily records |
| Top services | **Off by default.** Bytes per service ("YouTube", "Netflix", or the site's registrable domain) per user per day; never page addresses or times | 30 days (`set --site-days`, 1–90); turning it off deletes them at once |
| Connected from | The last 20 public addresses per user, with protocol and first/last seen. Shadowsocks/VLESS: the connecting address; WireGuard/AmneziaWG: the peer's endpoint | 30 days |

What it can't see: VPN traffic is encrypted, so the server never sees page contents or full URLs. Site names come from the TLS/QUIC handshake, HTTP Host and DNS, and apps that hide them (for example with ECH) show up only as their traffic type.

**Rotation, so the disk never fills:**
- **By age:** every save (every 5 minutes, and at shutdown) drops records past their retention.
- **By size:** the file has a hard size limit (default 20 MB; `set --history-max-mb`). Over it, the oldest site totals go first, then the oldest breakdowns, then hourly records; daily totals go last.
- **Low disk:** when the disk has less than 500 MB or 5 % free, the server stops recording detail and shows that in `top`, the dashboard and the app. Live data and usage totals (needed for data limits) continue. Recording resumes on its own when space is freed.
- **Container log:** Docker caps it at 10 MB × 3, and it holds only warnings and errors, never traffic.

## Administer the container

| Command | Does |
|---|---|
| `sudo ghostlink-server show-key` | Print the management key again |
| `sudo ghostlink-server status` | Container status, hostname and ports |
| `sudo ghostlink-server logs [N]` | Last N log lines (warnings and errors only; no traffic logging) |
| `sudo ghostlink-server setup [--hostname H]` | Reload the bundled image and recreate the container, keeping all data |
| `sudo ghostlink-server restart` / `stop` | Restart or stop the container |
| `sudo ghostlink-server remove` | Remove the container and image; keep users and keys |

## Ports

Every port is random on first install (10000–32000, all different) and shown by `status` and in the app:

| Service | Transport |
|---|---|
| Management API | TCP |
| Web dashboard | TCP (127.0.0.1 only unless public) |
| Shadowsocks | TCP and UDP |
| VLESS-REALITY | TCP |
| WireGuard | UDP |
| AmneziaWG | UDP |

Open them in the host firewall and any cloud security group. Ports below 1024 (for example 443 for VLESS) are not supported in this version, because the container runs without capabilities.

## Upgrade and remove

- **Upgrade:** install the newer package. It loads the new image and recreates the container. Users, keys, rules and the management key are kept.
- **Remove:** `sudo apt remove ghostlink-server` stops and removes the container and image, and keeps `/var/lib/ghostlink-server`.
- **Purge:** `sudo apt purge ghostlink-server` also deletes the state and the system account. On RPM systems, removal keeps the state; delete `/var/lib/ghostlink-server` yourself if you want it gone.

## How it is built

- One Go program, `ghostlink-server` (GPL-3.0-or-later, from `core/outline-worker/cmd/ghostlink-server`), runs the management API and one unmodified sing-box 1.14.4 instance. Shadowsocks and VLESS are sing-box inbounds. WireGuard and AmneziaWG are both served by Ghostlink's `amneziawg` endpoint on unmodified amneziawg-go (zero obfuscation for plain WireGuard), on a userspace network stack. So every user's traffic, whatever the protocol, passes the same router and rules.
- **Changes:** each change is applied to a copy of the state and started in a new engine instance, and only then saved. A change the engine refuses, such as a port already in use, leaves the server as it was. Restarting the engine briefly disconnects users, and their clients reconnect on their own.
- **Container:**
  - image: `gcr.io/distroless/static-debian12:nonroot`, pinned by digest, plus the static binary and its notices;
  - user: the host account `ghostlink-server`;
  - hardening: `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, and only the state directory mounted;
  - networking: host networking, like Outline, so UDP needs no proxy hop and ports can change at runtime;
  - logs: rotated at 10 MB × 3.

### Traffic rules, in order

1. Sniff protocol and site name (TLS SNI, HTTP Host, QUIC, DNS).
2. All DNS (protocol DNS or port 53) is answered by the server's resolver, so site blocks cannot be skipped by choosing another resolver.
3. Names are resolved on the server, so the next blocks also catch names that point inside.
4. **Always blocked:**
   - loopback, private and link-local ranges, CGNAT (`100.64.0.0/10`) and cloud metadata (`169.254.169.254`);
   - multicast, and NAT64/IPv4-mapped forms of all of these;
   - the management API port;
   - the server's own address, when its hostname is an IP address.

   With host networking, this keeps VPN users away from services on the host and its network.
5. Each user's own blocks.
6. Users exempt from the rules for everyone go out directly.
7. The rules for everyone.
8. Everything else goes out directly.

Disabled users and users over their limit are removed from the engine entirely, which also ends their open connections. Usage counts each user's payload bytes in both directions (not protocol overhead) and is saved every 30 seconds.

### Management API

All paths are under the secret prefix from the management key, over TLS 1.3. Request bodies are JSON (at most 64 KiB, unknown fields refused). Wrong paths get `404`, and an address that makes 20 wrong guesses in a minute gets `429` for the rest of that minute.

| Method and path | Purpose |
|---|---|
| `GET` / `PATCH /server` | Name, hostname used in keys, VLESS-REALITY site, each protocol's `enabled` and `port` |
| `GET` / `POST /users`, `GET` / `PATCH` / `DELETE /users/{id}` | Users: `name`, `enabled`, `data_limit_bytes`, `exempt_from_global_rules`, `rules`, `reset_usage` |
| `GET` / `POST /users/{id}/keys`, `DELETE /users/{id}/keys/{key}` | Keys: create with `{"protocol":"amneziawg"\|"wireguard"\|"vless"\|"shadowsocks"}` |
| `GET` / `PUT /rules` | Rules for everyone: `blocked_domains`, `blocked_ips`, `blocked_ports`, `block_bittorrent`, `block_smtp` |
| `GET /metrics` | Per-user and total bytes |
| `GET /live` | Speeds, open connections, online users, the last 2 minutes of server rates, health |
| `GET /stats?range=24h\|7d\|30d\|90d[&user=ID]` | Usage over time, traffic types, protocols, top services (when on), totals per user |
| `GET /clients[?user=ID]` | Addresses users connected from |
| `GET /users/{id}/keys/{key}/qr?format=svg\|text&content=auto\|key\|conf` | A key's QR code |
| `GET /users/{id}/kit` | The HTML connection kit |
| `GET /dashboard` | Dashboard port, mode and login token |

`PATCH /server` also takes `site_stats`, `history_days`, `site_days`, `history_max_mb`, `dashboard_port`, `dashboard_public` and `reset_dashboard_token`. User names are unique, ignoring case.

The Ghostlink service is the only intended client. It pins the certificate during the TLS handshake, so the secret path is never sent to a server that cannot prove it holds the certificate's key.

## Limits and notes

- **Changing the hostname:** new keys use the new address, but keys you already shared keep the old one. The management key also changes (`show-key` prints the new one). Ghostlink keeps working through the old address for as long as it still reaches the server.
- **REALITY site:** VLESS-REALITY borrows the TLS 1.3 handshake of a public site, `www.googletagmanager.com` by default. Choose a site that is reachable from the server and not blocked where your users are.
- **Amnezia apps:** the `vpn://` keys follow Amnezia's export format for AmneziaWG and WireGuard, with no SSH credentials. Importing them into Amnezia's own apps has not been verified yet.
- **Not in this version:** IPv6 inside the tunnels, automatic updates, per-user speed and device limits, monthly limit resets, subscription links, and alerts.

Security details: [security model](../security/model.md). What has been tested: [verification ledger](../development/verification.md).
