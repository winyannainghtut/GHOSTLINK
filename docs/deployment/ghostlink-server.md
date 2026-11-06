# Ghostlink server

A self-hosted VPN server in one Docker container, administered from the Ghostlink app or CLI in the style of Outline: installing it prints a **management key**, and whoever holds that key manages the server.

- **Protocols:** AmneziaWG (2.0 obfuscation), WireGuard, VLESS with REALITY, and Outline-compatible Shadowsocks. Each can be turned off or moved to another port.
- **Users and keys:** create users, then issue keys per protocol. A key works in Ghostlink and is meant for other clients too: `ss://` for Outline apps, `vless://` for Xray-based apps, `.conf` for WireGuard/AmneziaWG apps, and an Amnezia-format `vpn://` for AmneziaWG/WireGuard.
- **Traffic rules:** block sites, IP ranges, ports, BitTorrent and outgoing mail, for everyone or one user. A user can be exempted from the rules for everyone.
- **Usage and limits:** per-user data counters and data limits; users who reach their limit are cut off until the limit is raised or the counter is reset.
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

## Administer on the server

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

The Ghostlink service is the only intended client. It pins the certificate during the TLS handshake, so the secret path is never sent to a server that cannot prove it holds the certificate's key.

## Limits and notes

- **Changing the hostname:** new keys use the new address, but keys you already shared keep the old one. The management key also changes (`show-key` prints the new one). Ghostlink keeps working through the old address for as long as it still reaches the server.
- **REALITY site:** VLESS-REALITY borrows the TLS 1.3 handshake of a public site, `www.googletagmanager.com` by default. Choose a site that is reachable from the server and not blocked where your users are.
- **Amnezia apps:** the `vpn://` keys follow Amnezia's export format for AmneziaWG and WireGuard, with no SSH credentials. Importing them into Amnezia's own apps has not been verified yet.
- **Not in this version:** IPv6 inside the tunnels, automatic updates, per-user speed limits, and a web dashboard.

Security details: [security model](../security/model.md). What has been tested: [verification ledger](../development/verification.md).
