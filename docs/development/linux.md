# Linux setup and validation still required

CI builds and runs the Linux daemon, CLI and worker. Release CI runs `ghostlinkd` as a real systemd service from the `.deb` (start, status, doctor, upgrade, removal, purge). A privileged TUN session, routing and DNS inside the unit's sandbox have not been verified.

On Ubuntu/Debian install Rust 1.92+, Go (the worker pins 1.26.10), a native C linker, pkg-config and OpenSSL development libraries. For GUI development also install the Tauri GTK/WebKit2GTK 4.1 development requirements. Build the root workspace with `cargo build --release --locked`; build the managed worker from `core/outline-worker` with `CGO_ENABLED=0 go build -mod=readonly -trimpath -tags with_gvisor,with_utls,with_wireguard -o ghostlink-tunnel .`.

Install `ghostlink`, `ghostlinkd`, `ghostlink-mcp` in `/usr/local/bin`, worker in `/usr/local/lib/ghostlink/ghostlink-tunnel`, and the supplied unit under `/etc/systemd/system/ghostlinkd.service`, all root-owned and not writable by other users. Create a root-owned `/etc/ghostlink/ghostlinkd.env` containing `GHOSTLINK_OWNER_UID=` followed by the intended user's numeric UID. This value is mandatory so a service does not authorize an accidental default user. The daemon sets the Unix socket owner and checks peer credentials.

Full tunnel is disabled by default on Linux. Every Shadowsocks and VLESS key is a full tunnel, and so is an OpenVPN profile with `redirect-gateway` and a WireGuard or AmneziaWG profile whose `AllowedIPs` cover every public IPv4 address, also when split into pieces such as `0.0.0.0/1, 128.0.0.0/1`. After preserving the route to an SSH administration client and authorizing a route change, an administrator adds `GHOSTLINK_FLAGS=--allow-full-tunnel` to `/etc/ghostlink/ghostlinkd.env` and restarts `ghostlinkd`. Do not enable it casually on an SSH-administered VPS or use this client service as a VPN server. The self-hosted proxy service is a separate unprivileged service.

## Packages

Releases include `.deb` and `.rpm` packages built with nfpm from `packages/linux/ghostlink.nfpm.yaml` by `scripts/build-linux.sh`. They:

- install `/usr/bin/{ghostlink,ghostlinkd,ghostlink-mcp}`, `/usr/lib/ghostlink/ghostlink-tunnel`, the unit (`/lib/systemd/system/ghostlinkd.service` in the `.deb`, where Debian/Ubuntu register units; `/usr/lib/systemd/system/` in the `.rpm`), the config file `/etc/ghostlink/ghostlinkd.env` (kept on upgrade) and `/usr/share/doc/ghostlink/`;
- in post-install, set `GHOSTLINK_OWNER_UID` from `SUDO_UID` when it is empty (never root). An owner already in the file is kept, in any form systemd reads (quoted, with spaces around `=`, the last assignment counting). Without an owner they print instructions instead;
- on a first install, enable and start the service. An upgrade restarts it only if it is enabled, so a service you disabled stays off. Installing again after removing the package counts as a first install if the service was enabled when it was removed;
- in pre-remove, disable and stop the service on removal. A Debian upgrade only stops it until the new post-install starts it; an RPM upgrade leaves it running, and the `.rpm`'s `%posttrans` starts an enabled service that an older package's pre-remove stopped;
- on a Debian `purge`, delete `/var/lib/ghostlink` and `/etc/ghostlink`. RPM removal keeps them.

The mesh agent's `.deb`/`.rpm` stops and starts the agent the same way during upgrades.

Release CI installs the `.deb` on Ubuntu 22.04 (x64 and arm64), checks that `ghostlinkd` is active and answers `ghostlink status` and `doctor`, reinstalls it with the service enabled and then disabled, removes and installs it again, then purges it. The `.tar.gz` contains the same files in a `/usr/local` layout plus an `INSTALL.txt`.

## Server packages

`scripts/build-linux-server.sh` builds:
- the static `ghostlink-server` binary;
- the container image, from `packages/linux/server/Dockerfile` (pinned distroless base, no `RUN` steps, so it builds natively on each architecture without emulation);
- `ghostlink-server` `.deb`/`.rpm` packages from `packages/linux/server/ghostlink-server.nfpm.yaml`, which carry `docker save` output as `/usr/lib/ghostlink-server/image.tar.gz`.

It needs Go, Docker and nfpm. The package scripts are `packages/linux/scripts/server-*.sh`, and the admin command is `packages/linux/server/ghostlink-server.sh`.

Release CI installs the server `.deb` on each Ubuntu runner with `GHOSTLINK_SERVER_HOSTNAME=127.0.0.1`, then:
- matches the served certificate against the printed pin;
- checks that a wrong path gets `404`;
- creates a user and a key for every protocol;
- checks the container is running read-only with `no-new-privileges` on host networking, with all capabilities dropped but the four the server needs to start (`SETUID`, `SETGID`, `SETPCAP`, `NET_BIND_SERVICE`), and that the running server is the `ghostlink-server` account with only `NET_BIND_SERVICE` (`/proc/PID/status`: effective, permitted, ambient and bounding sets, and `NoNewPrivs`);
- moves Shadowsocks to port 443 and checks that it listens there, on TCP and UDP, and that its keys follow;
- checks the state directory is `700 ghostlink-server`;
- reinstalls, and confirms users and keys survive;
- purges, and confirms the container, state and account are gone.

See the [server guide](../deployment/ghostlink-server.md).

## Service flags

`GHOSTLINK_FLAGS` in `/etc/ghostlink/ghostlinkd.env` is appended to the service command line (unquoted, so it may hold several flags). The common use is `GHOSTLINK_FLAGS=--allow-full-tunnel`. The file is root-owned and the daemon accepts only its known flags.

The unit bounds capabilities to networking needs plus `CAP_CHOWN`, which the daemon needs to hand the control socket to `GHOSTLINK_OWNER_UID`; without it the service cannot start for a non-root owner. It grants write access only to its runtime/state paths. Verify that the target kernel exposes `/dev/net/tun` and that routing/DNS integration works under this sandbox. Ubuntu/systemd-resolved and RHEL resolver/firewall configurations differ; a successful compile is insufficient. OpenVPN's optional backend needs separately installed OpenVPN and its own resolver verification.

Still to verify on a real host: a privileged TUN session, routes/DNS/IPv6 before, during and after, and service stop/crash/restart. The release CI install test covers the package and service lifecycle, not full-device routing.
