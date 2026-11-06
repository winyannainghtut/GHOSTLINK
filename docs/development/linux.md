# Linux setup and validation still required

The Rust daemon/CLI and Go worker have Linux code paths; this environment has not run them on Linux. CI is provided to build/check them. Do not treat the systemd unit as runtime-verified.

On Ubuntu/Debian install Rust 1.92+, Go (the worker pins 1.26.10), a native C linker, pkg-config and OpenSSL development libraries. For GUI development also install the Tauri GTK/WebKit2GTK 4.1 development requirements. Build the root workspace with `cargo build --release --locked`; build the managed worker from `core/outline-worker` with `CGO_ENABLED=0 go build -mod=readonly -trimpath -tags with_gvisor,with_utls,with_wireguard -o ghostlink-tunnel .`.

Install `ghostlink`, `ghostlinkd`, `ghostlink-mcp` in `/usr/local/bin`, worker in `/usr/local/lib/ghostlink/ghostlink-tunnel`, and the supplied unit under `/etc/systemd/system/ghostlinkd.service`, all root-owned and not writable by other users. Create a root-owned `/etc/ghostlink/ghostlinkd.env` containing `GHOSTLINK_OWNER_UID=` followed by the intended user's numeric UID. This value is mandatory so a service does not authorize an accidental default user. The daemon sets the Unix socket owner and checks peer credentials.

Full tunnel is disabled by default on Linux. After preserving the route to an SSH administration client and authorizing a route change, an administrator adds `GHOSTLINK_FLAGS=--allow-full-tunnel` to `/etc/ghostlink/ghostlinkd.env` and restarts `ghostlinkd`. Do not enable it casually on an SSH-administered VPS or use this client service as a VPN server. The self-hosted proxy service is a separate unprivileged service.

## Packages

Releases include `.deb` and `.rpm` packages built with nfpm from `packages/linux/ghostlink.nfpm.yaml` by `scripts/build-linux.sh`. They:

- install `/usr/bin/{ghostlink,ghostlinkd,ghostlink-mcp}`, `/usr/lib/ghostlink/ghostlink-tunnel`, `/usr/lib/systemd/system/ghostlinkd.service`, the config file `/etc/ghostlink/ghostlinkd.env` (kept on upgrade) and `/usr/share/doc/ghostlink/`;
- in post-install, set `GHOSTLINK_OWNER_UID` from `SUDO_UID` when it is empty (never root), then enable and restart the service; without an owner they print instructions instead;
- in pre-remove, disable and stop the service (stop only on upgrade);
- on a Debian `purge`, delete `/var/lib/ghostlink` and `/etc/ghostlink`. RPM removal keeps them.

Release CI installs the `.deb` on Ubuntu 22.04 (x64 and arm64), checks that `ghostlinkd` is active and answers `ghostlink status` and `doctor`, then purges it. The `.tar.gz` contains the same files in a `/usr/local` layout plus an `INSTALL.txt`.

## Service flags

`GHOSTLINK_FLAGS` in `/etc/ghostlink/ghostlinkd.env` is appended to the service command line (unquoted, so it may hold several flags). The common use is `GHOSTLINK_FLAGS=--allow-full-tunnel`. The file is root-owned and the daemon accepts only its known flags.

The unit bounds capabilities to networking needs plus `CAP_CHOWN`, which the daemon needs to hand the control socket to `GHOSTLINK_OWNER_UID`; without it the service cannot start for a non-root owner. It grants write access only to its runtime/state paths. Verify that the target kernel exposes `/dev/net/tun` and that routing/DNS integration works under this sandbox. Ubuntu/systemd-resolved and RHEL resolver/firewall configurations differ; a successful compile is insufficient. OpenVPN's optional backend needs separately installed OpenVPN and its own resolver verification.

Before packaging: run the process/real-engine tests, authorize a local privileged TUN test, compare routes/DNS/IPv6 before/during/after, test service stop/crash/restart, then build native DEB/RPM packages. No DEB/RPM is claimed produced in the current Windows environment.
