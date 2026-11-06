# Linux setup and validation still required

The Rust daemon/CLI and Go worker have Linux code paths; this environment has not run them on Linux. CI is provided to build/check them. Do not treat the systemd unit as runtime-verified.

On Ubuntu/Debian install Rust 1.92+, Go (the worker pins 1.26.10), a native C linker, pkg-config and OpenSSL development libraries. For GUI development also install the Tauri GTK/WebKit2GTK 4.1 development requirements. Build the root workspace with `cargo build --release --locked`; build the managed worker from `core/outline-worker` with `CGO_ENABLED=0 go build -mod=readonly -trimpath -tags with_gvisor -o myvpn-tunnel .`.

Install `myvpn`, `myvpnd`, `myvpn-mcp` in `/usr/local/bin`, worker in `/usr/local/lib/myvpn/myvpn-tunnel`, and the supplied unit under `/etc/systemd/system/myvpnd.service`, all root-owned and not writable by other users. Create a root-owned `/etc/myvpn/myvpnd.env` containing `MYVPN_OWNER_UID=` followed by the intended user's numeric UID. This value is mandatory so a service does not authorize an accidental default user. The daemon sets the Unix socket owner and checks peer credentials.

Full tunnel is disabled by default on Linux. After preserving the route to an SSH administration client and authorizing a route change, an administrator may create a systemd override replacing `ExecStart` with the same command plus `--allow-full-tunnel`. Do not enable it casually on an SSH-administered VPS or use this client service as a VPN server. The self-hosted proxy service is a separate unprivileged service.

The unit bounds capabilities to networking needs and grants write access only to its runtime/state paths. Verify that the target kernel exposes `/dev/net/tun` and that routing/DNS integration works under this sandbox. Ubuntu/systemd-resolved and RHEL resolver/firewall configurations differ; a successful compile is insufficient. OpenVPN's optional backend needs separately installed OpenVPN and its own resolver verification.

Before packaging: run the process/real-engine tests, authorize a local privileged TUN test, compare routes/DNS/IPv6 before/during/after, test service stop/crash/restart, then build native DEB/RPM packages. No DEB/RPM is claimed produced in the current Windows environment.
