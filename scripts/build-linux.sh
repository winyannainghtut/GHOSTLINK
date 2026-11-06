#!/usr/bin/env bash
# Build the headless Linux release archive for the host architecture: CLI, privileged service,
# MCP bridge, managed tunnel worker, systemd unit and notices. The desktop GUI is not included
# until the GTK dependency advisory in docs/security/dependencies.md is resolved.
# Usage: scripts/build-linux.sh [VERSION]   (default: checked version from release-version.mjs)
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(node scripts/release-version.mjs)}"
case "$(uname -m)" in
  x86_64) arch=x64 goarch=amd64 ;;
  aarch64 | arm64) arch=arm64 goarch=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

cargo build --release --locked --workspace
(
  cd core/outline-worker
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -mod=readonly -trimpath -buildvcs=false \
    -tags with_gvisor,with_utls,with_wireguard -ldflags '-s -w' -o ../../target/release/ghostlink-tunnel .
)

name="ghostlink-$version-linux-$arch"
out="artifacts/linux-$arch"
stage="$out/$name"
rm -rf -- "$stage"
mkdir -p "$stage/bin" "$stage/lib/ghostlink" "$stage/systemd" "$stage/licenses"
install -m 0755 target/release/ghostlink target/release/ghostlinkd target/release/ghostlink-mcp "$stage/bin/"
install -m 0755 target/release/ghostlink-tunnel "$stage/lib/ghostlink/"
install -m 0644 packages/linux/ghostlinkd.service "$stage/systemd/"
cp LICENSE NOTICE.md "$stage/licenses/"
cp -R LICENSES/. "$stage/licenses/"
cat > "$stage/INSTALL.txt" <<EOF
Ghostlink $version for Linux ($arch): headless CLI, service, MCP bridge and tunnel worker.

This is an unsigned pre-release. Linux runtime, routing and DNS behavior have not yet been
verified on a real host; test on a machine where route changes are authorized.

Install as root:
  install -m 0755 bin/ghostlink bin/ghostlinkd bin/ghostlink-mcp /usr/local/bin/
  install -d -m 0755 /usr/local/lib/ghostlink
  install -m 0755 lib/ghostlink/ghostlink-tunnel /usr/local/lib/ghostlink/
  install -m 0644 systemd/ghostlinkd.service /etc/systemd/system/
  install -d -m 0755 /etc/ghostlink
  echo "GHOSTLINK_OWNER_UID=\$(id -u YOUR_USER)" > /etc/ghostlink/ghostlinkd.env
  systemctl daemon-reload && systemctl enable --now ghostlinkd

Then, as YOUR_USER:  ghostlink status

Outline full-tunnel routing is disabled by default on Linux. Protect your SSH route first,
then add --allow-full-tunnel through a systemd override (see docs/development/linux.md).

The tunnel worker is GPL-3.0-or-later. Its corresponding source is published with this
release as Ghostlink-$version-worker-corresponding-source.zip. Notices are in licenses/.
EOF
tar -C "$out" --owner=0 --group=0 -czf "$out/$name.tar.gz" "$name"
echo "$out/$name.tar.gz"
