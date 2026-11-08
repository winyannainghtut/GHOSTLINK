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

Full-tunnel routing is disabled by default on Linux. After protecting your SSH access, add
GHOSTLINK_FLAGS=--allow-full-tunnel to /etc/ghostlink/ghostlinkd.env and restart ghostlinkd.

Prefer a package? The release also has ghostlink_${version}-1_${goarch}.deb and an .rpm
that install to /usr/bin and start the service for the user who ran sudo.

The tunnel worker is GPL-3.0-or-later. Its corresponding source is published with this
release as Ghostlink-$version-worker-corresponding-source.zip. Notices are in licenses/.
EOF
# The archive must not inherit group-writable modes from the checkout either.
chmod -R u=rwX,go=rX "$stage"
tar -C "$out" --owner=0 --group=0 -czf "$out/$name.tar.gz" "$name"
echo "$out/$name.tar.gz"

# .deb/.rpm: same binaries in standard locations (/usr/bin, /usr/lib/ghostlink).
pkg="$out/package-files"
rm -rf -- "$pkg"
mkdir -p "$pkg"
sed -e 's#/usr/local/bin/#/usr/bin/#' -e 's#/usr/local/lib/ghostlink/#/usr/lib/ghostlink/#' \
  packages/linux/ghostlinkd.service > "$pkg/ghostlinkd.service"
# A conffile. The post-install fills in the owner, so dpkg treats an installed copy as changed:
# editing this text makes every later upgrade of such a machine ask what to do with the file.
cat > "$pkg/ghostlinkd.env" <<'EOF'
# Ghostlink service settings, read by ghostlinkd.service. Restart after editing:
#   sudo systemctl restart ghostlinkd
# GHOSTLINK_OWNER_UID: the one local user (numeric ID, see `id -u`) allowed to control Ghostlink.
# The installer fills it in from sudo.
GHOSTLINK_OWNER_UID=
# GHOSTLINK_FLAGS: extra service flags. Full-tunnel routing is off on Linux until you add
# --allow-full-tunnel here, after making sure your SSH access is protected.
GHOSTLINK_FLAGS=
EOF
cat > "$stage/licenses/README.md" <<EOF
# Ghostlink $version for Linux

- \`ghostlink\`: CLI (run as your user). Try \`ghostlink status\`, \`ghostlink key add --name NAME --file KEY.txt\`,
  \`ghostlink connect\`.
- \`ghostlinkd\`: the service (\`systemctl status ghostlinkd\`). Settings: \`/etc/ghostlink/ghostlinkd.env\`.
- \`ghostlink-mcp\`: optional bridge for AI agents.
- \`/usr/lib/ghostlink/ghostlink-tunnel\`: the tunnel worker (GPL-3.0-or-later; source is published with each release).

Full-tunnel routing is off until you add \`GHOSTLINK_FLAGS=--allow-full-tunnel\` to the settings file and
restart the service. Protect your SSH access first if this machine is administered remotely.

Removing the package stops the service. \`apt purge ghostlink\` also deletes saved servers and keys.
Project: https://github.com/winyannainghtut/GHOSTLINK
EOF
# Package files must not inherit group-writable modes from the checkout.
chmod -R u=rwX,go=rX "$stage/licenses" "$pkg"
if command -v nfpm >/dev/null 2>&1; then
  sed -e "s|@VERSION@|$version|" -e "s|@GOARCH@|$goarch|" -e "s|@STAGE@|$stage|g" -e "s|@PKG@|$pkg|g" \
    packages/linux/ghostlink.nfpm.yaml > "$pkg/nfpm.yaml"
  for packager in deb rpm; do
    nfpm package --config "$pkg/nfpm.yaml" --packager "$packager" --target "$out/"
  done
else
  echo "nfpm not found: skipped .deb/.rpm (install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0)" >&2
fi
