#!/usr/bin/env bash
# Build the Ghostlink server for the host architecture: the static ghostlink-server binary,
# its container image, and the ghostlink-server .deb/.rpm that carry the image (docker save),
# so a server can be installed without any registry.
# Needs Go, Docker and nfpm 2.48. Usage: scripts/build-linux-server.sh [VERSION]
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(node scripts/release-version.mjs)}"
case "$(uname -m)" in
  x86_64) arch=x64 goarch=amd64 ;;
  aarch64 | arm64) arch=arm64 goarch=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 1; }
command -v nfpm >/dev/null || { echo "nfpm is required (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0)" >&2; exit 1; }

out="artifacts/linux-$arch"
work="$out/server-build"
rm -rf -- "$work"
mkdir -p "$work/context/licenses" "$work/pkg/doc"
(
  cd core/outline-worker
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -mod=readonly -trimpath -buildvcs=false \
    -tags with_gvisor,with_utls,with_wireguard -ldflags '-s -w' \
    -o "../../$work/context/ghostlink-server" ./cmd/ghostlink-server
)
reported=$("$work/context/ghostlink-server" version)
case "$reported" in
  "Ghostlink server $version;"*) ;;
  *) echo "ghostlink-server reports '$reported', expected version $version" >&2; exit 1 ;;
esac

# Notices for everything inside the image: the GPL server and its Go dependencies.
cp NOTICE.md LICENSES/GPL-3.0.txt LICENSES/sing-box.txt "$work/context/licenses/"
mkdir -p "$work/context/licenses/dependencies"
for notice in LICENSES/dependencies/go-*; do
  cp -R "$notice" "$work/context/licenses/dependencies/"
done
cat > "$work/context/licenses/SOURCE.txt" <<EOF
Ghostlink server $version is free software under the GNU GPL, version 3 or later.
Its complete corresponding source is published with the same release as
Ghostlink-$version-worker-corresponding-source.zip
(https://github.com/winyannainghtut/GHOSTLINK/releases/tag/v$version).
It builds the server with: go build -tags with_gvisor,with_utls,with_wireguard ./cmd/ghostlink-server
EOF
chmod -R u=rwX,go=rX "$work/context"

image="ghostlink-server:$version"
docker build --build-arg VERSION="$version" --tag "$image" --file packages/linux/server/Dockerfile "$work/context"
docker run --rm "$image" version | grep -q "^Ghostlink server $version;"
docker save "$image" | gzip -9 > "$work/pkg/image.tar.gz"
printf 'IMAGE=%s\n' "$image" > "$work/pkg/image.env"

cp -R "$work/context/licenses/." "$work/pkg/doc/"
cat > "$work/pkg/doc/README.md" <<EOF
# Ghostlink server $version

A self-hosted VPN server in a Docker container: AmneziaWG, WireGuard, VLESS-REALITY and
Shadowsocks (Outline-compatible). Installing the package loads the bundled image, creates the
server and prints a **management key**. Paste it into the Ghostlink app (Servers I manage) or
\`ghostlink server add\` to create users and keys and set traffic rules.

    sudo ghostlink-server show-key            # print the management key again
    sudo ghostlink-server setup --hostname H  # change the address clients use, then restart
    sudo ghostlink-server status | logs | restart | stop

- State: \`/var/lib/ghostlink-server\` (owned by the \`ghostlink-server\` system account, mode 0700).
- Open these ports in your firewall or cloud security group: the API port (TCP), Shadowsocks
  (TCP+UDP), VLESS (TCP), WireGuard and AmneziaWG (UDP). \`sudo ghostlink-server status\` lists them.
- Upgrading the package keeps users, keys and rules. \`apt purge ghostlink-server\` deletes them;
  removing the RPM keeps them.

Project: https://github.com/winyannainghtut/GHOSTLINK
EOF
chmod -R u=rwX,go=rX "$work/pkg"

sed -e "s|@VERSION@|$version|" -e "s|@GOARCH@|$goarch|" -e "s|@PKG@|$work/pkg|g" \
  packages/linux/server/ghostlink-server.nfpm.yaml > "$work/nfpm.yaml"
for packager in deb rpm; do
  nfpm package --config "$work/nfpm.yaml" --packager "$packager" --target "$out/"
done
ls -l "$out"/ghostlink-server[_-]*
