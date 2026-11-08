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
mkdir -p "$work/context/licenses" "$work/pkg/doc" "$work/ipsec/licenses"
(
  cd core/outline-worker
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -mod=readonly -trimpath -buildvcs=false \
    -tags with_gvisor,with_utls,with_wireguard -ldflags '-s -w' \
    -o "../../$work/context/ghostlink-server" ./cmd/ghostlink-server
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -mod=readonly -trimpath -buildvcs=false -ldflags '-s -w' \
    -o "../../$work/ipsec/ghostlink-ipsec-agent" ./cmd/ghostlink-ipsec-agent
)
reported=$("$work/context/ghostlink-server" version)
case "$reported" in
  "Ghostlink server $version;"*) ;;
  *) echo "ghostlink-server reports '$reported', expected version $version" >&2; exit 1 ;;
esac

# Notices for everything inside the image: the GPL server, its Go dependencies and the npm
# packages bundled into its dashboard.
cp NOTICE.md LICENSES/GPL-3.0.txt LICENSES/sing-box.txt "$work/context/licenses/"
mkdir -p "$work/context/licenses/dependencies"
for notice in LICENSES/dependencies/go-* LICENSES/dependencies/npm-*; do
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

# The optional IPsec component (IKEv2/IPsec for iPhone, iPad and Mac): strongSwan and iptables
# from Alpine with the agent. Its GPL source is built by scripts/ipsec-source.sh.
cp packages/linux/server/ipsec-collect.sh "$work/ipsec/collect.sh"
cp NOTICE.md LICENSES/GPL-3.0.txt "$work/ipsec/licenses/"
cat > "$work/ipsec/licenses/SOURCE.txt" <<SOURCE
The Ghostlink IPsec component $version contains ghostlink-ipsec-agent (GNU GPL 3.0 or later;
source: Ghostlink-$version-worker-corresponding-source.zip) and files from the Alpine Linux
packages listed with versions and licenses in packages.txt (strongSwan and iptables are GNU GPL
2.0 or later). Their complete corresponding source (Alpine recipes, patches and upstream
sources) is published with the same release as
Ghostlink-$version-ipsec-component-source-$arch.tar.gz
(https://github.com/winyannainghtut/GHOSTLINK/releases/tag/v$version).
SOURCE
chmod -R u=rwX,go=rX "$work/ipsec"
ipsec_image="ghostlink-ipsec:$version"
docker build --build-arg VERSION="$version" --tag "$ipsec_image" --file packages/linux/server/ipsec.Dockerfile "$work/ipsec"
docker run --rm "$ipsec_image" version | grep -qx "Ghostlink IPsec agent $version"
container=$(docker create "$ipsec_image")
docker cp "$container:/usr/share/doc/ghostlink-ipsec/packages.txt" "$out/ipsec-packages-$arch.txt"
docker rm "$container" >/dev/null
docker save "$ipsec_image" | gzip -9 > "$work/pkg/ipsec-image.tar.gz"
printf 'IMAGE=%s\nIPSEC_IMAGE=%s\n' "$image" "$ipsec_image" > "$work/pkg/image.env"

cp -R "$work/context/licenses/." "$work/pkg/doc/"
cat > "$work/pkg/doc/README.md" <<EOF
# Ghostlink server $version

A self-hosted VPN server in a Docker container: AmneziaWG, WireGuard, VLESS-REALITY and
Shadowsocks (Outline-compatible), plus optional IKEv2/IPsec for the built-in VPN of iPhone, iPad
and Mac (\`sudo ghostlink-server ipsec enable\`). Installing the package loads the bundled image, creates the
server and prints a **management key**. Paste it into the Ghostlink app (Servers I run) or
\`ghostlink server add\` to create users and keys and set traffic rules.

    sudo ghostlink-server show-key            # print the management key again
    sudo ghostlink-server setup --hostname H  # change the address clients use, then restart
    sudo ghostlink-server status | logs | restart | stop

- State: \`/var/lib/ghostlink-server\` (owned by the \`ghostlink-server\` system account, mode 0700).
- Open these ports in your firewall or cloud security group: the API port (TCP), Shadowsocks
  (TCP+UDP), VLESS (TCP), WireGuard and AmneziaWG (UDP), and UDP 500 and 4500 for IKEv2/IPsec.
  \`sudo ghostlink-server status\` lists them.
- Upgrading the package keeps users, keys and rules. \`apt purge ghostlink-server\` deletes them;
  removing the RPM keeps them.

Project: https://github.com/winyannainghtut/GHOSTLINK
EOF
chmod -R u=rwX,go=rX "$work/pkg"

sed -e "s|@VERSION@|$version|" -e "s|@GOARCH@|$goarch|" -e "s|@PKG@|$work/pkg|g" \
  packages/linux/server/ghostlink-server.nfpm.yaml > "$work/nfpm.yaml"
# The file names carry the version as released (0.9.0-rc.1), which is what install-server.sh
# downloads. nfpm's own names write a pre-release as 0.9.0~rc.1, which GitHub may rename on
# upload. Inside the packages it stays 0.9.0~rc.1, so that it sorts before 0.9.0.
case "$goarch" in amd64) rpm_arch=x86_64 ;; arm64) rpm_arch=aarch64 ;; esac
nfpm package --config "$work/nfpm.yaml" --packager deb --target "$out/ghostlink-server_${version}-1_${goarch}.deb"
nfpm package --config "$work/nfpm.yaml" --packager rpm --target "$out/ghostlink-server-${version}-1.${rpm_arch}.rpm"
ls -l "$out"/ghostlink-server[_-]*
