#!/usr/bin/env bash
# Build the Ghostlink mesh agent for the host architecture: the static ghostlink-mesh binary and
# its .deb/.rpm (systemd service). Needs Go and nfpm 2.48.
# Usage: scripts/build-linux-mesh.sh [VERSION]
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(node scripts/release-version.mjs)}"
case "$(uname -m)" in
  x86_64) arch=x64 goarch=amd64 ;;
  aarch64 | arm64) arch=arm64 goarch=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
command -v nfpm >/dev/null || { echo "nfpm is required (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0)" >&2; exit 1; }

out="artifacts/linux-$arch"
work="$out/mesh-build"
rm -rf -- "$work"
mkdir -p "$work/pkg/doc/dependencies"
(
  cd core/outline-worker
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -mod=readonly -trimpath -buildvcs=false -ldflags '-s -w' \
    -o "../../$work/pkg/ghostlink-mesh" ./cmd/ghostlink-mesh
)
reported=$("$work/pkg/ghostlink-mesh" version)
[ "$reported" = "Ghostlink mesh agent $version" ] || { echo "ghostlink-mesh reports '$reported', expected $version" >&2; exit 1; }

cp NOTICE.md LICENSES/GPL-3.0.txt "$work/pkg/doc/"
for notice in LICENSES/dependencies/go-*; do
  cp -R "$notice" "$work/pkg/doc/dependencies/"
done
cat > "$work/pkg/doc/README.md" <<EOF
# Ghostlink mesh agent $version

Joins this Linux server to a Ghostlink mesh: a private network between your servers over kernel
WireGuard (interface \`glmesh0\`), coordinated by a Ghostlink server.

    sudo ghostlink-mesh status       # this node, its peers, paths and latency
    sudo ghostlink-mesh leave        # leave the mesh and remove everything the agent set up

- Join with the command from the Ghostlink app (Servers I run > Mesh > Add node) or
  \`sudo ghostlink-server mesh invite\` on the coordinator.
- Public nodes need UDP 51820 (or the chosen --port) open; nodes behind NAT need nothing inbound.
- State: \`/var/lib/ghostlink-mesh\` (the node's private key never leaves this machine).

GPL-3.0-or-later. Source: Ghostlink-$version-worker-corresponding-source.zip with the release.
Guide: https://github.com/winyannainghtut/GHOSTLINK/blob/main/docs/deployment/mesh.md
EOF
chmod -R u=rwX,go=rX "$work/pkg"

sed -e "s|@VERSION@|$version|" -e "s|@GOARCH@|$goarch|" -e "s|@PKG@|$work/pkg|g" \
  packages/linux/mesh/ghostlink-mesh.nfpm.yaml > "$work/nfpm.yaml"
for packager in deb rpm; do
  nfpm package --config "$work/nfpm.yaml" --packager "$packager" --target "$out/"
done
ls -l "$out"/ghostlink-mesh[_-]*
