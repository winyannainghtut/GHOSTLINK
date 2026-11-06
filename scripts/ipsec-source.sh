#!/usr/bin/env bash
# Builds the complete corresponding source for the IPsec component image of one architecture:
# for every Alpine package with a copyleft license that provides files in the image (see
# usr/share/doc/ghostlink-ipsec/packages.txt), its Alpine recipe (APKBUILD, patches, scripts)
# and the upstream source files, fetched and checksum-verified by Alpine's own abuild.
# Needs Docker. Usage: scripts/ipsec-source.sh VERSION ARCH PACKAGES_TXT
set -euo pipefail
cd "$(dirname "$0")/.."
version=$1 arch=$2 packages=$3
alpine="alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4"
branch=3.24-stable
out=artifacts/source
name="Ghostlink-$version-ipsec-component-source-$arch"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$out" "$work/$name"
cp "$packages" "$work/packages.txt"
cp "$packages" "$work/$name/packages.txt"

# Lines look like: "strongswan-6.0.7-r2 x86_64 {strongswan} (GPL-2.0-or-later WITH ...)".
# Copyleft = any GPL, LGPL or MPL license (dual-licensed packages are included too).
# The recipes come from Alpine's official aports mirror on GitHub (a sparse, shallow checkout),
# since gitlab.alpinelinux.org refuses automated downloads.
docker run --rm -e BRANCH="$branch" -e OWNER="$(id -u):$(id -g)" -v "$work:/work" "$alpine" sh -euc '
  trap "chown -R \"\$OWNER\" /work" EXIT
  apk add --no-cache abuild git >/dev/null
  grep -E "\((.*GPL.*|.*MPL.*)\)" /work/packages.txt | while read -r package _ origin _; do
    origin=${origin#\{}; origin=${origin%\}}
    echo "$origin $package"
  done | sort -u > /work/copyleft
  cat /work/copyleft
  git clone --quiet --depth 1 --filter=blob:none --sparse --branch "$BRANCH" https://github.com/alpinelinux/aports.git /aports
  (cd /aports && git sparse-checkout set $(cut -d" " -f1 /work/copyleft | sort -u | sed "s|.*|main/& community/&|"))
  echo "aports $BRANCH at $(git -C /aports rev-parse HEAD)" > /work/'"$name"'/aports-commit.txt
  cut -d" " -f1 /work/copyleft | sort -u | while read -r origin; do
    dest=/work/'"$name"'/$origin
    mkdir -p "$dest/upstream"
    for repo in main community; do
      if [ -f "/aports/$repo/$origin/APKBUILD" ]; then
        cp -R "/aports/$repo/$origin/." "$dest/"
        break
      fi
    done
    [ -f "$dest/APKBUILD" ] || { echo "no Alpine recipe for $origin" >&2; exit 1; }
    # The recipe must be exactly the version in the image.
    want=$(. "$dest/APKBUILD" >/dev/null 2>&1; echo "$pkgver-r$pkgrel")
    grep "^$origin " /work/copyleft | while read -r _ package; do
      case "$package" in
        *-"$want") ;;
        *) echo "$origin recipe is $want but the image has $package; rebuild both" >&2; exit 1 ;;
      esac
    done
    (cd "$dest" && SRCDEST="$dest/upstream" abuild -F fetch && SRCDEST="$dest/upstream" abuild -F verify)
  done
'
cat > "$work/$name/README.txt" <<EOF
Corresponding source for the Ghostlink IPsec component $version ($arch).

The image ghostlink-ipsec:$version (shipped inside the ghostlink-server package) contains
ghostlink-ipsec-agent, whose source is Ghostlink-$version-worker-corresponding-source.zip, and
files from the Alpine Linux $branch packages in packages.txt. For each of those under a
copyleft license, this archive holds a directory with:

  APKBUILD and patches   Alpine's build recipe, exactly as used for the installed version
  upstream/              the upstream source files the recipe names, checksum-verified

To rebuild a package: copy its directory into an Alpine $branch aports tree and run
"abuild -r" there (see https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package).
The image is assembled by packages/linux/server/ipsec.Dockerfile in the Ghostlink source.
EOF
tar -C "$work" -czf "$out/$name.tar.gz" "$name"
ls -l "$out/$name.tar.gz"
