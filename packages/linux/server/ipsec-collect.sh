#!/bin/sh
# Runs in the Alpine build stage of ipsec.Dockerfile: copies the files the IPsec agent needs,
# with their shared libraries, into $1, and records which Alpine packages they come from.
set -eu
out=$1
plugins="random nonce kdf constraints openssl pem pkcs1 pkcs8 x509 revocation pubkey
  kernel-netlink socket-default vici eap-identity eap-mschapv2 xauth-generic"
files="/usr/lib/strongswan/charon /usr/sbin/swanctl /usr/sbin/xtables-nft-multi
  /usr/sbin/xtables-legacy-multi /usr/lib/ossl-modules/legacy.so"
for p in $plugins; do files="$files /usr/lib/ipsec/plugins/libstrongswan-$p.so"; done
for f in /usr/lib/xtables/*.so; do files="$files $f"; done

copy() { # copy one file (following symlinks) to the same path under $out
    [ -e "$out$1" ] && return 0
    mkdir -p "$out$(dirname "$1")"
    cp -L "$1" "$out$1"
    echo "$1" >> /tmp/copied
}
: > /tmp/copied
for f in $files; do
    [ -e "$f" ] || { echo "missing $f" >&2; exit 1; }
    copy "$f"
    # musl ldd: "libx.so => /usr/lib/libx.so (0x...)" and the loader as "/lib/ld-musl-*.so.1 (0x...)"
    ldd "$f" 2>/dev/null | while read -r name arrow path _; do
        if [ "$arrow" = "=>" ] && [ -e "$path" ]; then
            copy "$path"
            # also under the name programs ask for (for example libc.musl-*.so.1)
            [ "$(basename "$path")" = "$name" ] || { mkdir -p "$out/usr/lib"; [ -e "$out/usr/lib/$name" ] || cp -L "$path" "$out/usr/lib/$name"; }
        elif [ -e "$name" ]; then
            copy "$name"
        fi
    done
done
for name in iptables-nft iptables-nft-save iptables-nft-restore; do ln -s xtables-nft-multi "$out/usr/sbin/$name"; done
for name in iptables-legacy iptables-legacy-save iptables-legacy-restore; do ln -s xtables-legacy-multi "$out/usr/sbin/$name"; done

# charon looks up "root" by name; iptables wants a lock directory; /var/run is /run (tmpfs).
mkdir -p "$out/etc" "$out/run" "$out/var" "$out/usr/share/doc/ghostlink-ipsec"
printf 'root:x:0:0:root:/:/nonexistent\n' > "$out/etc/passwd"
printf 'root:x:0:\n' > "$out/etc/group"
ln -s ../run "$out/var/run"

# Which packages the files come from, with versions and licenses, for the source bundle.
sort -u /tmp/copied | while read -r f; do apk info --who-owns "$(readlink -f "$f")" 2>/dev/null | sed -n 's/.* is owned by //p'; done |
    sort -u > /tmp/owners
apk list --installed 2>/dev/null | while read -r line; do
    package=${line%% *}
    if grep -qx "$package" /tmp/owners; then echo "$line"; fi
done | sed 's/ \[installed\]$//' > "$out/usr/share/doc/ghostlink-ipsec/packages.txt"
cat "$out/usr/share/doc/ghostlink-ipsec/packages.txt"
test -s "$out/usr/share/doc/ghostlink-ipsec/packages.txt"
