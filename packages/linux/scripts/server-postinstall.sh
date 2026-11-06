#!/bin/sh
# Ghostlink server post-install (deb "configure", rpm %post): load the bundled image and
# create or upgrade the server container. Users, keys and rules survive upgrades.
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] &&
    systemctl list-unit-files docker.service >/dev/null 2>&1; then
    systemctl enable --now docker.service >/dev/null 2>&1 || true
fi
if ! /usr/sbin/ghostlink-server setup; then
    echo "Ghostlink server: setup did not finish. Fix the problem above, then run:" >&2
    echo "  sudo ghostlink-server setup [--hostname YOUR_PUBLIC_IP_OR_NAME]" >&2
fi
exit 0
