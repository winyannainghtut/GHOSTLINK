#!/bin/sh
# Ghostlink mesh post-install (deb "configure", rpm %post). After an upgrade the agent restarts
# with the new version; on a fresh install it waits for `ghostlink-mesh join`.
set -e
modprobe wireguard >/dev/null 2>&1 || true
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ -f /var/lib/ghostlink-mesh/node.json ]; then
        systemctl enable ghostlink-mesh.service >/dev/null 2>&1 || true
        systemctl restart ghostlink-mesh.service >/dev/null 2>&1 || true
    else
        echo "Ghostlink mesh agent installed. Join a mesh with the command from the Ghostlink app"
        echo "(Servers I run > Manage > Network > Mesh > Add node), or: sudo ghostlink-server mesh invite"
    fi
fi
exit 0
