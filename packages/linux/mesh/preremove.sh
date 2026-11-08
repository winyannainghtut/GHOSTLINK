#!/bin/sh
# Ghostlink mesh pre-remove (deb "remove"/"upgrade", rpm %preun). Removing the package leaves
# the mesh (the coordinator drops the node) and removes the interface, firewall chains and
# /etc/hosts entries. A deb upgrade only stops the agent until the new version's postinst starts
# it. An rpm upgrade runs this old script after the new package's %post has already restarted
# the agent, so it must leave the agent alone.
set -e
case "${1:-}" in
    remove | purge | 0)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl disable --now ghostlink-mesh.service >/dev/null 2>&1 || true
        fi
        if [ -f /var/lib/ghostlink-mesh/node.json ]; then
            /usr/bin/ghostlink-mesh leave >/dev/null 2>&1 || true
        fi
        ;;
    1)
        ;;
    *)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl stop ghostlink-mesh.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
