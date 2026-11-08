#!/bin/sh
# Ghostlink mesh pre-remove (deb "remove"/"upgrade", rpm %preun). Removing the package leaves
# the mesh (the coordinator drops the node) and removes the interface, firewall chains and
# /etc/hosts entries; a Debian upgrade only stops the agent until the new version starts.
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
    [1-9]*)
        # RPM upgrade: this runs after the new package's post-install has restarted the agent
        # with the new version, so leave it running.
        ;;
    *)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl stop ghostlink-mesh.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
