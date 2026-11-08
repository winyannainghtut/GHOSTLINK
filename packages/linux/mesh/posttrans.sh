#!/bin/sh
# Ghostlink mesh rpm %posttrans: runs once the whole transaction is done. Upgrading from an older
# package runs that package's %preun after this one's %post, and the older %preun stops the
# agent; start it again. Starting an agent that is already running does nothing.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && [ -f /var/lib/ghostlink-mesh/node.json ]; then
    systemctl start ghostlink-mesh.service >/dev/null 2>&1 || true
fi
exit 0
