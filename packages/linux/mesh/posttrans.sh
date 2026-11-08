#!/bin/sh
# Ghostlink mesh rpm %posttrans: runs after every other script of the transaction. In an
# upgrade from a package up to 0.8.0, the old package's pre-remove stops the agent after the
# new post-install has restarted it, so start it again while it is enabled.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] &&
    systemctl is-enabled --quiet ghostlink-mesh.service 2>/dev/null &&
    ! systemctl is-active --quiet ghostlink-mesh.service 2>/dev/null; then
    systemctl start ghostlink-mesh.service >/dev/null 2>&1 || true
fi
exit 0
