#!/bin/sh
# Ghostlink client rpm %posttrans: runs after every other script of the transaction. In an
# upgrade from a package up to 0.8.0, the old package's pre-remove stops the service after the
# new post-install has restarted it, so start it again while it is enabled.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] &&
    systemctl is-enabled --quiet ghostlinkd.service 2>/dev/null &&
    ! systemctl is-active --quiet ghostlinkd.service 2>/dev/null; then
    systemctl start ghostlinkd.service >/dev/null 2>&1 || true
fi
exit 0
