#!/bin/sh
# Ghostlink client post-remove (deb "remove"/"purge", rpm %postun).
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
# Only an explicit Debian purge deletes the saved servers, keys and settings. A plain remove,
# an upgrade, and RPM removal keep them so a reinstall picks up where you left off.
if [ "${1:-}" = "purge" ]; then
    rm -rf /var/lib/ghostlink /etc/ghostlink
fi
exit 0
