#!/bin/sh
# Ghostlink mesh post-remove (deb "remove"/"purge", rpm %postun).
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "purge" ]; then
    rm -rf /var/lib/ghostlink-mesh
fi
exit 0
