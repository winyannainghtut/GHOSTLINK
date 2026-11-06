#!/bin/sh
# Ghostlink server post-remove (deb "remove"/"purge", rpm %postun). Only a Debian purge deletes
# the server's users, keys, rules and management key, and its system account.
set -e
if [ "${1:-}" = "purge" ]; then
    rm -rf /var/lib/ghostlink-server
    if id -u ghostlink-server >/dev/null 2>&1; then
        userdel ghostlink-server >/dev/null 2>&1 || true
    fi
fi
exit 0
