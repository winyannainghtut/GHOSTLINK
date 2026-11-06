#!/bin/sh
# Ghostlink client pre-remove (deb "remove"/"upgrade", rpm %preun): stop the service first.
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    case "${1:-}" in
        remove | purge | 0)
            # Removal: disconnect cleanly and stop starting at boot.
            systemctl disable --now ghostlinkd.service >/dev/null 2>&1 || true
            ;;
        *)
            # Upgrade: stop now; the new package's post-install starts it again.
            systemctl stop ghostlinkd.service >/dev/null 2>&1 || true
            ;;
    esac
fi
exit 0
