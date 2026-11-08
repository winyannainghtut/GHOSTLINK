#!/bin/sh
# Ghostlink client pre-remove (deb "remove"/"upgrade", rpm %preun): stop the service first.
set -e
reenable=/var/lib/ghostlink/enable-on-install
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    case "${1:-}" in
        remove | purge | 0)
            # Removal: disconnect cleanly and stop starting at boot. Remember an enabled service,
            # so that installing the package again turns it back on (see client-postinstall.sh).
            # touch, not a redirection: a failed redirection of a special built-in such as ":"
            # ends the whole script in dash, even with "|| true".
            if systemctl is-enabled --quiet ghostlinkd.service 2>/dev/null; then
                mkdir -p -m 0700 "${reenable%/*}" 2>/dev/null || true
                touch "$reenable" 2>/dev/null || true
            fi
            systemctl disable --now ghostlinkd.service >/dev/null 2>&1 || true
            ;;
        [1-9]*)
            # RPM upgrade: this runs after the new package's post-install has restarted the
            # service with the new version, so leave it running.
            ;;
        *)
            # Debian upgrade: stop now; the new package's post-install starts it again if it is
            # enabled.
            systemctl stop ghostlinkd.service >/dev/null 2>&1 || true
            ;;
    esac
fi
exit 0
