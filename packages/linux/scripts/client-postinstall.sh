#!/bin/sh
# Ghostlink client post-install (deb "configure", rpm %post): pick the owner, start the service.
set -e

env_file=/etc/ghostlink/ghostlinkd.env
owner=$(sed -n 's/^GHOSTLINK_OWNER_UID=\([0-9][0-9]*\)$/\1/p' "$env_file" 2>/dev/null | head -n 1)

# The owner is the one local user allowed to control the service. When installed with sudo,
# default to the user who ran sudo; never guess root or any other account.
if [ -z "$owner" ] && [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != "0" ]; then
    case "$SUDO_UID" in
        *[!0-9]*) ;;
        *)
            owner=$SUDO_UID
            if grep -q '^GHOSTLINK_OWNER_UID=' "$env_file" 2>/dev/null; then
                sed -i "s/^GHOSTLINK_OWNER_UID=.*/GHOSTLINK_OWNER_UID=$owner/" "$env_file"
            else
                printf 'GHOSTLINK_OWNER_UID=%s\n' "$owner" >> "$env_file"
            fi
            ;;
    esac
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ -n "$owner" ]; then
        systemctl enable ghostlinkd.service >/dev/null 2>&1 || true
        if systemctl restart ghostlinkd.service; then
            echo "Ghostlink is installed for user ID $owner. Try: ghostlink status"
        else
            echo "Ghostlink: the service did not start; check: journalctl -u ghostlinkd" >&2
        fi
    else
        echo "Ghostlink is installed. Set GHOSTLINK_OWNER_UID in $env_file to your user ID"
        echo "(run: id -u), then run: sudo systemctl enable --now ghostlinkd"
    fi
fi
echo "Full-tunnel routing on Linux is off until you enable it; see /usr/share/doc/ghostlink/README.md."
exit 0
