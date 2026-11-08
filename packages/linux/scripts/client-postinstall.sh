#!/bin/sh
# Ghostlink client post-install (deb "configure", rpm %post): pick the owner, start the service.
# A first install enables and starts the service. An upgrade restarts it only while it is
# enabled, so a service the administrator turned off stays off.
set -e

env_file=/etc/ghostlink/ghostlinkd.env
# Written by the pre-remove script when removing the package turned an enabled service off.
# Installing again from Debian's "config-files" state looks like an upgrade, so the file marks
# it as a first install, which turns the service back on.
reenable=/var/lib/ghostlink/enable-on-install

# GHOSTLINK_OWNER_UID as systemd reads the EnvironmentFile: the last assignment counts, and the
# value may be quoted, have blanks around "=" or end in a carriage return.
owner_value() {
    [ -f "$env_file" ] || return 0
    awk -v q="'" '
        { sub(/\r$/, ""); line = $0; sub(/^[ \t]+/, "", line) }
        line ~ /^GHOSTLINK_OWNER_UID[ \t]*=/ {
            sub(/^GHOSTLINK_OWNER_UID[ \t]*=[ \t]*/, "", line)
            sub(/[ \t]+$/, "", line)
            first = substr(line, 1, 1)
            if (length(line) >= 2 && (first == "\"" || first == q) && substr(line, length(line), 1) == first)
                line = substr(line, 2, length(line) - 2)
            value = line
        }
        END { print value }
    ' "$env_file"
}

upgrade=
case "${1:-}" in
    configure) [ -z "${2:-}" ] || upgrade=1 ;; # deb: configure <last configured version>
    abort-*) upgrade=1 ;;
    1 | "") ;; # rpm first install, or run by hand
    *) upgrade=1 ;; # rpm upgrade: 2 or more
esac
if [ -e "$reenable" ]; then
    upgrade=
    rm -f "$reenable"
fi

value=$(owner_value)
owner=
case "$value" in
    "" | *[!0-9]*) ;;
    *) owner=$value ;;
esac

# The owner is the one local user allowed to control the service. When installed with sudo,
# fill in an empty owner with the user who ran sudo; never guess root or any other account,
# and never replace an owner that is already set.
if [ -z "$value" ] && [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != "0" ]; then
    case "$SUDO_UID" in
        *[!0-9]*) ;;
        *)
            owner=$SUDO_UID
            if grep -q '^[[:blank:]]*GHOSTLINK_OWNER_UID[[:blank:]]*=' "$env_file" 2>/dev/null; then
                sed -i "s/^[[:blank:]]*GHOSTLINK_OWNER_UID[[:blank:]]*=.*/GHOSTLINK_OWNER_UID=$owner/" "$env_file"
            else
                printf 'GHOSTLINK_OWNER_UID=%s\n' "$owner" >> "$env_file"
            fi
            ;;
    esac
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ -z "$owner" ]; then
        if [ -n "$value" ]; then
            echo "Ghostlink is installed, but GHOSTLINK_OWNER_UID in $env_file is not a user ID."
            echo "Set it to your numeric user ID (run: id -u), then run: sudo systemctl enable --now ghostlinkd"
        else
            echo "Ghostlink is installed. Set GHOSTLINK_OWNER_UID in $env_file to your user ID"
            echo "(run: id -u), then run: sudo systemctl enable --now ghostlinkd"
        fi
    elif [ -z "$upgrade" ] || systemctl is-enabled --quiet ghostlinkd.service 2>/dev/null; then
        [ -n "$upgrade" ] || systemctl enable ghostlinkd.service >/dev/null 2>&1 || true
        if systemctl restart ghostlinkd.service; then
            echo "Ghostlink is installed for user ID $owner. Try: ghostlink status"
        else
            echo "Ghostlink: the service did not start; check: journalctl -u ghostlinkd" >&2
        fi
    else
        echo "Ghostlink is upgraded. The ghostlinkd service is disabled, so it was not started."
        echo "To turn it on: sudo systemctl enable --now ghostlinkd"
    fi
fi
echo "Full-tunnel routing on Linux is off until you enable it; see /usr/share/doc/ghostlink/README.md."
exit 0
