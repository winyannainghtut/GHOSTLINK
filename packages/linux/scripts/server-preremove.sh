#!/bin/sh
# Ghostlink server pre-remove (deb "remove"/"upgrade", rpm %preun). On removal, stop and
# delete the container and image; on upgrade, keep it running until the new version starts.
set -e
case "${1:-}" in
    remove | purge | 0) /usr/sbin/ghostlink-server remove || true ;;
esac
exit 0
