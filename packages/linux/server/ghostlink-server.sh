#!/bin/sh
# ghostlink-server: administer the Ghostlink VPN server container on this machine.
# Installed as /usr/sbin/ghostlink-server by the ghostlink-server .deb/.rpm, which also carries
# the container image, so no registry is needed.
set -eu

LIB=/usr/lib/ghostlink-server
STATE=/var/lib/ghostlink-server
CONTAINER=ghostlink-server
ACCOUNT=ghostlink-server
# shellcheck source=/dev/null
. "$LIB/image.env" # IMAGE=ghostlink-server:<version>

usage() {
    cat <<'EOF'
usage: sudo ghostlink-server <command>

  setup [--hostname HOST]  load the bundled image, create the server on first run and
                           (re)start it; prints the management key
  show-key                 print the management key to paste into the Ghostlink app
  status                   show whether the server is running and its ports
  logs [N]                 show the last N log lines (default 100)
  restart                  restart the server container
  stop                     stop the server (it stays stopped until setup or restart)
  remove                   remove the container and image (keeps users and keys)
  version                  print the bundled server version

HOST is the public IP or DNS name VPN clients use. Without --hostname, setup keeps the
stored one or, on first run, asks api.ipify.org / icanhazip.com for this server's IP.
EOF
}

die() {
    echo "ghostlink-server: $*" >&2
    exit 1
}

need_root() {
    [ "$(id -u)" = 0 ] || die "run this as root, for example: sudo ghostlink-server $1"
}

need_docker() {
    command -v docker >/dev/null 2>&1 || die "Docker is not installed (install docker.io or docker-ce)"
    docker info >/dev/null 2>&1 || die "Docker is not running (try: sudo systemctl enable --now docker)"
}

# The container runs as a dedicated unprivileged host account that owns only the state.
ensure_account() {
    if ! id -u "$ACCOUNT" >/dev/null 2>&1; then
        nologin=/usr/sbin/nologin
        [ -x "$nologin" ] || nologin=/sbin/nologin
        useradd --system --no-create-home --home-dir "$STATE" --shell "$nologin" \
            --comment "Ghostlink VPN server" "$ACCOUNT" ||
            die "could not create the $ACCOUNT system account"
    fi
    uid=$(id -u "$ACCOUNT")
    gid=$(id -g "$ACCOUNT")
    install -d -m 0700 -o "$uid" -g "$gid" "$STATE"
    chown -R "$uid:$gid" "$STATE"
}

# Shared hardening: host networking (as Outline does), no capabilities, read-only root,
# no privilege escalation; only the state directory is writable.
hardening() {
    printf '%s\n' --network host --user "$uid:$gid" --cap-drop ALL \
        --security-opt no-new-privileges --read-only --volume "$STATE:$STATE"
}

tool() {
    # shellcheck disable=SC2046
    docker run --rm $(hardening) "$IMAGE" "$@" --state "$STATE"
}

load_image() {
    docker load --input "$LIB/image.tar.gz" >/dev/null || die "could not load the bundled image"
    # Drop images from earlier versions of this package.
    docker image ls --format '{{.Repository}}:{{.Tag}}' ghostlink-server 2>/dev/null |
        while read -r old; do
            [ "$old" = "$IMAGE" ] || docker image rm "$old" >/dev/null 2>&1 || true
        done
}

start_container() {
    docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    # shellcheck disable=SC2046
    docker run --detach --name "$CONTAINER" --restart unless-stopped \
        --log-opt max-size=10m --log-opt max-file=3 \
        $(hardening) "$IMAGE" serve --state "$STATE" >/dev/null
    tries=0
    while [ $tries -lt 20 ]; do
        running=$(docker inspect --format '{{.State.Running}} {{.RestartCount}}' "$CONTAINER" 2>/dev/null || true)
        [ "$running" = "true 0" ] && [ $tries -ge 4 ] && return 0
        tries=$((tries + 1))
        sleep 0.5
    done
    docker logs --tail 20 "$CONTAINER" >&2 || true
    die "the server did not stay running; see: sudo ghostlink-server logs"
}

show_key() {
    [ -f "$STATE/management-key.json" ] || die "no server yet; run: sudo ghostlink-server setup"
    cat <<EOF

Ghostlink server is running. Paste this management key into the Ghostlink app
(Servers I manage > Add server), or run: ghostlink server add --name NAME --key-file FILE

$(cat "$STATE/management-key.json")

Keep it private: it gives full control of this server. Show it again with:
  sudo ghostlink-server show-key
EOF
}

setup() {
    hostname=${GHOSTLINK_SERVER_HOSTNAME:-}
    while [ $# -gt 0 ]; do
        case "$1" in
            --hostname) [ $# -ge 2 ] || die "--hostname needs a value"; hostname=$2; shift 2 ;;
            --hostname=*) hostname=${1#--hostname=}; shift ;;
            *) usage >&2; exit 2 ;;
        esac
    done
    need_root setup
    need_docker
    ensure_account
    load_image
    if [ -n "$hostname" ]; then
        tool init --hostname "$hostname" >/dev/null
    else
        tool init >/dev/null
    fi
    tool check >/dev/null
    start_container
    show_key
}

command=${1:-}
[ $# -gt 0 ] && shift
case "$command" in
    setup) setup "$@" ;;
    show-key) need_root show-key; show_key ;;
    status)
        need_root status
        need_docker
        docker ps --all --filter "name=^${CONTAINER}\$" --format 'container: {{.Status}}'
        [ -f "$STATE/state.json" ] && sed -n 's/^ *"\(port\|hostname\|enabled\)": *\(.*\),\{0,1\}$/  \1: \2/p' "$STATE/state.json" | head -n 20
        ;;
    logs) need_root logs; need_docker; docker logs --tail "${1:-100}" "$CONTAINER" ;;
    restart) need_root restart; need_docker; docker restart "$CONTAINER" >/dev/null && echo "restarted" ;;
    stop) need_root stop; need_docker; docker stop "$CONTAINER" >/dev/null && echo "stopped" ;;
    remove)
        need_root remove
        if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
            docker image ls --format '{{.Repository}}:{{.Tag}}' ghostlink-server 2>/dev/null |
                while read -r image; do docker image rm "$image" >/dev/null 2>&1 || true; done
        fi
        ;;
    version) echo "${IMAGE#ghostlink-server:}" ;;
    "" | help | -h | --help) usage ;;
    *) usage >&2; exit 2 ;;
esac
