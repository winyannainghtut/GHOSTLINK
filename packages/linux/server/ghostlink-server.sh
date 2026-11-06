#!/bin/sh
# ghostlink-server: administer the Ghostlink VPN server container on this machine.
# Installed as /usr/sbin/ghostlink-server by the ghostlink-server .deb/.rpm, which also carries
# the container image, so no registry is needed.
set -eu

LIB=/usr/lib/ghostlink-server
STATE=/var/lib/ghostlink-server
CONTAINER=ghostlink-server
IPSEC_CONTAINER=ghostlink-ipsec
SYSCTL_FILE=/etc/sysctl.d/90-ghostlink-ipsec.conf
ACCOUNT=ghostlink-server
# shellcheck source=/dev/null
. "$LIB/image.env" # IMAGE=ghostlink-server:<version>, IPSEC_IMAGE=ghostlink-ipsec:<version>

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

Users, keys, rules and monitoring (also available in the Ghostlink app and the dashboard):

  users                                list users, usage and status
  user add NAME [--limit 50GB] [--exempt]
  user enable|disable|remove|reset NAME
  user rename NAME NEW-NAME | user limit NAME 50GB|none | user exempt NAME on|off
  key add NAME PROTOCOL [--no-qr]      amneziawg, wireguard, vless or shadowsocks; prints a QR code
  key add NAME ikev2|ipsec [--auth eap|certificate|psk] [--address H] [--remote-id ID] [--local-id ID]
                                       built-in VPN of iPhone, iPad and Mac (see ipsec below)
  profile NAME ID --output FILE [--prompt-password] [--on-demand]
                                       save an IKEv2/IPsec key as an Apple profile (.mobileconfig)
  keys NAME [--show]                   list keys (key text only with --show)
  key qr NAME ID | key remove NAME ID
  kit NAME --output FILE               HTML page with all of NAME's keys, QR codes and app help
  rules [--user NAME]                  show traffic rules
  rules set [--user NAME] [--block-site S]... [--block-ip CIDR]... [--block-port P]...
            [--block-bittorrent] [--block-smtp]
  usage | stats [NAME] [--range 7d] | clients [NAME]
  top [--once]                         live speed per user (Ctrl+C to quit)
  settings | set [--hostname H] [--enable P] [--disable P] [--port P=N] [--history-days N] ...
  site-stats on|off                    record top sites per user (off deletes them)
  dashboard [--port N] [--public|--private] [--reset-token]
                                       web dashboard: prints the SSH tunnel command and login link

IKEv2/IPsec for iPhone, iPad and Mac (optional; strongSwan in a second, network-privileged
container that only applies settings the server writes):

  ipsec enable             check kernel support, turn on IPv4 forwarding, start the component
  ipsec disable            stop it; its firewall rules and interface are removed
  ipsec status | ipsec logs [N]

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
    # After an upgrade, the IPsec component (if enabled) moves to the new image too.
    if docker inspect "$IPSEC_CONTAINER" >/dev/null 2>&1; then
        ipsec_start
    fi
    show_key
}

# --- IPsec component ---

ipsec_backend() { # the iptables backend this host (and Docker) uses
    if command -v iptables >/dev/null 2>&1; then
        case "$(iptables -V 2>/dev/null)" in
            *nf_tables*) echo nft; return ;;
            *legacy*) echo legacy; return ;;
        esac
    fi
    echo auto
}

ipsec_check_kernel() {
    if command -v modprobe >/dev/null 2>&1; then
        for module in xfrm_user esp4 dummy xt_policy xt_conntrack xt_TCPMSS; do
            modprobe -q "$module" 2>/dev/null || true
        done
    fi
    if command -v ip >/dev/null 2>&1 && ! ip xfrm state >/dev/null 2>&1; then
        die "this kernel has no IPsec (xfrm) support. Container-based VPS types (OpenVZ, LXC) usually cannot run IKEv2/IPsec; use a KVM VPS or a dedicated server."
    fi
}

ipsec_stop_container() {
    if docker inspect "$IPSEC_CONTAINER" >/dev/null 2>&1; then
        # A stop sends SIGTERM, so the agent removes its firewall rules and interface first.
        docker stop --time 20 "$IPSEC_CONTAINER" >/dev/null 2>&1 || true
        docker rm --force "$IPSEC_CONTAINER" >/dev/null 2>&1 || true
    fi
}

# ipsec_start (re)creates the component: root in the server account's group (to share only the
# ipsec directory), no capabilities but the three IPsec needs, read-only, no privilege escalation.
ipsec_start() {
    docker load --input "$LIB/ipsec-image.tar.gz" >/dev/null || die "could not load the bundled IPsec image"
    docker image ls --format '{{.Repository}}:{{.Tag}}' ghostlink-ipsec 2>/dev/null |
        while read -r old; do
            [ "$old" = "$IPSEC_IMAGE" ] || docker image rm "$old" >/dev/null 2>&1 || true
        done
    install -d -m 0770 -o "$uid" -g "$gid" "$STATE/ipsec"
    chown "$uid:$gid" "$STATE/ipsec"
    chmod 0770 "$STATE/ipsec"
    ipsec_stop_container
    rm -f "$STATE/ipsec/status.json"
    docker run --detach --name "$IPSEC_CONTAINER" --restart unless-stopped \
        --log-opt max-size=10m --log-opt max-file=3 \
        --network host --user "0:$gid" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
        --cap-add NET_BIND_SERVICE --security-opt no-new-privileges --read-only --tmpfs /run \
        --volume "$STATE/ipsec:$STATE/ipsec" \
        "$IPSEC_IMAGE" serve --dir "$STATE/ipsec" --iptables "$(ipsec_backend)" >/dev/null
    tries=0
    while [ $tries -lt 40 ]; do
        grep -q '"running": true' "$STATE/ipsec/status.json" 2>/dev/null && return 0
        [ "$(docker inspect --format '{{.State.Running}}' "$IPSEC_CONTAINER" 2>/dev/null || true)" = true ] || break
        tries=$((tries + 1))
        sleep 0.5
    done
    docker logs --tail 20 "$IPSEC_CONTAINER" >&2 || true
    die "the IPsec component did not start; see: sudo ghostlink-server ipsec logs"
}

ipsec_command() {
    action=${1:-status}
    [ $# -gt 0 ] && shift
    need_root "ipsec $action"
    need_docker
    case "$action" in
        enable)
            ensure_account
            ipsec_check_kernel
            printf '# Written by "ghostlink-server ipsec enable"; removed by "ipsec disable".\nnet.ipv4.ip_forward = 1\n' > "$SYSCTL_FILE"
            sysctl -q -w net.ipv4.ip_forward=1 || die "could not turn on IPv4 forwarding"
            ipsec_start
            cat <<'EOF'
The IPsec component is running. Next:
  1. Open UDP 500 and UDP 4500 in this server's firewall and your cloud security group.
  2. Turn the protocols on:  sudo ghostlink-server set --enable ikev2 [--enable ipsec]
  3. Add a key:              sudo ghostlink-server key add NAME ikev2
  4. Save its profile:       sudo ghostlink-server profile NAME ID --output NAME.mobileconfig
     and send it privately (AirDrop, Mail or Files); opening it installs the VPN.
EOF
            ;;
        disable)
            ipsec_stop_container
            rm -f "$SYSCTL_FILE" "$STATE/ipsec/status.json"
            echo "The IPsec component is stopped; its firewall rules and interface are removed."
            echo "IKEv2/IPsec keys stop working until you run: sudo ghostlink-server ipsec enable"
            ;;
        status)
            if docker inspect "$IPSEC_CONTAINER" >/dev/null 2>&1; then
                docker ps --all --filter "name=^${IPSEC_CONTAINER}\$" --format 'container: {{.Status}}'
                sed -n 's/^  "\(running\|error\|applied_generation\)": \([^,]*\),\{0,1\}$/  \1: \2/p' "$STATE/ipsec/status.json" 2>/dev/null || true
                connected=$(grep -c '"identity"' "$STATE/ipsec/status.json" 2>/dev/null) || true
                printf '  connections: %s\n' "${connected:-0}"
            else
                echo "The IPsec component is not installed. Start it with: sudo ghostlink-server ipsec enable"
            fi
            ;;
        logs) docker logs --tail "${1:-100}" "$IPSEC_CONTAINER" ;;
        *) die "usage: sudo ghostlink-server ipsec enable|disable|status|logs" ;;
    esac
}

# admin runs a management command inside the running container, against its local API.
admin() {
    need_root "$1"
    need_docker
    running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)
    [ "$running" = "true" ] || die "the server is not running (start it: sudo ghostlink-server setup)"
    if [ -t 0 ] && [ -t 1 ]; then
        docker exec -it "$CONTAINER" /usr/bin/ghostlink-server admin --state "$STATE" "$@"
    else
        docker exec "$CONTAINER" /usr/bin/ghostlink-server admin --state "$STATE" "$@"
    fi
}

# save_private runs an admin command into a new file only root can read.
save_private() {
    output=$1
    shift
    [ ! -e "$output" ] || die "$output already exists; choose a new file name"
    previous=$(umask)
    umask 077
    if admin "$@" > "$output"; then
        umask "$previous"
    else
        umask "$previous"
        rm -f "$output"
        exit 1
    fi
}

# kit writes a user's connection kit to a new private file on the host.
kit() {
    [ $# -ge 1 ] || die "usage: sudo ghostlink-server kit NAME --output FILE"
    name=$1
    shift
    output=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --output) [ $# -ge 2 ] || die "--output needs a file name"; output=$2; shift 2 ;;
            --output=*) output=${1#--output=}; shift ;;
            *) die "unknown option $1" ;;
        esac
    done
    [ -n "$output" ] || die "choose a file: sudo ghostlink-server kit $name --output $name.html"
    save_private "$output" kit "$name"
    echo "Saved $output. Send it privately to $name; it contains their keys."
}

# profile writes an IKEv2/IPsec key's Apple configuration profile to a new private file.
profile() {
    [ $# -ge 2 ] || die "usage: sudo ghostlink-server profile NAME ID --output FILE [--prompt-password] [--on-demand]"
    name=$1
    id=$2
    shift 2
    output=""
    options=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --output) [ $# -ge 2 ] || die "--output needs a file name"; output=$2; shift 2 ;;
            --output=*) output=${1#--output=}; shift ;;
            --prompt-password | --on-demand) options="$options $1"; shift ;;
            *) die "unknown option $1" ;;
        esac
    done
    [ -n "$output" ] || die "choose a file: sudo ghostlink-server profile $name $id --output $name.mobileconfig"
    # shellcheck disable=SC2086
    save_private "$output" profile "$name" "$id" $options
    echo "Saved $output. Send it privately to $name (AirDrop, Mail or Files); opening it on the"
    echo "iPhone, iPad or Mac installs the VPN (Settings > General > VPN & Device Management)."
}

command=${1:-}
[ $# -gt 0 ] && shift
case "$command" in
    users | user | key | keys | rules | usage | stats | clients | top | settings | set | site-stats | dashboard)
        admin "$command" "$@" ;;
    kit) need_root kit; kit "$@" ;;
    profile) need_root profile; profile "$@" ;;
    ipsec) ipsec_command "$@" ;;
    setup) setup "$@" ;;
    show-key) need_root show-key; show_key ;;
    status)
        need_root status
        need_docker
        docker ps --all --filter "name=^${CONTAINER}\$" --format 'container: {{.Status}}'
        [ -f "$STATE/state.json" ] && sed -n 's/^ *"\(port\|hostname\|enabled\)": *\(.*\),\{0,1\}$/  \1: \2/p' "$STATE/state.json" | head -n 20
        if docker inspect "$IPSEC_CONTAINER" >/dev/null 2>&1; then
            docker ps --all --filter "name=^${IPSEC_CONTAINER}\$" --format 'IPsec component: {{.Status}} (UDP 500, 4500)'
        fi
        ;;
    logs) need_root logs; need_docker; docker logs --tail "${1:-100}" "$CONTAINER" ;;
    restart) need_root restart; need_docker; docker restart "$CONTAINER" >/dev/null && echo "restarted" ;;
    stop) need_root stop; need_docker; docker stop "$CONTAINER" >/dev/null && echo "stopped" ;;
    remove)
        need_root remove
        if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            ipsec_stop_container
            docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
            for repository in ghostlink-server ghostlink-ipsec; do
                docker image ls --format '{{.Repository}}:{{.Tag}}' "$repository" 2>/dev/null |
                    while read -r image; do docker image rm "$image" >/dev/null 2>&1 || true; done
            done
        fi
        rm -f "$SYSCTL_FILE"
        ;;
    version) echo "${IMAGE#ghostlink-server:}" ;;
    "" | help | -h | --help) usage ;;
    *) usage >&2; exit 2 ;;
esac
