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
  migrate-outline [--check] [--outline-dir /opt/outline]
                           take over the Outline server on this machine: its access keys
                           become clients whose ss:// keys keep working, then Outline is
                           stopped (its files stay as a backup). --check only shows what
                           would happen

Users, keys, rules and monitoring (also available in the Ghostlink app and the dashboard):

  users                                list users, usage and status
  user add NAME [--limit 50GB] [--speed 2MB] [--exempt]
  user enable|disable|remove|reset NAME
  user rename NAME NEW-NAME | user limit NAME 50GB|none | user exempt NAME on|off
  user speed NAME 2MB|none|default     speed limit in bytes per second (2MB = 2 MB/s),
                                       download and upload alike, for all of NAME's keys
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
  set --speed-limit 2MB|none           default speed limit for clients without their own
  site-stats on|off                    record top sites per user (off deletes them)
  dashboard [--port N] [--public|--private] [--reset-token]
                                       web dashboard: prints the SSH tunnel command and login link

Mesh: a private network between your Linux servers (this server coordinates it):

  mesh enable | mesh invite [--tags web] | mesh nodes | mesh map | mesh approve NAME | mesh help
  mesh join-here           make this server a mesh node too (the relay for nodes behind NAT);
                           needs the ghostlink-mesh package (scripts/install-mesh.sh)

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

# The state belongs to the container account, and the server container can rename and replace
# anything in it. A compromised server could therefore put a symlink to any host directory where
# a directory of the state belongs, so root must never follow one there. in_state_dir runs a
# command inside such a directory only after checking, from inside it, that it is that directory
# of the state. The command then acts on ".", which a swap after the check cannot redirect.
in_state_dir() { # NAME COMMAND...
    target=$1
    shift
    (
        expected=$(cd -P "$STATE" && pwd -P)/$target &&
            cd -P "$STATE/$target" 2>/dev/null &&
            [ "$(pwd -P)" = "$expected" ] &&
            "$@"
    )
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
}

# prune_images drops the images of other versions of a repository. Call it after the container
# was recreated: Docker keeps an image that a container still uses.
prune_images() { # REPOSITORY IMAGE-TO-KEEP
    docker image ls --format '{{.Repository}}:{{.Tag}}' "$1" 2>/dev/null |
        while read -r old; do
            [ "$old" = "$2" ] || docker image rm "$old" >/dev/null 2>&1 || true
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
(Servers I run > Add server), or run: ghostlink server add --name NAME --key-file FILE

$(cat "$STATE/management-key.json")

Keep it private: it gives full control of this server. Show it again with:
  sudo ghostlink-server show-key
EOF
}

# state_summary prints the address in keys and each service's port from the state file, which
# the server writes with two spaces of indentation per level. Ports inside "users" belong to
# keys imported from Outline that kept their own.
state_summary() { # STATE-FILE
    awk '
        BEGIN {
            title["api"] = "management API: TCP"
            title["shadowsocks"] = "Shadowsocks: TCP and UDP"
            title["vless"] = "VLESS-REALITY: TCP"
            title["wireguard"] = "WireGuard: UDP"
            title["amneziawg"] = "AmneziaWG: UDP"
            title["mesh"] = "mesh coordinator: TCP"
            title["dashboard"] = "web dashboard: TCP"
        }
        /^  "hostname": "/ { host = $2; gsub(/[",]/, "", host) }
        /^  "users": [[]$/ { users = 1; next }
        users && /^  ]/ { users = 0; next }
        users && /^ +"port": [0-9]+,?$/ {
            p = $2; sub(/,$/, "", p)
            if (!(p in extra)) { extra[p] = 1; extras = extras (extras == "" ? "" : ", ") p }
            next
        }
        /^  "[a-z_]+": [{]$/ { section = $1; gsub(/[":]/, "", section); next }
        section != "" && /^    "enabled": / { state[section] = ($2 ~ /^true/) ? "on" : "off" }
        section != "" && /^    "public": / { state[section] = ($2 ~ /^true/) ? "public" : "127.0.0.1 only" }
        section != "" && /^    "port": / { p = $2; sub(/,$/, "", p); port[section] = p; order[++n] = section }
        /^  [}]/ { section = "" }
        END {
            if (host != "") print "  address in keys: " host
            for (i = 1; i <= n; i++) {
                s = order[i]
                if (!(s in title)) continue
                line = "  " title[s] " " port[s]
                if (s == "shadowsocks" && extras != "") line = line " (and " extras " for keys from Outline)"
                if (s in state) line = line ", " state[s]
                print line
            }
        }
    ' "$1"
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
    # Stop the running server before init. A stop lets it save its usage and history, and it
    # must not save its old state over what init writes next (it saves every 30 seconds).
    was_running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)
    if [ "$was_running" = true ]; then
        docker stop "$CONTAINER" >/dev/null 2>&1 || true
    fi
    if [ -n "$hostname" ]; then
        tool init --hostname "$hostname" >/dev/null || setup_failed
    else
        tool init >/dev/null || setup_failed
    fi
    tool check >/dev/null || setup_failed
    start_container
    prune_images ghostlink-server "$IMAGE"
    # After an upgrade, the IPsec component (if enabled) moves to the new image too.
    if docker inspect "$IPSEC_CONTAINER" >/dev/null 2>&1; then
        ipsec_start
    fi
    show_key
}

# setup_failed starts the server that setup stopped, with its old image, and stops.
setup_failed() {
    if [ "$was_running" = true ] && docker start "$CONTAINER" >/dev/null 2>&1; then
        die "setup did not finish (see above); the server runs as before"
    fi
    die "setup did not finish (see above)"
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

# ipsec_dir makes $STATE/ipsec, the only directory the IPsec container gets, a directory of the
# server account with mode 0770, or stops if something else is in its place (see in_state_dir).
ipsec_dir() {
    mkdir -m 0770 "$STATE/ipsec" 2>/dev/null || true
    in_state_dir ipsec ipsec_dir_owner || ipsec_dir_refused
}

ipsec_dir_owner() { chown "$uid:$gid" . && chmod 0770 .; }

ipsec_dir_refused() {
    die "$STATE/ipsec is not a plain directory (Ghostlink never makes it a symlink or a file); check it, move it away and run this again"
}

# ipsec_start (re)creates the component: root in the server account's group (to share only the
# ipsec directory), no capabilities but the three IPsec needs, read-only, no privilege escalation.
ipsec_start() {
    ipsec_dir
    docker load --input "$LIB/ipsec-image.tar.gz" >/dev/null || die "could not load the bundled IPsec image"
    ipsec_stop_container
    # Checked again right before Docker mounts it.
    in_state_dir ipsec rm -f status.json || ipsec_dir_refused
    docker run --detach --name "$IPSEC_CONTAINER" --restart unless-stopped \
        --log-opt max-size=10m --log-opt max-file=3 \
        --network host --user "0:$gid" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
        --cap-add NET_BIND_SERVICE --security-opt no-new-privileges --read-only --tmpfs /run \
        --volume "$STATE/ipsec:$STATE/ipsec" \
        "$IPSEC_IMAGE" serve --dir "$STATE/ipsec" --iptables "$(ipsec_backend)" >/dev/null
    prune_images ghostlink-ipsec "$IPSEC_IMAGE"
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
            ipsec_dir # a refusal leaves the host as it was
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
            rm -f "$SYSCTL_FILE"
            in_state_dir ipsec rm -f status.json || true
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

# mesh_command manages the mesh; join-here also makes this host a node and the relay.
mesh_command() {
    if [ "${1:-}" != join-here ]; then
        admin mesh "$@"
        return
    fi
    shift
    need_root "mesh join-here"
    command -v ghostlink-mesh >/dev/null 2>&1 ||
        die "install the mesh agent first: curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-mesh.sh | sudo bash"
    [ ! -f /var/lib/ghostlink-mesh/node.json ] || die "this server is already a mesh node (see: sudo ghostlink-mesh status)"
    invite=$(admin --json mesh invite --relay --local --hours 1 --note "this server" | sed -n 's/^  "invite": "\(glmesh1:[^"]*\)".*/\1/p')
    [ -n "$invite" ] || die "could not create an invite; is the mesh on? (sudo ghostlink-server mesh enable)"
    # Other nodes reach this host at its public address, which the agent can't always see.
    host=$(sed -n 's/^  "hostname": "\([^"]*\)".*/\1/p' "$STATE/state.json" | head -n 1)
    case "$host" in
        *[!0-9.]*) address=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR == 1 { print $1 }') ;;
        *) address=$host ;;
    esac
    # The endpoint names the port the agent listens on: its --port, if one is passed on.
    port=51820
    take=""
    for argument in "$@"; do
        if [ -n "$take" ]; then
            port=$argument
            take=""
            continue
        fi
        case "$argument" in
            --port | -port) take=1 ;;
            --port=* | -port=*) port=${argument#*=} ;;
        esac
    done
    if [ -n "$address" ]; then
        GHOSTLINK_MESH_INVITE="$invite" ghostlink-mesh join --relay --endpoint "$address:$port" "$@"
    else
        GHOSTLINK_MESH_INVITE="$invite" ghostlink-mesh join --relay "$@"
    fi
    systemctl enable --now ghostlink-mesh.service >/dev/null
    echo "This server is now a mesh node and the relay. Allow UDP $port in its firewall and cloud security group."
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

# save_private runs an admin command into a new file only root can read. With set -C the shell
# creates the file exclusively, so it never writes through a symlink left in its place. The
# command runs in a subshell, so that a failed check (die exits) still removes the file below.
save_private() {
    output=$1
    shift
    if [ -e "$output" ] || [ -L "$output" ]; then
        die "$output already exists; choose a new file name"
    fi
    previous=$(umask)
    umask 077
    if (set -C; admin "$@" > "$output"); then
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

# --- migration from Outline ---

# outline_restore puts Outline's containers back as they were before the migration: each
# gets its old restart policy, and those that were running start again. $outline_state holds
# NAME=POLICY=RUNNING entries. It says which container it could not bring back.
outline_restore() {
    restored=0
    for entry in $outline_state; do
        name=${entry%%=*}
        rest=${entry#*=}
        policy=${rest%%=*}
        if ! docker update --restart="$policy" "$name" >/dev/null 2>&1; then
            echo "ghostlink-server: could not set $name's restart policy back to $policy: sudo docker update --restart=$policy $name" >&2
            restored=1
        fi
        if [ "${rest#*=}" = true ] && ! docker start "$name" >/dev/null 2>&1; then
            echo "ghostlink-server: could not start $name again: sudo docker start $name" >&2
            restored=1
        fi
    done
    return $restored
}

# outline_entry turns what docker inspect says about a container (POLICY/RETRIES/RUNNING) into
# a NAME=POLICY=RUNNING entry for outline_restore. The fields are split on "/" so that an empty
# policy name, which older Docker reports for a container created without one, stays a field.
outline_entry() { # NAME POLICY/RETRIES/RUNNING
    policy=${2%%/*}
    rest=${2#*/}
    retries=${rest%%/*}
    up=${rest#*/}
    policy=${policy:-no}
    if [ "$policy" = on-failure ] && [ "${retries:-0}" -gt 0 ] 2>/dev/null; then
        policy="on-failure:$retries"
    fi
    echo "$1=$policy=${up:-false}"
}

# copy_outline_files runs inside the new work directory (see migrate_outline). The directory is
# still root's while the copies are made, so nothing else can swap them, and goes to the server
# account last, so that the server can read them.
copy_outline_files() {
    for file in shadowbox_config.json shadowbox_server_config.json; do
        if [ -f "$persisted/$file" ]; then
            install -m 0600 -o "$uid" -g "$gid" "$persisted/$file" "$file" || return 1
        fi
    done
    chown "$uid:$gid" .
}

# outline_imported is true when Ghostlink already has clients: the import went through even
# if a later step failed. Called from the exit trap, so it must not exit itself.
outline_imported() {
    docker exec "$CONTAINER" /usr/bin/ghostlink-server admin --state "$STATE" --json users 2>/dev/null | grep -q '"id"'
}

# migrate_exit runs whenever migrate-outline ends (also on Ctrl+C or a lost SSH session): if
# Outline was stopped but the import did not go through, Outline comes back; the private
# copies of its files are always deleted.
migrate_exit() {
    status=$?
    trap - EXIT
    if [ "$outline_stopped" = 1 ] && [ "$import_done" = 0 ]; then
        if outline_imported; then
            echo "ghostlink-server: the import went through, but a later step failed; Outline stays stopped. Check: sudo ghostlink-server users" >&2
        elif outline_restore; then
            echo "ghostlink-server: the import did not go through; Outline is back as it was." >&2
        else
            echo "ghostlink-server: the import did not go through, and Outline could not be fully restored (see above)." >&2
        fi
    fi
    rm -rf "$work"
    exit "$status"
}

# migrate_outline takes over the Outline server (Jigsaw's shadowbox) on this machine.
migrate_outline() {
    check=""
    outline_dir=/opt/outline
    while [ $# -gt 0 ]; do
        case "$1" in
            --check) check=--check; shift ;;
            --outline-dir) [ $# -ge 2 ] || die "--outline-dir needs a directory"; outline_dir=$2; shift 2 ;;
            --outline-dir=*) outline_dir=${1#--outline-dir=}; shift ;;
            *) die "usage: sudo ghostlink-server migrate-outline [--check] [--outline-dir /opt/outline]" ;;
        esac
    done
    need_root migrate-outline
    need_docker
    [ -f "$outline_dir/persisted-state/shadowbox_config.json" ] ||
        die "no Outline server here: $outline_dir/persisted-state/shadowbox_config.json does not exist (if Outline is installed elsewhere, use --outline-dir)"
    outline_dir=$(cd "$outline_dir" && pwd -P)
    persisted=$outline_dir/persisted-state
    dir_option=""
    [ "$outline_dir" = /opt/outline ] || dir_option=" --outline-dir '$outline_dir'"
    running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)
    [ "$running" = "true" ] || die "the Ghostlink server is not running (set it up first: sudo ghostlink-server setup)"

    # Private copies inside the state, which the server reads; Outline's files stay as they are.
    # Root makes the directory anew and fills it from inside (see in_state_dir and
    # copy_outline_files), so the copies cannot be sent anywhere else on the host.
    uid=$(id -u "$ACCOUNT")
    gid=$(id -g "$ACCOUNT")
    work=$STATE/outline-import
    outline_stopped=0
    import_done=0
    outline_state=""
    rm -rf "$work"
    trap migrate_exit EXIT
    trap 'exit 130' INT TERM HUP
    mkdir -m 0700 "$work" || die "could not create $work"
    in_state_dir outline-import copy_outline_files || die "could not copy Outline's files into $work"

    if [ -n "$check" ]; then
        admin import-outline --dir "$work" --check
        echo
        echo "Outline keeps running. To take it over: sudo ghostlink-server migrate-outline$dir_option"
        return 0
    fi
    # Check first: a refusal (for example, Ghostlink already has clients) leaves Outline alone.
    admin import-outline --dir "$work" --check >/dev/null

    # Stop Outline so its ports are free, and keep it from starting again on boot. What each
    # container was like is kept first, so the exit trap can put it back.
    for name in shadowbox watchtower; do
        found=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}/{{.HostConfig.RestartPolicy.MaximumRetryCount}}/{{.State.Running}}' "$name" 2>/dev/null) || continue
        outline_state="$outline_state $(outline_entry "$name" "$found")"
    done
    if [ -n "$outline_state" ]; then
        echo "Stopping Outline (its files in $outline_dir are kept)"
        outline_stopped=1
        for entry in $outline_state; do
            docker update --restart=no "${entry%%=*}" >/dev/null
            docker stop "${entry%%=*}" >/dev/null
        done
    fi
    admin import-outline --dir "$work"
    import_done=1

    echo
    echo "Outline's access keys now connect to Ghostlink."
    if [ -z "$outline_state" ]; then
        echo "No Outline containers (shadowbox, watchtower) were found, so nothing was stopped."
        return 0
    fi
    names=""
    echo "Outline is stopped and stays off after a reboot; its files in $outline_dir are untouched."
    echo
    echo "To go back to Outline:"
    echo "  sudo ghostlink-server stop"
    for entry in $outline_state; do
        name=${entry%%=*}
        rest=${entry#*=}
        names="$names $name"
        if [ "${rest#*=}" = true ]; then
            echo "  sudo docker update --restart=${rest%%=*} $name && sudo docker start $name"
        else
            echo "  sudo docker update --restart=${rest%%=*} $name"
        fi
    done
    echo "When everything works, remove Outline for good:"
    echo "  sudo docker rm -f$names && sudo rm -rf '$outline_dir'"
}

command=${1:-}
[ $# -gt 0 ] && shift
case "$command" in
    users | user | key | keys | rules | usage | stats | clients | top | settings | set | site-stats | dashboard)
        admin "$command" "$@" ;;
    --json) # machine-readable output: ghostlink-server --json users
        case "${1:-}" in
            users | user | key | keys | rules | usage | stats | clients | settings | set | site-stats | dashboard | mesh) admin --json "$@" ;;
            *) die "--json works with: users, user, key, keys, rules, usage, stats, clients, settings, set, site-stats, dashboard, mesh" ;;
        esac ;;
    kit) need_root kit; kit "$@" ;;
    profile) need_root profile; profile "$@" ;;
    mesh) mesh_command "$@" ;;
    ipsec) ipsec_command "$@" ;;
    setup) setup "$@" ;;
    migrate-outline) migrate_outline "$@" ;;
    show-key) need_root show-key; show_key ;;
    status)
        need_root status
        need_docker
        docker ps --all --filter "name=^${CONTAINER}\$" --format 'container: {{.Status}}'
        [ ! -f "$STATE/state.json" ] || state_summary "$STATE/state.json" || true
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
            # A stop lets the server save its usage and history first.
            docker stop "$CONTAINER" >/dev/null 2>&1 || true
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
