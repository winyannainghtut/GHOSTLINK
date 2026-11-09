#!/usr/bin/env bash
# End-to-end test of the Ghostlink mesh with kernel WireGuard (CI runner, root). A coordinator
# (ghostlink-server) runs on the host; mesh nodes run ghostlink-mesh in network namespaces:
#
#   relay  198.51.100.11  public, relay
#   pub    198.51.100.12  public, tag web, shares 192.168.50.0/24 (namespace lan behind it)
#   nata   behind NAT router 1 (198.51.100.20, random source ports), tag web
#   natb   behind NAT router 2 (198.51.100.21, random source ports), tag db
#
# nata and natb can't reach each other directly, so their traffic must go through the relay.
# Checked: joining, every pair pings, paths (direct vs relay), names (<node>.mesh), access rules,
# a published port (DNAT, as Docker does), subnet sharing only after approval and the router's
# own address in it, Docker's rules ahead of the agent's and a connection kept across a gap in
# the rules, disabling and removing nodes, an interface deleted under its agent, the firewall
# after a reload, and a clean host afterwards.
# Usage: sudo tests/mesh/e2e.sh DIR-WITH-ghostlink-server-AND-ghostlink-mesh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
bin=$(realpath "$1")
work=$(mktemp -d)
pids=()
declare -A agent
step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
namespaces=(relay pub nata natb nat1 nat2 lan)

cleanup() {
    status=$?
    set +e
    if [ $status -ne 0 ]; then
        echo "--- coordinator log"; tail -n 40 "$work/coord.log"
        for ns in relay pub nata natb; do
            echo "--- $ns agent log"; tail -n 30 "$work/$ns.log" 2>/dev/null
            echo "--- $ns status"; cat "$work/$ns/status.json" 2>/dev/null | head -n 40
            echo "--- $ns wg"; ip netns exec "$ns" wg show 2>/dev/null
        done
        echo "--- topology"; admin --json mesh map 2>/dev/null
    fi
    # A paused agent only ends once it may run again.
    for pid in "${pids[@]}"; do kill -CONT "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; done
    sleep 2
    for ns in "${namespaces[@]}"; do ip netns del "$ns" 2>/dev/null; rm -rf "/etc/netns/$ns"; done
    ip link del glinet 2>/dev/null
    iptables -D FORWARD -i glinet -o glinet -j ACCEPT 2>/dev/null
    rm -rf -- "$work"
    exit $status
}
trap cleanup EXIT

admin() { "$bin/ghostlink-server" admin --state "$work/coord" "$@"; }
in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

step "Network: a bridge for the 'internet', namespaces, two NAT routers"
command -v wg >/dev/null || { apt-get update -qq && apt-get install -y -qq wireguard-tools >/dev/null; }
ip link add glinet type bridge && ip addr add 198.51.100.1/24 dev glinet && ip link set glinet up
# Docker's FORWARD policy would drop bridged traffic (br_netfilter).
iptables -I FORWARD -i glinet -o glinet -j ACCEPT
wire() { # NS IFNAME ADDRESS: a veth from the bridge into NS
    ip link add "b-$1-$2" type veth peer name "$2" netns "$1"
    ip link set "b-$1-$2" master glinet up
    ip -n "$1" addr add "$3" dev "$2" && ip -n "$1" link set "$2" up
}
for ns in "${namespaces[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    mkdir -p "/etc/netns/$ns" && printf '127.0.0.1\tlocalhost\n' > "/etc/netns/$ns/hosts"
done
wire relay eth0 198.51.100.11/24 && ip -n relay route add default via 198.51.100.1
wire pub eth0 198.51.100.12/24 && ip -n pub route add default via 198.51.100.1
wire nat1 wan 198.51.100.20/24 && ip -n nat1 route add default via 198.51.100.1
wire nat2 wan 198.51.100.21/24 && ip -n nat2 route add default via 198.51.100.1
link() { # A IF-A ADDR-A B IF-B ADDR-B
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2" && ip -n "$1" link set "$2" up
    ip -n "$4" addr add "$6" dev "$5" && ip -n "$4" link set "$5" up
}
link nat1 lan 10.10.1.1/24 nata eth0 10.10.1.2/24 && ip -n nata route add default via 10.10.1.1
link nat2 lan 10.10.2.1/24 natb eth0 10.10.2.2/24 && ip -n natb route add default via 10.10.2.1
link pub lan0 192.168.50.1/24 lan eth0 192.168.50.10/24 && ip -n lan route add default via 192.168.50.1
for router in nat1 nat2; do
    in_ns "$router" sysctl -q -w net.ipv4.ip_forward=1
    # Random source ports: the address a node is seen from is not where it can be reached.
    in_ns "$router" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE --random-fully
done

step "Coordinator"
"$bin/ghostlink-server" init --state "$work/coord" --hostname 198.51.100.1 >/dev/null
"$bin/ghostlink-server" serve --state "$work/coord" --log-level warn >"$work/coord.log" 2>&1 &
pids+=($!)
for i in $(seq 1 50); do admin users >/dev/null 2>&1 && break; sleep 0.2; done
admin mesh enable | tee "$work/enable.txt"
grep -q "100.96.0.0/16" "$work/enable.txt"

step "Join four nodes"
join() { # NS NAME INVITE-OPTIONS -- AGENT-OPTIONS
    local ns=$1 name=$2; shift 2
    local options=() agent_flags=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do options+=("$1"); shift; done
    [ $# -gt 0 ] && shift
    agent_flags=("$@")
    invite=$(admin --json mesh invite "${options[@]}" | jq -r .invite)
    in_ns "$ns" env GHOSTLINK_MESH_INVITE="$invite" "$bin/ghostlink-mesh" join --state "$work/$ns" --name "$name" "${agent_flags[@]}" | tee -a "$work/joins.txt"
    ip netns exec "$ns" "$bin/ghostlink-mesh" serve --state "$work/$ns" >"$work/$ns.log" 2>&1 &
    pids+=($!)
    agent[$ns]=$!
}
join relay relay --relay -- --relay
join pub pub --tags web -- --advertise-routes 192.168.50.0/24
join nata nata --tags web
join natb natb --tags db
grep -q "Joined the mesh as natb (100.96.0.4), connected" "$work/joins.txt" || fail "joining"

address() { admin --json mesh nodes | jq -r --arg n "$1" '.nodes[] | select(.name == $n) | .address'; }
reaches() { in_ns "$1" ping -c 1 -W 2 "$2" >/dev/null 2>&1; }
wait_for() { # SECONDS DESCRIPTION COMMAND...
    local seconds=$1 what=$2; shift 2
    for i in $(seq 1 "$seconds"); do "$@" && return 0; sleep 1; done
    fail "$what"
}
all_online() { [ "$(admin --json mesh nodes | jq '[.nodes[] | select(.online and .in_sync)] | length')" = 4 ]; }
wait_for 40 "all four nodes online and in sync" all_online

step "Direct links"
for pair in relay:pub relay:nata relay:natb pub:nata pub:natb; do
    a=${pair%%:*} b=${pair##*:}
    wait_for 30 "$a reaches $b over the mesh" reaches "$a" "$(address "$b")"
done
in_ns pub getent hosts natb.mesh | grep -q "$(address natb)" || fail "names in /etc/hosts"

step "nata <-> natb: no direct path, so through the relay"
relayed() { admin --json mesh map | jq -e --arg a "$(admin --json mesh nodes | jq -r '.nodes[] | select(.name=="nata") | .id')" \
    --arg b "$(admin --json mesh nodes | jq -r '.nodes[] | select(.name=="natb") | .id')" \
    '.[] | select((.a == $a and .b == $b) or (.a == $b and .b == $a)) | .path == "relay"' >/dev/null; }
wait_for 150 "the nata-natb pair switched to the relay" relayed
wait_for 30 "nata reaches natb through the relay" reaches nata "$(address natb)"
in_ns nata wg show glmesh0 | grep -q "$(admin --json mesh nodes | jq -r '.nodes[] | select(.name=="natb") | .address')/32" ||
    fail "natb's address should be routed to the relay peer on nata"
admin mesh map | tee "$work/map.txt"
grep -q "via relay" "$work/map.txt"

step "A published port: pub DNATs its port 9000 to a server, as Docker does for a container"
# lan stands in for the container. Docker turns on forwarding itself.
in_ns lan python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1 & pids+=($!)
in_ns pub sysctl -q -w net.ipv4.ip_forward=1
in_ns pub iptables -t nat -A PREROUTING -d "$(address pub)" -p tcp --dport 9000 -j DNAT --to-destination 192.168.50.10:8000
published() { in_ns "$1" curl -s -o /dev/null --max-time 4 "http://pub.mesh:9000/"; }
wait_for 20 "open mesh: relay reaches pub's published port" published relay

step "Access rules: only web -> db TCP 5432, and web -> pub TCP 9000"
in_ns natb python3 -m http.server 5432 --bind 0.0.0.0 >/dev/null 2>&1 & pids+=($!)
in_ns natb python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 & pids+=($!)
sleep 1
http() { in_ns "$1" curl -s -o /dev/null --max-time 4 "http://natb.mesh:$2/"; }
wait_for 20 "open mesh: relay reaches natb:8080" http relay 8080
admin mesh rules add --from tag:web --to tag:db --proto tcp --ports 5432
admin mesh rules add --from tag:web --to node:pub --proto tcp --ports 9000
sleep 3
wait_for 20 "web (pub) reaches db:5432" http pub 5432
wait_for 20 "web (nata, relayed) reaches db:5432" http nata 5432
wait_for 20 "web (nata) reaches pub's published port" published nata
if http pub 8080; then fail "web reached db:8080, which no rule allows"; fi
if http relay 5432; then fail "relay (not web) reached db:5432"; fi
if published relay; then fail "relay (not web) reached pub's published port"; fi
# Docker starting after the agent puts its own rules ahead of the agent's FORWARD jump: its
# DOCKER-USER chain first, then rules that accept traffic to its containers' published ports.
in_ns pub iptables -N DOCKER-USER
in_ns pub iptables -A DOCKER-USER -j RETURN
in_ns pub iptables -I FORWARD 1 -d 192.168.50.10/32 -p tcp --dport 8000 -j ACCEPT
in_ns pub iptables -I FORWARD 1 -j DOCKER-USER
# Right away, before the agent has noticed Docker (it is paused, so it can't): the guard in the
# mangle table refuses the node without a rule, though Docker's accept rule comes first.
kill -STOP "${agent[pub]}"
if published relay; then fail "relay (not web) reached pub's published port right after Docker's rules came first"; fi
published nata || fail "web (nata) lost pub's published port to the guard"
kill -CONT "${agent[pub]}"
docker_jump() { in_ns pub iptables -C DOCKER-USER -i glmesh0 -j GHOSTLINK-MESH-FWD 2>/dev/null; }
wait_for 45 "pub's agent puts its jump first in DOCKER-USER" docker_jump
test "$(in_ns pub iptables -S DOCKER-USER | sed -n 2p)" = "-A DOCKER-USER -o glmesh0 -j GHOSTLINK-MESH-OUT" ||
    fail "the agent's jumps are not first in DOCKER-USER: $(in_ns pub iptables -S DOCKER-USER)"
if published relay; then fail "relay (not web) reached pub's published port once Docker's rules came first"; fi
wait_for 20 "web (nata) still reaches pub's published port" published nata
reaches relay "$(address natb)" || fail "ping must still pass"

step "A connection opened while the agent's rules were missing ends when they are back"
# An echo service behind pub, published on pub's mesh address port 9001, which no rule allows to relay.
in_ns lan python3 -c '
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 8001)); s.listen()
def echo(c):
    while (data := c.recv(64)):
        c.sendall(data)
while True:
    c, _ = s.accept(); threading.Thread(target=echo, args=(c,), daemon=True).start()
' >/dev/null 2>&1 & pids+=($!)
in_ns pub iptables -t nat -A PREROUTING -d "$(address pub)" -p tcp --dport 9001 -j DNAT --to-destination 192.168.50.10:8001
# A gap in enforcement: the agent (paused, so it can't put them back) has none of its jumps.
kill -STOP "${agent[pub]}"
in_ns pub iptables -D INPUT -i glmesh0 -j GHOSTLINK-MESH-IN
for j in "-i glmesh0 -j GHOSTLINK-MESH-FWD" "-o glmesh0 -j GHOSTLINK-MESH-OUT"; do
    in_ns pub iptables -D FORWARD $j
    in_ns pub iptables -D DOCKER-USER $j
done
in_ns pub iptables -t mangle -D INPUT -i glmesh0 -j GHOSTLINK-MESH-GUARD-IN
in_ns pub iptables -t mangle -D FORWARD -i glmesh0 -j GHOSTLINK-MESH-GUARD-FWD
# relay opens a connection meanwhile and keeps it, sending a byte every half second and noting
# whether the echo comes back.
in_ns relay python3 -c '
import socket, sys, time
c = socket.create_connection((sys.argv[1], 9001), timeout=4); c.settimeout(1.5)
with open(sys.argv[2], "a", buffering=1) as out:
    while True:
        try:
            c.sendall(b"x"); ok = c.recv(1) == b"x"
        except OSError:
            ok = False
        out.write("ok\n" if ok else "fail\n"); time.sleep(0.5)
' "$(address pub)" "$work/held.txt" >/dev/null 2>&1 & held=$!; pids+=($held)
wait_for 15 "relay's connection carries data while the rules are missing" grep -q '^ok$' "$work/held.txt"
kill -CONT "${agent[pub]}"
guard_jump() { in_ns pub iptables -t mangle -C FORWARD -i glmesh0 -j GHOSTLINK-MESH-GUARD-FWD 2>/dev/null; }
wait_for 60 "pub's agent puts its rules back" guard_jump
stopped() { [ "$(tail -n 3 "$work/held.txt" | sort -u)" = fail ]; }
wait_for 20 "relay's connection stops carrying data once the rules are back" stopped
oks=$(grep -c '^ok$' "$work/held.txt")
sleep 5
[ "$(grep -c '^ok$' "$work/held.txt")" = "$oks" ] || fail "the connection relay opened while the rules were missing carries data again"
kill "$held"
wait_for 20 "web (nata) still reaches pub's published port" published nata
admin mesh rules clear

step "Shared subnet only after approval"
if reaches relay 192.168.50.10; then fail "the subnet was reachable before approval"; fi
admin mesh nodes | grep -q "1 waiting" || fail "the offered subnet is not listed as waiting"
admin mesh approve pub
wait_for 30 "relay reaches 192.168.50.10 behind pub" reaches relay 192.168.50.10
wait_for 30 "natb reaches 192.168.50.10 behind pub" reaches natb 192.168.50.10
wait_for 30 "relay reaches pub's own address in the subnet it shares" reaches relay 192.168.50.1

step "Disable and remove"
admin mesh node natb --disable
wait_for 20 "a disabled node loses its interface" bash -c "! ip netns exec natb ip link show glmesh0 >/dev/null 2>&1"
if reaches pub 100.96.0.4; then fail "a disabled node is still reachable"; fi
admin mesh node natb --enable
wait_for 40 "re-enabled node is back" reaches pub "$(address natb)"
admin mesh remove nata
wait_for 20 "a removed node's agent cleans up and stops" bash -c "! ip netns exec nata ip link show glmesh0 >/dev/null 2>&1 && [ ! -e '$work/nata/node.json' ]"
wait_for 20 "peers drop the removed node" bash -c "! ip netns exec pub wg show glmesh0 allowed-ips | grep -q 100.96.0.3/32"

step "An interface deleted under its agent comes back"
in_ns pub ip link del glmesh0
wait_for 45 "pub's agent creates its interface again" reaches relay "$(address pub)"

step "The agent puts its firewall back after a firewall reload"
# A reload that replaces the filter table (iptables-restore, netfilter-persistent) drops the agent's chains.
printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n' | in_ns natb iptables-restore
has_jump() { in_ns natb iptables -C INPUT -i glmesh0 -j GHOSTLINK-MESH-IN 2>/dev/null; }
has_jump && fail "the reload left the mesh jump in place"
wait_for 60 "natb's agent restores its firewall" has_jump

step "Stopping an agent leaves its host clean"
kill "${agent[pub]}"
wait_for 15 "the stopped agent exits" bash -c "! kill -0 ${agent[pub]} 2>/dev/null"
in_ns pub ip link show glmesh0 >/dev/null 2>&1 && fail "glmesh0 left behind"
in_ns pub iptables-save | grep -q GHOSTLINK-MESH && fail "firewall chains left behind"
grep -q "mesh" "/etc/netns/pub/hosts" && fail "/etc/hosts block left behind"
step "Mesh end-to-end passed"
