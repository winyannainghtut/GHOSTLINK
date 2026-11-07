#!/usr/bin/env bash
# End-to-end IKEv2/IPsec test on a Linux host with Docker (CI runners). It installs the
# ghostlink-server .deb, enables the IPsec component, and connects a strongSwan client, in its own
# network namespace, with exactly the parameters of each downloaded Apple profile:
#   IKEv2 + username/password (EAP-MSCHAPv2), IKEv2 + certificate,
#   IPsec (IKEv1) + certificate + XAuth, IPsec + shared group key + XAuth (Aggressive Mode).
# Through each tunnel: NAT to an "internet" host works, a blocked port and this host are refused,
# DNS goes through the server's site blocks. Then: disabled users, removed keys, wrong passwords
# and data limits are refused, usage is counted, and "ipsec disable" leaves the host clean.
# Usage: sudo tests/ipsec/interop.sh path/to/ghostlink-server_*.deb
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
deb=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
state=/var/lib/ghostlink-server
step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    status=$?
    set +e
    if [ $status -ne 0 ]; then
        echo "--- agent log"; docker logs --tail 120 ghostlink-ipsec 2>&1
        echo "--- client log"; docker logs --tail 120 glclient 2>&1
        echo "--- server log"; docker logs --tail 40 ghostlink-server 2>&1
        echo "--- status"; cat "$state/ipsec/status.json" 2>/dev/null
        echo "--- firewall"; iptables-save 2>/dev/null | grep -i ghostlink
    fi
    docker rm -f glclient >/dev/null 2>&1
    [ -n "${web_pids:-}" ] && kill $web_pids 2>/dev/null
    ip netns del gli 2>/dev/null
    ip link del glh0 2>/dev/null
    rm -rf -- "$work"
    exit $status
}
trap cleanup EXIT

# The server's address (10.99.0.1) must exist before anything calls its API.
ip link add glh0 type veth peer name glc0
ip addr add 10.99.0.1/24 dev glh0 && ip link set glh0 up

step "Install the server package and enable the IPsec component"
GHOSTLINK_SERVER_HOSTNAME=10.99.0.1 apt-get install -y "$deb" >/dev/null
ghostlink-server ipsec enable | tee "$work/enable.txt"
grep -q "UDP 500 and UDP 4500" "$work/enable.txt"
ghostlink-server ipsec status | tee "$work/status.txt"
grep -q "running: true" "$work/status.txt"
docker inspect ghostlink-ipsec --format 'readonly={{.HostConfig.ReadonlyRootfs}} drop={{.HostConfig.CapDrop}} add={{.HostConfig.CapAdd}} user={{.Config.User}} net={{.HostConfig.NetworkMode}} nnp={{.HostConfig.SecurityOpt}}' | tee "$work/container.txt"
grep -Eq '^readonly=true drop=\[ALL\] add=\[[A-Z_ ]+\] user=0:[0-9]+ net=host nnp=\[no-new-privileges\]$' "$work/container.txt" ||
    fail "IPsec container is not hardened as expected"
added=$(sed -n 's/.* add=\[\([^]]*\)\].*/\1/p' "$work/container.txt" | tr ' ' '\n' | sed 's/^CAP_//' | sort | tr '\n' ' ')
test "$added" = "NET_ADMIN NET_BIND_SERVICE NET_RAW " || fail "unexpected capabilities: $added"
test "$(stat -c %a "$state/ipsec")" = 770
test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 && test -f /etc/sysctl.d/90-ghostlink-ipsec.conf

key=$(ghostlink-server show-key | grep '^{')
url=$(echo "$key" | jq -r .apiUrl)
api() { # METHOD PATH [JSON]
    curl -sk --fail-with-body --connect-timeout 5 --max-time 90 -X "$1" ${3:+-d "$3"} "$url$2"
}
api PATCH /server '{"protocols":{"ikev2":{"enabled":true},"ipsec":{"enabled":true}}}' | jq -e '.protocols.ikev2.enabled and .protocols.ipsec.enabled and .ipsec_component.running' >/dev/null
api PUT /rules '{"blocked_domains":["blocked.example"],"blocked_ports":["8081"]}' >/dev/null
user=$(api POST /users '{"name":"Phone"}' | jq -r .id)
declare -A key_id
for spec in ikev2-eap:ikev2:eap ikev2-cert:ikev2:certificate ipsec-cert:ipsec:certificate ipsec-psk:ipsec:psk ikev2-wrong:ikev2:eap; do
    IFS=: read -r name protocol auth <<<"$spec"
    created=$(api POST "/users/$user/keys" "{\"protocol\":\"$protocol\",\"auth\":\"$auth\"}")
    key_id[$name]=$(echo "$created" | jq -r .id)
    curl -sk --fail --max-time 60 -o "$work/$name.mobileconfig" -w '%{content_type}\n' "$url/users/$user/keys/${key_id[$name]}/profile" | grep -qx 'application/x-apple-aspen-config'
done
api POST "/users/$user/keys" '{"protocol":"ipsec","auth":"psk"}' | jq -e '.warning | test("weak")' >/dev/null

step "Client configuration from the profiles"
python3 "$here/client_config.py" "$work/client" \
    ikev2-eap="$work/ikev2-eap.mobileconfig" ikev2-cert="$work/ikev2-cert.mobileconfig" \
    ipsec-cert="$work/ipsec-cert.mobileconfig" ipsec-psk="$work/ipsec-psk.mobileconfig" \
    ikev2-wrong="$work/ikev2-wrong.mobileconfig" --wrong ikev2-wrong
chmod -R a+rX "$work/client"

step "Network: client namespace (10.99.0.2) and an internet host (198.51.100.10)"
image=$(sed -n 's/^IPSEC_IMAGE=//p' /usr/lib/ghostlink-server/image.env)
docker run --detach --name glclient --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
    --cap-add NET_BIND_SERVICE --read-only --tmpfs /run --volume "$work/client:/client:ro" \
    --env STRONGSWAN_CONF=/client/strongswan.conf --env SWANCTL_DIR=/client/swanctl \
    --entrypoint /usr/lib/strongswan/charon "$image" >/dev/null
pid=$(docker inspect --format '{{.State.Pid}}' glclient)
in_client() { nsenter --target "$pid" --net "$@"; }
ip link set glc0 netns "$pid"
in_client ip addr add 10.99.0.2/24 dev glc0
in_client ip link set glc0 up
in_client ip link set lo up
in_client ip route add default via 10.99.0.1
ip netns add gli
ip link add glih0 type veth peer name gli0
ip link set gli0 netns gli
ip addr add 198.51.100.1/24 dev glih0 && ip link set glih0 up
ip netns exec gli ip addr add 198.51.100.10/24 dev gli0
ip netns exec gli ip link set gli0 up
ip netns exec gli ip link set lo up
mkdir -p "$work/www" && echo ghostlink-ok > "$work/www/index.html"
web_pids=""
for port in 8080 8081; do
    ip netns exec gli python3 -m http.server "$port" --bind 198.51.100.10 --directory "$work/www" >/dev/null 2>&1 &
    web_pids="$web_pids $!"
done
sleep 1
ip netns exec gli curl -s --max-time 3 http://198.51.100.10:8080/ | grep -q ghostlink-ok
for i in $(seq 1 20); do docker exec glclient swanctl --stats >/dev/null 2>&1 && break; sleep 0.5; done
docker exec glclient swanctl --load-all --noprompt

swan() { docker exec glclient swanctl "$@"; }
api_port=$(echo "$url" | sed 's|https://[^:]*:\([0-9]*\)/.*|\1|')
check_tunnel() { # NAME GATEWAY
    in_client curl -s --max-time 8 http://198.51.100.10:8080/ | grep -q ghostlink-ok || fail "$1: no internet through the tunnel"
    if in_client curl -s --max-time 4 http://198.51.100.10:8081/ >/dev/null; then fail "$1: blocked port 8081 reachable"; fi
    if in_client curl -sk --max-time 4 "https://10.99.0.1:$api_port/" >/dev/null; then fail "$1: the server itself is reachable from the VPN"; fi
    test "$(in_client python3 "$here/dnsquery.py" "$2" www.blocked.example)" = NXDOMAIN || fail "$1: DNS at $2 does not apply site blocks"
    # Any resolver is redirected to the server's DNS.
    test "$(in_client python3 "$here/dnsquery.py" 198.51.100.10 www.blocked.example)" = NXDOMAIN || fail "$1: other resolvers are not redirected"
    for i in $(seq 1 12); do
        api GET /server | jq -e '.ipsec_component.connections >= 1' >/dev/null && return 0
        sleep 1
    done
    fail "$1: the server does not count the connection"
}
connect() { swan --initiate --child "$1" --timeout 40 >"$work/initiate-$1.log" 2>&1 || { cat "$work/initiate-$1.log"; fail "$1 did not connect"; }; }
refused() { if swan --initiate --child "$1" --timeout 25 >"$work/refused-$1.log" 2>&1; then fail "$1 connected but should be refused ($2)"; fi; swan --terminate --ike "$1" --timeout 10 >/dev/null 2>&1 || true; }
wait_applied() {
    for i in $(seq 1 30); do
        want=$(jq .generation "$state/ipsec/desired.json")
        got=$(jq .applied_generation "$state/ipsec/status.json" 2>/dev/null || echo 0)
        [ "$want" = "$got" ] && return 0
        sleep 1
    done
    fail "the agent did not apply the new settings"
}

wait_applied
for spec in ikev2-eap:10.79.0.1 ikev2-cert:10.79.0.1 ipsec-cert:10.80.0.1 ipsec-psk:10.80.0.1; do
    IFS=: read -r name gateway <<<"$spec"
    step "Connect with $name"
    connect "$name"
    swan --list-sas | tee "$work/sas-$name.txt" | grep -q ESTABLISHED
    check_tunnel "$name" "$gateway"
    swan --terminate --ike "$name" --timeout 15 >/dev/null
done

step "Refusals: wrong password, disabled user, removed key"
refused ikev2-wrong "wrong password"
connect ikev2-eap
api PATCH "/users/$user" '{"enabled":false}' >/dev/null
wait_applied
for i in $(seq 1 15); do swan --list-sas | grep -q ESTABLISHED || break; sleep 1; done
swan --list-sas | grep -q ESTABLISHED && fail "a disabled user's session was not ended"
refused ikev2-cert "certificate of a disabled user (on hold)"
refused ipsec-psk "disabled user"
api PATCH "/users/$user" '{"enabled":true}' >/dev/null
wait_applied
connect ikev2-cert
swan --terminate --ike ikev2-cert --timeout 15 >/dev/null
api DELETE "/users/$user/keys/${key_id[ikev2-cert]}" >/dev/null
wait_applied
refused ikev2-cert "removed key (revoked certificate)"

step "Speed limit: a capped client is held to its rate, and the cap lifts at once"
head -c 1500000 /dev/urandom > "$work/www/big.bin"
download() { in_client curl -s --fail --max-time 40 -o /dev/null -w '%{time_total}' http://198.51.100.10:8080/big.bin; }
limit_rules() { iptables-save | grep -c "GHOSTLINK-IPSEC-LIM .*hashlimit-above ${1:-300000}b/s" || true; }
connect ikev2-eap
fast=$(download) || fail "no download through the tunnel"
api PATCH "/users/$user" '{"speed_limit_bps":300000}' >/dev/null
wait_applied
for i in $(seq 1 20); do [ "$(limit_rules)" = 2 ] && break; sleep 1; done
[ "$(limit_rules)" = 2 ] || { iptables-save | grep GHOSTLINK-IPSEC-LIM; fail "the session has no speed limit rules"; }
slow=$(download) || fail "no download through the tunnel with a speed limit"
# 1.5 MB at 300 KB/s: about 5 s, less up to a second of burst; policing (dropping) can only be slower.
python3 -c 'import sys; f, s = map(float, sys.argv[1:]); sys.exit(0 if 2.5 <= s <= 30 and s > 2 * f else 1)' "$fast" "$slow" ||
    fail "1.5 MB took ${slow} s capped at 300 KB/s (${fast} s without a cap)"
echo "1.5 MB: ${fast} s without a cap, ${slow} s at 300 KB/s"
# A new cap applies to the session that is still connected (the kernel keeps a hashlimit
# table's first rate, so the rules must move to a new table).
api PATCH "/users/$user" '{"speed_limit_bps":600000}' >/dev/null
wait_applied
for i in $(seq 1 20); do iptables-save | grep -q 'GHOSTLINK-IPSEC-LIM .*hashlimit-above 600000b/s' && break; sleep 1; done
iptables-save | grep -q 'GHOSTLINK-IPSEC-LIM .*hashlimit-above 600000b/s' || fail "the raised cap has no rules"
raised=$(download) || fail "no download through the tunnel with the raised cap"
python3 -c 'import sys; s, r = map(float, sys.argv[1:]); sys.exit(0 if r < s * 0.8 else 1)' "$slow" "$raised" ||
    fail "raising the cap to 600 KB/s did not speed the connected session up (${raised} s, was ${slow} s)"
echo "1.5 MB: ${raised} s at 600 KB/s, same session"
api PATCH "/users/$user" '{"speed_limit_bps":0}' >/dev/null
wait_applied
for i in $(seq 1 20); do [ "$(limit_rules "[0-9]*")" = 0 ] && break; sleep 1; done
[ "$(limit_rules "[0-9]*")" = 0 ] || fail "the speed limit rules stayed after the cap was removed"
swan --terminate --ike ikev2-eap --timeout 15 >/dev/null

step "Usage is counted and the data limit cuts the user off"
connect ipsec-cert
in_client curl -s --max-time 10 -o /dev/null http://198.51.100.10:8080/
for i in $(seq 1 25); do
    used=$(api GET "/users/$user" | jq .usage_bytes)
    [ "$used" -gt 0 ] && break
    sleep 2
done
[ "$used" -gt 0 ] || fail "IPsec traffic was not counted"
# One record per address, with the protocol it last used.
clients=$(api GET "/clients?user=$user")
echo "$clients" | jq -e 'any(.clients[]; .ip == "10.99.0.2" and (.protocol == "ikev2" or .protocol == "ipsec"))' >/dev/null || fail "client log lacks the IPsec client: $clients"
# Every session counted, including short ones that ended between reports.
stats=$(api GET "/stats?range=24h&user=$user")
echo "$stats" | jq -e 'any(.protocols[]; .label == "ikev2" and .bytes > 0) and any(.protocols[]; .label == "ipsec" and .bytes > 0) and any(.types[]; .label == "IPsec (not inspected)")' >/dev/null ||
    fail "statistics lack IKEv2/IPsec traffic: $stats"
api PATCH "/users/$user" "{\"data_limit_bytes\":$used}" >/dev/null
in_client curl -s --max-time 5 -o /dev/null http://198.51.100.10:8080/ || true
for i in $(seq 1 40); do swan --list-sas | grep -q ESTABLISHED || break; sleep 2; done
swan --list-sas | grep -q ESTABLISHED && fail "an over-limit user stayed connected"
api GET "/users/$user" | jq -e .over_limit >/dev/null

step "No secrets in logs"
for name in ikev2-eap ipsec-psk; do
    secret=$(python3 -c 'import plistlib,sys; p=plistlib.load(open(sys.argv[1],"rb")); v=[x for x in p["PayloadContent"] if x["PayloadType"]=="com.apple.vpn.managed"][0]; s=v[v["VPNType"]]; print(s.get("AuthPassword") or s.get("XAuthPassword"))' "$work/$name.mobileconfig")
    if docker logs ghostlink-ipsec 2>&1 | grep -qF "$secret"; then fail "the agent logged a password"; fi
done

step "Disable: the host is left clean"
ghostlink-server ipsec disable
if iptables-save | grep -q GHOSTLINK-IPSEC; then fail "firewall chains left behind"; fi
if ip link show glipsec0 >/dev/null 2>&1; then fail "glipsec0 left behind"; fi
test ! -e /etc/sysctl.d/90-ghostlink-ipsec.conf
ghostlink-server ipsec status | grep -q "not installed"
apt-get purge -y ghostlink-server >/dev/null
step "IPsec interop passed"
