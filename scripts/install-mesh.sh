#!/usr/bin/env bash
# Ghostlink mesh installer: installs the ghostlink-mesh agent from the newest published release
# and joins this Linux server to a mesh. The Ghostlink app (Servers I run > Manage > Network >
# Mesh > Add node) and `ghostlink-server mesh invite` print the full command, for example:
#
#   curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-mesh.sh | sudo bash -s -- --join 'glmesh1:...'
set -euo pipefail

REPO=winyannainghtut/GHOSTLINK
work=""

usage() {
    cat <<EOF
Join this Linux server to a Ghostlink mesh.

  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install-mesh.sh | sudo bash -s -- --join 'glmesh1:...'

It detects Debian/Ubuntu (.deb) or Fedora/RHEL family (.rpm) on x86_64 or arm64, checks that the
kernel has WireGuard, installs the ghostlink-mesh package (verified against the release's
SHA256SUMS.txt), joins with the invite and starts the agent. Run it again to upgrade the agent;
without --join it only installs or upgrades it (then, on the coordinator itself:
sudo ghostlink-server mesh join-here).

Options:
  --join INVITE              the invite (glmesh1:...) from the Ghostlink app or server; it can
                             also come from the GHOSTLINK_MESH_INVITE environment variable
  --name NAME                node name (default: this machine's host name)
  --advertise-routes CIDR,.. offer subnets behind this server (approved in the app)
  --relay                    allow this server to relay for nodes behind NAT
  --endpoint IP:PORT         public address, when it can't be detected
  --port N                   WireGuard UDP port (default 51820)
  --no-hosts                 do not add <node>.mesh names to /etc/hosts
  --open-firewall            allow the WireGuard port in an active ufw or firewalld, and with
                             firewalld put the mesh interface in its trusted zone
  --version X.Y.Z            install this release instead of the newest published one
  --package FILE             install a ghostlink-mesh .deb/.rpm you already downloaded
  -h, --help                 show this help
EOF
}

if [ -t 1 ]; then bold=$'\033[1m' red=$'\033[31m' reset=$'\033[0m'; else bold='' red='' reset=''; fi
say() { printf '%s==> %s%s\n' "$bold" "$*" "$reset"; }
die() { printf '%serror:%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }
cleanup() { [ -z "$work" ] || rm -rf -- "$work"; }
trap cleanup EXIT

main() {
    # An invite in the environment stays out of the process list and sudo's log.
    local invite=${GHOSTLINK_MESH_INVITE:-} version="" package="" open_firewall=0 port=51820
    unset GHOSTLINK_MESH_INVITE
    local join_args=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --join) [ $# -ge 2 ] || die "--join needs the invite"; invite=$2; shift 2 ;;
            --join=*) invite=${1#--join=}; shift ;;
            --name | --advertise-routes | --endpoint)
                [ $# -ge 2 ] || die "$1 needs a value"; join_args+=("$1" "$2"); shift 2 ;;
            --port) [ $# -ge 2 ] || die "--port needs a value"; port=$2; join_args+=(--port "$2"); shift 2 ;;
            --relay | --no-hosts) join_args+=("$1"); shift ;;
            --open-firewall) open_firewall=1; shift ;;
            --version) [ $# -ge 2 ] || die "--version needs a value"; version=${2#v}; shift 2 ;;
            --package) [ $# -ge 2 ] || die "--package needs a file"; package=$2; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) die "unknown option $1 (see --help)" ;;
        esac
    done
    exec </dev/null
    [ "$(id -u)" = 0 ] || die "run as root: ... | sudo bash -s -- --join 'glmesh1:...'"
    [ "$(uname -s)" = Linux ] || die "the Ghostlink mesh agent runs on Linux only (Windows is planned)"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "--port must be 1-65535"
    if [ -n "$version" ] && ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then die "--version must look like 0.6.0"; fi
    if [ -n "$package" ]; then
        [ -f "$package" ] || die "$package does not exist"
        package=$(cd "$(dirname "$package")" && pwd)/$(basename "$package")
    fi
    [ -z "$invite" ] || [[ "$invite" == glmesh1:* ]] || die "the invite starts with glmesh1:"
    local joined=0
    [ -f /var/lib/ghostlink-mesh/node.json ] && joined=1
    if [ -n "$invite" ] && [ "$joined" = 1 ]; then
        # Running the join command again upgrades the agent: the invite is not needed.
        say "This server is already in a mesh, so the invite is not used; upgrading the agent only"
        echo "    (to join another mesh, leave this one first: sudo ghostlink-mesh leave)"
        invite=""
    fi

    # shellcheck source=/dev/null
    . /etc/os-release
    local family="" os_id=${ID:-unknown}
    case " $os_id ${ID_LIKE:-} " in
        *" debian "* | *" ubuntu "*) family=deb ;;
        *" fedora "* | *" rhel "* | *" centos "* | *" rocky "* | *" almalinux "* | *" ol "* | *" amzn "*) family=rpm ;;
        *) die "unsupported distribution '${PRETTY_NAME:-$os_id}'" ;;
    esac
    local deb_arch rpm_arch
    case "$(uname -m)" in
        x86_64 | amd64) deb_arch=amd64 rpm_arch=x86_64 ;;
        aarch64 | arm64) deb_arch=arm64 rpm_arch=aarch64 ;;
        *) die "unsupported CPU architecture $(uname -m)" ;;
    esac
    say "System: ${PRETTY_NAME:-$os_id}, $(uname -m), kernel $(uname -r)"
    export DEBIAN_FRONTEND=noninteractive

    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v jq >/dev/null 2>&1 || missing+=(jq)
    command -v iptables >/dev/null 2>&1 || missing+=(iptables)
    if [ ${#missing[@]} -gt 0 ]; then
        say "Installing ${missing[*]}"
        pkg_install "$family" "${missing[@]}"
    fi

    # Kernel WireGuard (Linux 5.6+, or the wireguard module).
    modprobe wireguard >/dev/null 2>&1 || true
    if ! ip link add glmeshtest0 type wireguard >/dev/null 2>&1; then
        die "this kernel has no WireGuard support (Linux 5.6 or newer is needed). Container-based VPS types (OpenVZ, LXC) usually lack it; use a KVM VPS or a dedicated server."
    fi
    ip link del glmeshtest0 >/dev/null 2>&1 || true

    local file installed=""
    command -v ghostlink-mesh >/dev/null 2>&1 && installed=$(ghostlink-mesh version 2>/dev/null | sed 's/^Ghostlink mesh agent //')
    if [ -n "$package" ]; then
        file=$(basename "$package")
        version=$(printf '%s\n' "$file" | sed -E -e 's/^ghostlink-mesh[_-]//' -e 's/-1(_[a-z0-9]+\.deb|\.[a-z0-9_]+\.rpm)$//')
    else
        if [ -z "$version" ]; then
            version=$(curl -fsSL --retry 3 "https://api.github.com/repos/$REPO/releases?per_page=20" |
                jq -r '[.[] | select(.draft | not) | .tag_name | select(test("^v[0-9]"))][0] // empty' | sed 's/^v//') || true
            [ -n "$version" ] || die "no published Ghostlink release was found"
        fi
        if [ "$family" = deb ]; then file="ghostlink-mesh_${version}-1_${deb_arch}.deb"; else file="ghostlink-mesh-${version}-1.${rpm_arch}.rpm"; fi
    fi
    if [ "$installed" != "$version" ]; then
        say "Installing the Ghostlink mesh agent $version"
        if [ -z "$package" ]; then
            work=$(mktemp -d)
            local base="https://github.com/$REPO/releases/download/v$version"
            curl -fL --retry 3 --progress-bar -o "$work/$file" "$base/$file" || die "could not download $base/$file"
            curl -fsSL --retry 3 -o "$work/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || die "could not download the release checksums"
            awk -v f="$file" '$2 == f || $2 == "*" f' "$work/SHA256SUMS.txt" > "$work/expected.txt"
            [ -s "$work/expected.txt" ] || die "SHA256SUMS.txt does not list $file"
            (cd "$work" && sha256sum --check --status expected.txt) || die "checksum mismatch for $file; not installing it"
            package="$work/$file"
        fi
        if [ "$family" = deb ]; then
            apt-get install -y -o Dpkg::Options::=--force-confold "$package" >/dev/null
        else
            pkg_manager install -y "$package" >/dev/null
        fi
    fi

    if [ -n "$invite" ]; then
        say "Joining the mesh"
        # Bash before 4.4 (Amazon Linux 2, EL7) calls an empty array unbound under set -u.
        GHOSTLINK_MESH_INVITE="$invite" ghostlink-mesh join ${join_args[@]+"${join_args[@]}"}
    fi
    # Before the agent starts: a firewalld reload can remove the agent's iptables rules.
    [ "$open_firewall" = 0 ] || open_host_firewall "$port"
    if [ ! -f /var/lib/ghostlink-mesh/node.json ]; then
        cat <<EOF

The Ghostlink mesh agent $version is installed; this server is not in a mesh yet. Join it with
the command from the Ghostlink app or from \`sudo ghostlink-server mesh invite\`, or, on the
coordinator itself: sudo ghostlink-server mesh join-here
EOF
        return
    fi
    systemctl enable --now ghostlink-mesh.service >/dev/null
    systemctl restart ghostlink-mesh.service
    for _ in $(seq 1 30); do
        state=$(ghostlink-mesh status --json 2>/dev/null | jq -r '.status.state // empty')
        [ "$state" = active ] || [ "$state" = pending ] && break
        sleep 1
    done
    echo
    ghostlink-mesh status || true
    cat <<EOF

If this server has a public address, allow UDP $port in its firewall and cloud security group so
other nodes connect directly (behind NAT nothing is needed; traffic then uses the relay).
Check any time with: sudo ghostlink-mesh status
EOF
    if [ "$open_firewall" = 0 ] && firewalld_running; then
        cat <<EOF
firewalld is running: it refuses mesh traffic other than ping and SSH until the mesh interface is
trusted. Run this installer again with --open-firewall, or:
  sudo firewall-cmd --permanent --zone=trusted --change-interface=$(mesh_interface) && sudo firewall-cmd --reload
EOF
    fi
}

firewalld_running() { command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; }

mesh_interface() { jq -r '.interface // "glmesh0"' /var/lib/ghostlink-mesh/node.json 2>/dev/null || echo glmesh0; }

# open_host_firewall allows the WireGuard port in an active ufw or firewalld. With firewalld the
# mesh interface also goes into the trusted zone: its own nftables table would otherwise reject
# mesh traffic that the agent's iptables chains accept (a packet has to pass both). The agent's
# chains still enforce the mesh's access rules.
open_host_firewall() {
    local port=$1 iface
    iface=$(mesh_interface)
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        if ufw allow "$port/udp" comment 'Ghostlink mesh' >/dev/null; then
            say "Allowed UDP $port in ufw"
        else
            echo "warning: could not allow UDP $port in ufw" >&2
        fi
    elif firewalld_running; then
        if firewall-cmd --permanent --add-port="$port/udp" >/dev/null &&
            firewall-cmd --permanent --zone=trusted --change-interface="$iface" >/dev/null &&
            firewall-cmd --reload >/dev/null; then
            say "Allowed UDP $port in firewalld, and put $iface in its trusted zone"
        else
            echo "warning: could not change firewalld; allow UDP $port and trust $iface yourself" >&2
        fi
    fi
}

pkg_manager() {
    if command -v dnf >/dev/null 2>&1; then dnf "$@"; else yum "$@"; fi
}

pkg_install() {
    local family=$1
    shift
    if [ "$family" = deb ]; then
        apt-get update -qq
        apt-get install -y -qq "$@" >/dev/null
    else
        pkg_manager install -y -q "$@" >/dev/null
    fi
}

main "$@"
