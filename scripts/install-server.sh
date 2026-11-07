#!/usr/bin/env bash
# Ghostlink server installer for Linux: installs, or upgrades to, the newest published
# ghostlink-server release. See usage() below, or run with --help.
#
#   curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash
set -euo pipefail

REPO=winyannainghtut/GHOSTLINK
STATE=/var/lib/ghostlink-server
work=""

usage() {
    cat <<EOF
Install or upgrade the Ghostlink VPN server (Docker-based) on this Linux machine.

  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install-server.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install-server.sh | sudo bash -s -- --hostname vpn.example.com

It detects Debian/Ubuntu (.deb) or Fedora/RHEL family (.rpm) on x86_64 or arm64, installs
Docker from the distribution if needed, downloads the release package, checks it against the
release's SHA256SUMS.txt and installs it. Then it prints the management key for the Ghostlink
app and the ports to open. Running it again upgrades and keeps users, keys and rules.

Options:
  --version X.Y.Z   install this release instead of the newest published one
  --package FILE    install a ghostlink-server .deb/.rpm you already downloaded (no download)
  --hostname HOST   public IP or DNS name VPN clients use (default: keep the current one, or
                    detect this server's public IP on first install)
  --ipsec           also start the IKEv2/IPsec component (iPhone, iPad, Mac) and turn on IKEv2
  --mesh            also turn on the mesh (a private network between your Linux servers),
                    install the ghostlink-mesh agent and join this server as the relay
  --mesh-package F  with --mesh: install this ghostlink-mesh .deb/.rpm (no download)
  --open-firewall   allow the server's ports in ufw or firewalld when one is active
                    (a firewall that is off is never turned on)
  --no-docker       do not install Docker; stop if it is missing
  --reinstall       install even if this version is already installed
  --add-swap        on a server with under 1 GB of memory and swap, add a 1 GB swap file
                    (/swapfile, kept across reboots) so installing is not killed
  --migrate-outline take over the Outline server on this machine: its access keys become
                    Ghostlink clients and their ss:// keys keep working; Outline is stopped
                    (its files in /opt/outline stay as a backup)
  --migrate-outline --check
                    install Ghostlink next to Outline and only show what the migration
                    would do; Outline keeps running
  --outline-dir DIR where Outline is installed (default /opt/outline)
  -h, --help        show this help
EOF
}

if [ -t 1 ]; then bold=$'\033[1m' red=$'\033[31m' yellow=$'\033[33m' reset=$'\033[0m'; else bold='' red='' yellow='' reset=''; fi
say() { printf '%s==> %s%s\n' "$bold" "$*" "$reset"; }
warn() { printf '%swarning:%s %s\n' "$yellow" "$reset" "$*" >&2; }
die() { printf '%serror:%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }
cleanup() { [ -z "$work" ] || rm -rf -- "$work"; }
trap cleanup EXIT

main() {
    local version="" package="" hostname="" ipsec=0 open_firewall=0 docker_install=1 reinstall=0 add_swap=0
    local mesh=0 mesh_package="" migrate=0 migrate_check=0 outline_dir=/opt/outline
    while [ $# -gt 0 ]; do
        case "$1" in
            --version) [ $# -ge 2 ] || die "--version needs a value"; version=${2#v}; shift 2 ;;
            --version=*) version=${1#--version=}; version=${version#v}; shift ;;
            --package) [ $# -ge 2 ] || die "--package needs a file"; package=$2; shift 2 ;;
            --package=*) package=${1#--package=}; shift ;;
            --hostname) [ $# -ge 2 ] || die "--hostname needs a value"; hostname=$2; shift 2 ;;
            --hostname=*) hostname=${1#--hostname=}; shift ;;
            --ipsec) ipsec=1; shift ;;
            --mesh) mesh=1; shift ;;
            --mesh-package) [ $# -ge 2 ] || die "--mesh-package needs a file"; mesh=1; mesh_package=$2; shift 2 ;;
            --open-firewall) open_firewall=1; shift ;;
            --no-docker) docker_install=0; shift ;;
            --reinstall) reinstall=1; shift ;;
            --add-swap) add_swap=1; shift ;;
            --migrate-outline) migrate=1; shift ;;
            --check) migrate_check=1; shift ;;
            --outline-dir) [ $# -ge 2 ] || die "--outline-dir needs a directory"; outline_dir=$2; shift 2 ;;
            --outline-dir=*) outline_dir=${1#--outline-dir=}; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die "unknown option $1 (see --help)" ;;
        esac
    done
    # When piped (curl | bash), stdin is this script; nothing below may read it.
    exec </dev/null

    [ "$(id -u)" = 0 ] || die "run as root, for example: curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install-server.sh | sudo bash"
    [ "$(uname -s)" = Linux ] || die "the Ghostlink server runs on Linux only"
    if [ -n "$version" ] && ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
        die "--version must look like 0.7.0"
    fi
    if [ -n "$hostname" ] && ! [[ "$hostname" =~ ^[A-Za-z0-9.:-]{1,253}$ ]]; then
        die "--hostname must be an IP address or a DNS name"
    fi
    if [ -n "$package" ]; then
        [ -f "$package" ] || die "$package does not exist"
        package=$(cd "$(dirname "$package")" && pwd)/$(basename "$package")
    fi
    if [ -n "$mesh_package" ]; then
        [ -f "$mesh_package" ] || die "$mesh_package does not exist"
        mesh_package=$(cd "$(dirname "$mesh_package")" && pwd)/$(basename "$mesh_package")
    fi
    if [ "$migrate_check" = 1 ] && [ "$migrate" = 0 ]; then
        die "--check goes with --migrate-outline"
    fi
    if [ "$migrate" = 1 ] && [ ! -f "$outline_dir/persisted-state/shadowbox_config.json" ]; then
        die "no Outline server found: $outline_dir/persisted-state/shadowbox_config.json does not exist (use --outline-dir if it is elsewhere)"
    fi

    # --- this machine ---
    [ -r /etc/os-release ] || die "cannot read /etc/os-release to identify this Linux distribution"
    # shellcheck source=/dev/null
    . /etc/os-release
    local family="" os_id=${ID:-unknown}
    case " $os_id ${ID_LIKE:-} " in
        *" debian "* | *" ubuntu "*) family=deb ;;
        *" fedora "* | *" rhel "* | *" centos "* | *" rocky "* | *" almalinux "* | *" ol "* | *" amzn "*) family=rpm ;;
        *) die "unsupported distribution '${PRETTY_NAME:-$os_id}'. Supported: Debian, Ubuntu and derivatives; Fedora, RHEL, CentOS Stream, Rocky, AlmaLinux, Oracle Linux, Amazon Linux" ;;
    esac
    local deb_arch rpm_arch
    case "$(uname -m)" in
        x86_64 | amd64) deb_arch=amd64 rpm_arch=x86_64 ;;
        aarch64 | arm64) deb_arch=arm64 rpm_arch=aarch64 ;;
        *) die "unsupported CPU architecture $(uname -m); the server is built for x86_64 and arm64" ;;
    esac
    say "System: ${PRETTY_NAME:-$os_id}, $(uname -m)"
    export DEBIAN_FRONTEND=noninteractive

    # --- tools: curl, jq, sha256sum, CA certificates ---
    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v jq >/dev/null 2>&1 || missing+=(jq)
    command -v sha256sum >/dev/null 2>&1 || missing+=(coreutils)
    [ -e /etc/ssl/certs/ca-certificates.crt ] || [ -e /etc/pki/tls/certs/ca-bundle.crt ] || missing+=(ca-certificates)
    if [ ${#missing[@]} -gt 0 ]; then
        say "Installing ${missing[*]}"
        pkg_install "$family" "${missing[@]}"
    fi

    # --- memory: Docker, the server and apt together need about 1 GB, counting swap ---
    local memory_mb
    memory_mb=$(awk '/^(MemTotal|SwapTotal):/ { kb += $2 } END { print int(kb / 1024) }' /proc/meminfo)
    if [ "$memory_mb" -lt 900 ]; then
        if [ "$add_swap" = 1 ]; then
            add_swap_file
        else
            die "this server has only $memory_mb MB of memory and swap, so the kernel may kill the installation (the output then says 'Killed'). Run this again with --add-swap to add a 1 GB swap file, or add swap yourself."
        fi
    fi

    # --- Docker ---
    if [ "$(command -v docker 2>/dev/null)" = /snap/bin/docker ]; then
        die "Docker from the Snap store cannot use /var/lib/ghostlink-server. Remove it (snap remove docker) and run this again; the distribution's Docker will be installed"
    fi
    if ! command -v docker >/dev/null 2>&1; then
        [ "$docker_install" = 1 ] || die "Docker is not installed (and --no-docker was given)"
        install_docker "$family" "$os_id"
    fi
    if ! docker info >/dev/null 2>&1; then
        if command -v systemctl >/dev/null 2>&1; then
            say "Starting Docker"
            systemctl enable --now docker >/dev/null 2>&1 || true
        fi
        docker info >/dev/null 2>&1 || die "Docker is installed but not running; start it (for example: systemctl start docker) and run this again"
    fi
    say "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '(unknown version)') is running"

    # --- which package ---
    local file
    if [ -n "$package" ]; then
        file=$(basename "$package")
        case "$family:$file" in
            deb:ghostlink-server_*_"$deb_arch".deb | rpm:ghostlink-server-*."$rpm_arch".rpm) ;;
            *) die "$file is not a ghostlink-server package for this system (expected a .$family for $(uname -m))" ;;
        esac
        # ghostlink-server_<version>-1_<arch>.deb or ghostlink-server-<version>-1.<arch>.rpm
        version=$(printf '%s\n' "$file" | sed -E -e 's/^ghostlink-server[_-]//' -e 's/-1(_[a-z0-9]+\.deb|\.[a-z0-9_]+\.rpm)$//')
    else
        if [ -z "$version" ]; then
            version=$(newest_release) || true
            [ -n "$version" ] || die "no published Ghostlink release was found at https://github.com/$REPO/releases. New releases start as drafts; publish one (Releases > Edit > Publish release), or pass --version for a published release."
        fi
        if [ "$family" = deb ]; then file="ghostlink-server_${version}-1_${deb_arch}.deb"; else file="ghostlink-server-${version}-1.${rpm_arch}.rpm"; fi
    fi
    local installed=""
    if command -v ghostlink-server >/dev/null 2>&1; then
        installed=$(ghostlink-server version 2>/dev/null || true)
    fi
    # Finish an installation that was interrupted (for example killed for lack of memory).
    if [ "$family" = deb ] && dpkg-query -W -f='${Status}' ghostlink-server 2>/dev/null | grep -qv 'install ok installed'; then
        say "Finishing an interrupted installation"
        dpkg --configure -a
    fi

    # --- install or upgrade ---
    # The package's post-install loads the bundled images, creates or upgrades the server and
    # prints the management key. It reads the address from GHOSTLINK_SERVER_HOSTNAME.
    [ -z "$hostname" ] || export GHOSTLINK_SERVER_HOSTNAME="$hostname"
    if [ "$installed" = "$version" ] && [ "$reinstall" = 0 ]; then
        say "Ghostlink server $version is already installed"
    else
        if [ -n "$installed" ]; then say "Upgrading Ghostlink server $installed to $version"; else say "Installing Ghostlink server $version"; fi
        if [ -z "$package" ]; then
            download_verified "$version" "$file"
            package="$work/$file"
        fi
        if [ "$family" = deb ]; then
            apt-get install -y -o Dpkg::Options::=--force-confold "$package" || die "installing the package failed. If the output says 'Killed', the server ran out of memory: run this again with --add-swap"
        else
            pkg_manager install -y "$package" || die "installing the package failed. If the output says 'Killed', the server ran out of memory: run this again with --add-swap"
        fi
        command -v ghostlink-server >/dev/null 2>&1 || die "the package did not install ghostlink-server"
    fi

    # --- running, with the requested address ---
    local current="" running
    [ -f "$STATE/state.json" ] && current=$(jq -r '.hostname // empty' "$STATE/state.json" 2>/dev/null || true)
    running=$(docker inspect --format '{{.State.Running}}' ghostlink-server 2>/dev/null || true)
    if [ "$running" != true ] || { [ -n "$hostname" ] && [ "$hostname" != "$current" ]; }; then
        say "Running setup${hostname:+ for $hostname}"
        if [ -n "$hostname" ]; then ghostlink-server setup --hostname "$hostname" >/dev/null; else ghostlink-server setup >/dev/null; fi
    fi
    [ "$(docker inspect --format '{{.State.Running}}' ghostlink-server 2>/dev/null || true)" = true ] ||
        die "the server container is not running; see: sudo ghostlink-server logs"

    # --- optional: take over Outline ---
    if [ "$migrate" = 1 ]; then
        if [ "$migrate_check" = 1 ]; then
            say "Checking what the migration from Outline would do (Outline keeps running)"
            ghostlink-server migrate-outline --check --outline-dir "$outline_dir" || die "the check failed (see above); Outline is untouched"
            return 0
        fi
        say "Taking over the Outline server"
        ghostlink-server migrate-outline --outline-dir "$outline_dir" || die "the migration did not go through (see above); Outline is running as before"
        if [ -n "$hostname" ]; then
            # The import adopts Outline's address; the one asked for here wins.
            ghostlink-server set --hostname "$hostname" >/dev/null
        fi
    fi

    # --- optional IKEv2/IPsec ---
    if [ "$ipsec" = 1 ]; then
        say "Starting the IKEv2/IPsec component"
        if ghostlink-server ipsec enable >/dev/null && ghostlink-server set --enable ikev2 >/dev/null; then
            say "IKEv2 is on. Add a key with: sudo ghostlink-server key add NAME ikev2"
        else
            warn "the IPsec component could not start (see above); the other protocols work without it"
        fi
    fi

    # --- optional mesh: this server coordinates it and joins it as the relay ---
    local mesh_node=0
    if [ "$mesh" = 1 ]; then
        say "Turning on the mesh"
        ghostlink-server mesh enable >/dev/null || die "could not turn on the mesh; see: sudo ghostlink-server logs"
        modprobe wireguard >/dev/null 2>&1 || true
        if ! ip link add glmeshtest0 type wireguard >/dev/null 2>&1; then
            warn "this kernel has no WireGuard (Linux 5.6 or newer is needed), so this server cannot be a mesh node. It still coordinates the mesh; add other servers with: sudo ghostlink-server mesh invite"
        else
            ip link del glmeshtest0 >/dev/null 2>&1 || true
            local mesh_file
            if [ -n "$mesh_package" ]; then
                mesh_file=$(basename "$mesh_package")
                case "$family:$mesh_file" in
                    deb:ghostlink-mesh_*_"$deb_arch".deb | rpm:ghostlink-mesh-*."$rpm_arch".rpm) ;;
                    *) die "$mesh_file is not a ghostlink-mesh package for this system" ;;
                esac
            else
                if [ "$family" = deb ]; then mesh_file="ghostlink-mesh_${version}-1_${deb_arch}.deb"; else mesh_file="ghostlink-mesh-${version}-1.${rpm_arch}.rpm"; fi
                download_verified "$version" "$mesh_file"
                mesh_package="$work/$mesh_file"
            fi
            say "Installing the mesh agent"
            if [ "$family" = deb ]; then
                apt-get install -y -o Dpkg::Options::=--force-confold "$mesh_package" >/dev/null || die "installing the mesh agent failed"
            else
                pkg_manager install -y "$mesh_package" >/dev/null || die "installing the mesh agent failed"
            fi
            if [ -f /var/lib/ghostlink-mesh/node.json ]; then
                say "This server is already a mesh node; its agent is up to date"
            else
                say "Joining this server to the mesh as the relay"
                ghostlink-server mesh join-here >/dev/null || die "joining the mesh failed; see: sudo ghostlink-mesh status"
            fi
            mesh_node=1
        fi
    fi

    # --- ports ---
    local ports=()
    mapfile -t ports < <(server_ports || true)
    if [ "$mesh_node" = 1 ] || [ -f /var/lib/ghostlink-mesh/node.json ]; then
        ports+=("$(jq -r '"\(.listen_port // 51820)/udp  mesh (this server as a node)"' /var/lib/ghostlink-mesh/node.json 2>/dev/null || echo '51820/udp  mesh (this server as a node)')")
    fi
    [ ${#ports[@]} -gt 0 ] || warn "could not read the server's ports; run: sudo ghostlink-server status"
    if [ "$open_firewall" = 1 ] && [ ${#ports[@]} -gt 0 ]; then
        open_ports "${ports[@]}"
    fi

    # --- summary ---
    echo
    ghostlink-server show-key
    echo
    printf "%sAllow these ports in this server's firewall and in your cloud provider's security group:%s\n" "$bold" "$reset"
    local entry
    for entry in "${ports[@]}"; do printf '  %s\n' "$entry"; done
    if [ "$open_firewall" = 0 ]; then
        echo "  (ufw: sudo ufw allow PORT/PROTO · firewalld: sudo firewall-cmd --permanent --add-port=PORT/PROTO"
        echo "   then sudo firewall-cmd --reload · or run this installer again with --open-firewall)"
    fi
    cat <<EOF

Next steps:
  - Ghostlink app: Servers I run > Add server, then paste the management key above.
  - Or on this server:  sudo ghostlink-server user add Alice
                        sudo ghostlink-server key add Alice amneziawg
  - iPhone/iPad/Mac:    run this installer again with --ipsec, then: sudo ghostlink-server key add Alice ikev2
  - Mesh of servers:    run this installer again with --mesh, then: sudo ghostlink-server mesh invite --tags web
  - All commands:       sudo ghostlink-server help
  - Guide: https://github.com/$REPO/blob/main/docs/deployment/ghostlink-server.md
EOF
}

add_swap_file() {
    [ ! -e /swapfile ] || die "/swapfile already exists but is not enough; turn it on (swapon /swapfile) or make it larger, then run this again"
    say "Adding a 1 GB swap file (/swapfile)"
    if ! fallocate -l 1G /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
}

download_verified() { # VERSION FILE: download a release file into $work and check it against SHA256SUMS.txt
    local base="https://github.com/$REPO/releases/download/v$1" file=$2
    [ -n "$work" ] || work=$(mktemp -d)
    curl -fL --retry 3 --progress-bar -o "$work/$file" "$base/$file" ||
        die "could not download $base/$file (is v$1 published, with a package for this system?)"
    [ -s "$work/SHA256SUMS.txt" ] || curl -fsSL --retry 3 -o "$work/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || die "could not download the release checksums"
    awk -v f="$file" '$2 == f || $2 == "*" f' "$work/SHA256SUMS.txt" > "$work/expected.txt"
    [ -s "$work/expected.txt" ] || die "SHA256SUMS.txt does not list $file"
    (cd "$work" && sha256sum --check --status expected.txt) || die "checksum mismatch for $file; not installing it"
    say "Checksum of $file verified"
}

pkg_manager() {
    if command -v dnf >/dev/null 2>&1; then dnf "$@"; else yum "$@"; fi
}

pkg_install() { # FAMILY PACKAGE...
    local family=$1
    shift
    if [ "$family" = deb ]; then
        apt-get update -qq
        apt-get install -y -qq "$@" >/dev/null
    else
        pkg_manager install -y -q "$@" >/dev/null
    fi
}

install_docker() { # FAMILY OS_ID
    say "Installing Docker"
    case "$1:$2" in
        deb:*) pkg_install deb docker.io ;;
        rpm:fedora) pkg_install rpm moby-engine ;;
        rpm:amzn) pkg_install rpm docker ;;
        rpm:*)
            # RHEL, CentOS Stream, Rocky, AlmaLinux, Oracle Linux: Docker's own repository.
            curl -fsSL https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo ||
                die "could not add Docker's package repository"
            pkg_install rpm docker-ce docker-ce-cli containerd.io
            ;;
    esac
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker >/dev/null 2>&1 || true
    fi
}

newest_release() { # newest published (non-draft) release, pre-releases included
    curl -fsSL --retry 3 -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$REPO/releases?per_page=20" |
        jq -r '[.[] | select(.draft | not) | .tag_name | select(test("^v[0-9]"))][0] // empty' | sed 's/^v//'
}

server_ports() { # "PORT/PROTO  service" for everything clients connect to
    jq -r '
        ["\(.api.port)/tcp  management API (Ghostlink app)"]
        + (if .shadowsocks.enabled then ["\(.shadowsocks.port)/tcp  Shadowsocks (Outline)", "\(.shadowsocks.port)/udp  Shadowsocks (Outline)"] else [] end)
        + (if .shadowsocks.enabled then [.users[]?.keys[]? | select(.protocol == "shadowsocks" and (.port // 0) > 0) | .port] | unique
            | map("\(.)/tcp  Shadowsocks (keys from Outline)", "\(.)/udp  Shadowsocks (keys from Outline)") else [] end)
        + (if .vless.enabled then ["\(.vless.port)/tcp  VLESS-REALITY"] else [] end)
        + (if .wireguard.enabled then ["\(.wireguard.port)/udp  WireGuard"] else [] end)
        + (if .amneziawg.enabled then ["\(.amneziawg.port)/udp  AmneziaWG"] else [] end)
        + (if (.dashboard.public // false) and ((.dashboard.port // 0) > 0) then ["\(.dashboard.port)/tcp  web dashboard (public)"] else [] end)
        + (if (.ipsec.ikev2_enabled // false) or (.ipsec.ipsec_enabled // false) then ["500/udp  IKEv2/IPsec", "4500/udp  IKEv2/IPsec"] else [] end)
        + (if (.mesh.enabled // false) and ((.mesh.port // 0) > 0) then ["\(.mesh.port)/tcp  mesh coordinator (for mesh agents)"] else [] end)
        | .[]' "$STATE/state.json"
}

open_ports() { # "PORT/PROTO  service"...
    local entry
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        say "Allowing the ports in ufw"
        for entry in "$@"; do ufw allow "${entry%% *}" comment 'Ghostlink server' >/dev/null; done
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        say "Allowing the ports in firewalld"
        for entry in "$@"; do firewall-cmd --permanent --add-port="${entry%% *}" >/dev/null; done
        firewall-cmd --reload >/dev/null
    else
        say "No active ufw or firewalld here, so nothing to open on this server (check your cloud security group)"
    fi
}

main "$@"
