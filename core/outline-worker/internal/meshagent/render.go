// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package meshagent

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"ghostlink.local/outline-worker/internal/hostfw"
	"ghostlink.local/outline-worker/internal/meshproto"
)

// The agent's own chains; built-in chains only get one jump to each. The filter and guard jumps
// match the mesh interface; the nat and MSS ones match everything, but the rules inside them only
// touch mesh traffic.
const (
	chainIn  = "GHOSTLINK-MESH-IN"
	chainFwd = "GHOSTLINK-MESH-FWD"
	chainOut = "GHOSTLINK-MESH-OUT"
	chainNAT = "GHOSTLINK-MESH-POST"
	chainMSS = "GHOSTLINK-MESH-MSS"
	// The guards, in the mangle table, drop what the access rules do not allow before the filter
	// table sees it. Docker's accept rules, like those of similar software, are in the filter
	// table, so they can't run ahead of the guards, even while the filter jumps are not first.
	// They check every packet of a connection opened from the mesh, not only its first, so one
	// let through while the rules were missing (a firewall reload) ends once they are back (code
	// review 2026-11-10, R1).
	chainGuardIn  = "GHOSTLINK-MESH-GUARD-IN"
	chainGuardFwd = "GHOSTLINK-MESH-GUARD-FWD"
)

// Jumps are the rules placed first in built-in chains for interface iface. The filter FORWARD
// ones are also kept first in Docker's DOCKER-USER: FWD ends every packet with ACCEPT or DROP, and
// OUT only accepts replies, so a packet that passes them twice is not changed.
func Jumps(iface string) []hostfw.Jump {
	return []hostfw.Jump{
		{Table: "filter", Chain: "INPUT", Match: []string{"-i", iface}, Target: chainIn},
		{Table: "filter", Chain: "FORWARD", Match: []string{"-i", iface}, Target: chainFwd, Docker: true},
		{Table: "filter", Chain: "FORWARD", Match: []string{"-o", iface}, Target: chainOut, Docker: true},
		{Table: "nat", Chain: "POSTROUTING", Target: chainNAT},
		{Table: "mangle", Chain: "FORWARD", Target: chainMSS},
		{Table: "mangle", Chain: "INPUT", Match: []string{"-i", iface}, Target: chainGuardIn},
		{Table: "mangle", Chain: "FORWARD", Match: []string{"-i", iface}, Target: chainGuardFwd},
	}
}

// Chains lists the agent's chains per table.
func Chains() map[string][]string {
	return map[string][]string{"filter": {chainIn, chainFwd, chainOut}, "nat": {chainNAT}, "mangle": {chainMSS, chainGuardIn, chainGuardFwd}}
}

func address(c *meshproto.Config) string {
	p, _ := netip.ParsePrefix(c.Address)
	return p.Addr().String() + "/32"
}

// allowRules renders the accept rules of chain for traffic to dest. With dnat it matches
// connections the host redirected (DNAT) away from dest instead, by the address and port the
// peer connected to.
func allowRules(chain, dest string, fw meshproto.Firewall, dnat bool) []string {
	to, dport := "-d "+dest, "--dport"
	if dnat {
		to, dport = "-m conntrack --ctstate DNAT --ctorigdst "+dest, "--ctorigdstport"
	}
	var rules []string
	if fw.Ping {
		rules = append(rules, fmt.Sprintf("-A %s %s -p icmp --icmp-type echo-request -j ACCEPT", chain, to))
	}
	if fw.Open {
		return append(rules, fmt.Sprintf("-A %s %s -j ACCEPT", chain, to))
	}
	for _, a := range fw.Allow {
		if !slices.Contains(a.Destinations, dest) {
			continue
		}
		for _, src := range a.Sources {
			base := fmt.Sprintf("-A %s -s %s %s", chain, src, to)
			switch {
			case a.Protocol == "any":
				rules = append(rules, base+" -j ACCEPT")
			case a.Protocol == "icmp":
				rules = append(rules, base+" -p icmp -j ACCEPT")
			case len(a.Ports) == 0:
				rules = append(rules, fmt.Sprintf("%s -p %s -j ACCEPT", base, a.Protocol))
			default:
				for _, port := range a.Ports {
					rules = append(rules, fmt.Sprintf("%s -p %s %s %s -j ACCEPT", base, a.Protocol, dport, strings.Replace(port, "-", ":", 1)))
				}
			}
		}
	}
	return rules
}

// Rules renders iptables-restore input for a configuration on interface iface:
//   - IN: what the mesh may reach on this machine (replies, pings, then the rules), at its mesh
//     address and at its own addresses in the subnets it shares (a LAN gateway, for example);
//   - FWD: connections the host redirects from this node's mesh address (published container
//     ports), relayed traffic between peers, and mesh traffic to this node's shared subnets,
//     all under the same rules; everything else arriving from the mesh is dropped, so the mesh
//     can't use this machine to reach networks it does not share;
//   - OUT: replies going back into the mesh;
//   - GUARD-IN and GUARD-FWD (mangle): the same rules as IN and FWD, checked on every packet a
//     peer sends that is not a reply, before the filter table (see chainGuardFwd);
//   - POST: masquerading toward shared subnets; MSS clamping for the smaller tunnel MTU.
func Rules(c *meshproto.Config, iface string) map[string]string {
	// What the mesh may reach on this machine, and through it. Packets for the node's own address
	// in a shared subnet are delivered here, not forwarded.
	inAllowed := func(chain string) []string {
		rules := allowRules(chain, address(c), c.Firewall, false)
		for _, shared := range c.Shared {
			rules = append(rules, allowRules(chain, shared, c.Firewall, false)...)
		}
		return rules
	}
	// Docker's and Podman's published ports and Kubernetes NodePorts are DNATed in PREROUTING, so
	// a connection to one of them at this node's mesh address is forwarded (to the container),
	// not delivered locally. It is still a service of this node, under its rules.
	fwdAllowed := func(chain string) []string {
		rules := allowRules(chain, address(c), c.Firewall, true)
		if c.Relay {
			rules = append(rules, fmt.Sprintf("-A %s -o %s -j ACCEPT", chain, iface))
		}
		for _, shared := range c.Shared {
			rules = append(rules, allowRules(chain, shared, c.Firewall, false)...)
		}
		return rules
	}
	filter := []string{"*filter", ":" + chainIn + " - [0:0]", ":" + chainFwd + " - [0:0]", ":" + chainOut + " - [0:0]",
		"-A " + chainIn + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}
	filter = append(filter, inAllowed(chainIn)...)
	filter = append(filter, "-A "+chainIn+" -j DROP",
		"-A "+chainFwd+" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	filter = append(filter, fwdAllowed(chainFwd)...)
	filter = append(filter, "-A "+chainFwd+" -j DROP",
		"-A "+chainOut+" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	nat := []string{"*nat", ":" + chainNAT + " - [0:0]"}
	if c.Masquerade {
		for _, shared := range c.Shared {
			nat = append(nat, fmt.Sprintf("-A %s -s %s -d %s ! -o %s -j MASQUERADE", chainNAT, c.MeshCIDR, shared, iface))
		}
	}
	mangle := []string{"*mangle", ":" + chainMSS + " - [0:0]", ":" + chainGuardIn + " - [0:0]", ":" + chainGuardFwd + " - [0:0]",
		fmt.Sprintf("-A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", chainMSS, iface),
		fmt.Sprintf("-A %s -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", chainMSS, iface)}
	mangle = append(mangle, guard(chainGuardIn, inAllowed(chainGuardIn))...)
	mangle = append(mangle, guard(chainGuardFwd, fwdAllowed(chainGuardFwd))...)
	out := map[string]string{}
	for _, table := range [][]string{filter, nat, mangle} {
		out[table[0][1:]] = strings.Join(append(table, "COMMIT"), "\n") + "\n"
	}
	return out
}

// guard renders a guard chain from the accept rules of its filter chain. A reply (to a
// connection this machine or a host behind it opened) and an ICMP error about a connection go
// on; any other packet must match an accept rule, each time, or it is dropped. Allowed packets
// RETURN rather than ACCEPT, so the rest of the mangle table (MSS clamping, other software's
// rules) still sees them, and the filter table decides as before.
func guard(chain string, allowed []string) []string {
	rules := []string{
		"-A " + chain + " -m conntrack --ctdir REPLY -j RETURN",
		"-A " + chain + " -m conntrack --ctstate RELATED -j RETURN",
	}
	for _, rule := range allowed {
		rules = append(rules, strings.TrimSuffix(rule, " -j ACCEPT")+" -j RETURN")
	}
	return append(rules, "-A "+chain+" -j DROP")
}

const (
	hostsBegin = "# BEGIN ghostlink-mesh (managed by ghostlink-mesh; edits here are replaced)"
	hostsEnd   = "# END ghostlink-mesh"
)

// RenderHosts replaces (or adds, or with no entries removes) the managed block in an
// /etc/hosts file's text.
func RenderHosts(existing string, entries []meshproto.Host) string {
	var kept []string
	inside := false
	for _, line := range strings.Split(strings.TrimRight(existing, "\n"), "\n") {
		switch {
		case line == hostsBegin:
			inside = true
		case line == hostsEnd:
			inside = false
		case !inside:
			kept = append(kept, line)
		}
	}
	out := strings.Join(kept, "\n")
	if len(entries) > 0 {
		block := []string{hostsBegin}
		for _, h := range entries {
			block = append(block, fmt.Sprintf("%s\t%s.mesh", h.Address, h.Name))
		}
		block = append(block, hostsEnd)
		if out != "" {
			out += "\n"
		}
		out += strings.Join(block, "\n")
	}
	return out + "\n"
}

// PeerChanges turns the wanted peers into a WireGuard update that keeps existing sessions:
// current peers are updated in place, missing ones added, others removed. An endpoint is only
// set when the coordinator's suggestion changed, so WireGuard can keep following a peer that
// roams. applied maps public key to the endpoint last set; the new map is returned.
func PeerChanges(current []wgtypes.Peer, wanted []meshproto.Peer, applied map[string]string) ([]wgtypes.PeerConfig, map[string]string, error) {
	have := map[string]bool{}
	for _, p := range current {
		have[p.PublicKey.String()] = true
	}
	next := map[string]string{}
	var changes []wgtypes.PeerConfig
	keep := map[string]bool{}
	for _, p := range wanted {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("peer %s: %w", p.Name, err)
		}
		keep[p.PublicKey] = true
		var allowed []net.IPNet
		for _, text := range p.AllowedIPs {
			_, n, err := net.ParseCIDR(text)
			if err != nil {
				return nil, nil, fmt.Errorf("peer %s: %w", p.Name, err)
			}
			allowed = append(allowed, *n)
		}
		keepalive := time.Duration(p.Keepalive) * time.Second
		change := wgtypes.PeerConfig{PublicKey: key, UpdateOnly: have[p.PublicKey], ReplaceAllowedIPs: true, AllowedIPs: allowed,
			PersistentKeepaliveInterval: &keepalive}
		if p.Endpoint != "" && (!have[p.PublicKey] || applied[p.PublicKey] != p.Endpoint) {
			ap := netip.MustParseAddrPort(p.Endpoint)
			change.Endpoint = &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
		}
		if p.Endpoint != "" {
			next[p.PublicKey] = p.Endpoint
		}
		changes = append(changes, change)
	}
	for _, p := range current {
		if !keep[p.PublicKey.String()] {
			changes = append(changes, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	return changes, next, nil
}

// meshRoutes splits other nodes' shared subnets into those to route into the mesh and those it
// must leave alone, because the route would
//   - replace or hide a route the main table already has for exactly that subnet (the agent's
//     routes have metric 0, so the kernel replaces an equal one, and nothing would put it back);
//   - take over part or all of a network this machine is on itself (connected), cutting it off
//     from its own LAN;
//   - carry a peer's WireGuard endpoint into the mesh (for example the subnet router's address
//     on the same LAN), which loops; a more specific existing route for the endpoint prevents
//     that.
//
// routed is every main-table route but the agent's own.
func meshRoutes(routes []string, connected, routed []netip.Prefix, endpoints []netip.Addr) (keep, skip []string) {
	for _, text := range routes {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			keep = append(keep, text) // setRoutes reports it
			continue
		}
		taken := slices.Contains(routed, p)
		for _, n := range connected {
			taken = taken || (n.Bits() <= p.Bits() && n.Contains(p.Addr()))
		}
		for _, e := range endpoints {
			captured := p.Contains(e)
			for _, r := range routed {
				captured = captured && !(r.Bits() > p.Bits() && r.Contains(e))
			}
			taken = taken || captured
		}
		if taken {
			skip = append(skip, text)
		} else {
			keep = append(keep, text)
		}
	}
	return keep, skip
}
