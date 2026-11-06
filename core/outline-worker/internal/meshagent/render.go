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

// The agent's own chains; built-in chains only get one jump to each, matching the interface.
const (
	chainIn  = "GHOSTLINK-MESH-IN"
	chainFwd = "GHOSTLINK-MESH-FWD"
	chainOut = "GHOSTLINK-MESH-OUT"
	chainNAT = "GHOSTLINK-MESH-POST"
	chainMSS = "GHOSTLINK-MESH-MSS"
)

// Jumps are the rules placed first in built-in chains for interface iface.
func Jumps(iface string) []hostfw.Jump {
	return []hostfw.Jump{
		{Table: "filter", Chain: "INPUT", Match: []string{"-i", iface}, Target: chainIn},
		{Table: "filter", Chain: "FORWARD", Match: []string{"-i", iface}, Target: chainFwd},
		{Table: "filter", Chain: "FORWARD", Match: []string{"-o", iface}, Target: chainOut},
		{Table: "nat", Chain: "POSTROUTING", Target: chainNAT},
		{Table: "mangle", Chain: "FORWARD", Target: chainMSS},
	}
}

// Chains lists the agent's chains per table.
func Chains() map[string][]string {
	return map[string][]string{"filter": {chainIn, chainFwd, chainOut}, "nat": {chainNAT}, "mangle": {chainMSS}}
}

func address(c *meshproto.Config) string {
	p, _ := netip.ParsePrefix(c.Address)
	return p.Addr().String() + "/32"
}

// allowRules renders the accept rules of chain for traffic to dest.
func allowRules(chain, dest string, fw meshproto.Firewall) []string {
	var rules []string
	if fw.Ping {
		rules = append(rules, fmt.Sprintf("-A %s -d %s -p icmp --icmp-type echo-request -j ACCEPT", chain, dest))
	}
	if fw.Open {
		return append(rules, fmt.Sprintf("-A %s -d %s -j ACCEPT", chain, dest))
	}
	for _, a := range fw.Allow {
		if !slices.Contains(a.Destinations, dest) {
			continue
		}
		for _, src := range a.Sources {
			base := fmt.Sprintf("-A %s -s %s -d %s", chain, src, dest)
			switch {
			case a.Protocol == "any":
				rules = append(rules, base+" -j ACCEPT")
			case a.Protocol == "icmp":
				rules = append(rules, base+" -p icmp -j ACCEPT")
			case len(a.Ports) == 0:
				rules = append(rules, fmt.Sprintf("%s -p %s -j ACCEPT", base, a.Protocol))
			default:
				for _, port := range a.Ports {
					rules = append(rules, fmt.Sprintf("%s -p %s --dport %s -j ACCEPT", base, a.Protocol, strings.Replace(port, "-", ":", 1)))
				}
			}
		}
	}
	return rules
}

// Rules renders iptables-restore input for a configuration on interface iface:
//   - IN: what the mesh may reach on this machine (replies, pings, then the rules);
//   - FWD: relayed traffic between peers, and mesh traffic to this node's shared subnets
//     under the same rules; everything else arriving from the mesh is dropped, so the mesh
//     can't use this machine to reach networks it does not share;
//   - OUT: replies going back into the mesh;
//   - POST: masquerading toward shared subnets; MSS clamping for the smaller tunnel MTU.
func Rules(c *meshproto.Config, iface string) map[string]string {
	filter := []string{"*filter", ":" + chainIn + " - [0:0]", ":" + chainFwd + " - [0:0]", ":" + chainOut + " - [0:0]",
		"-A " + chainIn + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}
	filter = append(filter, allowRules(chainIn, address(c), c.Firewall)...)
	filter = append(filter, "-A "+chainIn+" -j DROP",
		"-A "+chainFwd+" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	if c.Relay {
		filter = append(filter, fmt.Sprintf("-A %s -o %s -j ACCEPT", chainFwd, iface))
	}
	for _, shared := range c.Shared {
		filter = append(filter, allowRules(chainFwd, shared, c.Firewall)...)
	}
	filter = append(filter, "-A "+chainFwd+" -j DROP",
		"-A "+chainOut+" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	nat := []string{"*nat", ":" + chainNAT + " - [0:0]"}
	if c.Masquerade {
		for _, shared := range c.Shared {
			nat = append(nat, fmt.Sprintf("-A %s -s %s -d %s ! -o %s -j MASQUERADE", chainNAT, c.MeshCIDR, shared, iface))
		}
	}
	mangle := []string{"*mangle", ":" + chainMSS + " - [0:0]",
		fmt.Sprintf("-A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", chainMSS, iface),
		fmt.Sprintf("-A %s -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", chainMSS, iface)}
	out := map[string]string{}
	for _, table := range [][]string{filter, nat, mangle} {
		out[table[0][1:]] = strings.Join(append(table, "COMMIT"), "\n") + "\n"
	}
	return out
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
