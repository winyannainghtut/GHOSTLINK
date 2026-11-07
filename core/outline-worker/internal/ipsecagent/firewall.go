// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package ipsecagent

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"ghostlink.local/outline-worker/internal/hostfw"
	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// The agent owns these chains and nothing else; built-in chains only get one jump to each.
const (
	chainForward = "GHOSTLINK-IPSEC-FWD"
	chainOut     = "GHOSTLINK-IPSEC-OUT"
	chainInput   = "GHOSTLINK-IPSEC-IN"
	chainDNAT    = "GHOSTLINK-IPSEC-PRE"
	chainNAT     = "GHOSTLINK-IPSEC-POST"
	chainMSS     = "GHOSTLINK-IPSEC-MSS"
	// chainLimit drops what capped clients send or receive above their speed limit.
	chainLimit = "GHOSTLINK-IPSEC-LIM"
)

// jumps are the rules placed first in built-in chains: table, chain, target.
var jumps = [][3]string{
	{"filter", "FORWARD", chainForward},
	{"filter", "INPUT", chainInput},
	{"nat", "PREROUTING", chainDNAT},
	{"nat", "POSTROUTING", chainNAT},
	{"mangle", "FORWARD", chainMSS},
}

type pool struct{ cidr, gateway string }

func pools(d ipsecproto.Desired) []pool {
	var out []pool
	if d.IKEv2 != nil {
		out = append(out, pool{d.IKEv2.Pool, d.IKEv2.Gateway})
	}
	if d.IKEv1 != nil {
		out = append(out, pool{d.IKEv1.Pool, d.IKEv1.Gateway})
	}
	return out
}

func ipv4Ranges(cidrs []string) []string {
	var out []string
	for _, text := range cidrs {
		if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Addr().Is4() {
			out = append(out, prefix.Masked().String())
		}
	}
	return out
}

// limitRules polices the speed of capped clients: for each connected session, traffic to and
// from its virtual IP above the client's rate is dropped. A client's sessions share one
// hashlimit bucket per direction (rules with the same name share it), so the cap holds for the
// client as a whole. hashlimit counts bytes with a "b/s" rate.
func limitRules(d ipsecproto.Desired, sas []ipsecproto.SA) []string {
	byIdentity := map[string]ipsecproto.SpeedLimit{}
	for _, l := range d.SpeedLimits {
		for _, id := range l.Identities {
			byIdentity[strings.ToLower(id)] = l
		}
	}
	var rules []string
	seen := map[netip.Addr]bool{}
	for _, sa := range sas {
		limit, capped := byIdentity[strings.ToLower(sa.Identity)]
		addr, err := netip.ParseAddr(sa.VirtualIP)
		if !capped || err != nil || !addr.Is4() || seen[addr] {
			continue
		}
		seen[addr] = true
		for _, direction := range []struct{ match, suffix string }{{"-d", "d"}, {"-s", "u"}} {
			rules = append(rules, fmt.Sprintf("-A %s %s %s/32 -m hashlimit --hashlimit-above %db/s --hashlimit-name %s%s -j DROP",
				chainLimit, direction.match, addr, limit.BytesPerSecond, hashlimitName(limit), direction.suffix))
		}
	}
	slices.Sort(rules)
	return rules
}

// hashlimitName names a client's buckets after the client and its rate. The kernel keeps a
// named table, with the rate of the rule that created it, for as long as any rule uses that
// name, so a new rate needs a new name to take effect for sessions already connected. At most
// 9 characters, which leaves room for the direction (hashlimit names are up to 15).
func hashlimitName(l ipsecproto.SpeedLimit) string {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s/%d", l.Name, l.BytesPerSecond)
	return "gl" + strconv.FormatUint(uint64(h.Sum32()), 36)
}

// Rules renders iptables-restore input for each table. Restoring with --noflush replaces only
// the chains declared here, atomically per table. sas are the connected sessions, for the
// speed limits.
//
// VPN clients may reach the internet, minus the server's always-blocked internal ranges and the
// administrator's blocked addresses and ports; DNS (any resolver) goes to the server's DNS so
// global site blocks apply; nothing else on this host is reachable from the pools.
func Rules(d ipsecproto.Desired, sas []ipsecproto.SA) map[string]string {
	filter := []string{"*filter", ":" + chainForward + " - [0:0]", ":" + chainOut + " - [0:0]", ":" + chainInput + " - [0:0]",
		":" + chainLimit + " - [0:0]", "-A " + chainForward + " -j " + chainLimit}
	filter = append(filter, limitRules(d, sas)...)
	nat := []string{"*nat", ":" + chainDNAT + " - [0:0]", ":" + chainNAT + " - [0:0]"}
	mangle := []string{"*mangle", ":" + chainMSS + " - [0:0]"}
	f := d.Firewall
	dns := fmt.Sprint(f.DNSPort)
	for _, p := range pools(d) {
		filter = append(filter,
			fmt.Sprintf("-A %s -d %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", chainForward, p.cidr),
			fmt.Sprintf("-A %s -s %s -j %s", chainForward, p.cidr, chainOut),
			fmt.Sprintf("-A %s -s %s -d %s/32 -p udp --dport %s -m policy --dir in --pol ipsec -j ACCEPT", chainInput, p.cidr, p.gateway, dns),
			fmt.Sprintf("-A %s -s %s -d %s/32 -p tcp --dport %s -m policy --dir in --pol ipsec -j ACCEPT", chainInput, p.cidr, p.gateway, dns),
			fmt.Sprintf("-A %s -s %s -j DROP", chainInput, p.cidr))
		for _, proto := range []string{"udp", "tcp"} {
			nat = append(nat, fmt.Sprintf("-A %s -s %s -p %s --dport 53 -m policy --dir in --pol ipsec -j DNAT --to-destination %s:%s", chainDNAT, p.cidr, proto, p.gateway, dns))
		}
		nat = append(nat, fmt.Sprintf("-A %s -s %s -m policy --dir out --pol none -j MASQUERADE", chainNAT, p.cidr))
		mangle = append(mangle,
			fmt.Sprintf("-A %s -s %s -p tcp --tcp-flags SYN,RST SYN -m policy --dir in --pol ipsec -j TCPMSS --set-mss 1360", chainMSS, p.cidr),
			fmt.Sprintf("-A %s -d %s -p tcp --tcp-flags SYN,RST SYN -m policy --dir out --pol ipsec -j TCPMSS --set-mss 1360", chainMSS, p.cidr))
	}
	// Traffic from the pools that did not arrive through IPsec is spoofed.
	filter = append(filter, fmt.Sprintf("-A %s -m policy --dir in --pol none -j DROP", chainOut))
	for _, cidr := range ipv4Ranges(f.Internal) {
		filter = append(filter, fmt.Sprintf("-A %s -d %s -j DROP", chainOut, cidr))
	}
	if addr, err := netip.ParseAddr(f.ServerIP); err == nil && addr.Is4() {
		filter = append(filter, fmt.Sprintf("-A %s -d %s/32 -j DROP", chainOut, addr))
	}
	for _, cidr := range ipv4Ranges(f.Blocked) {
		filter = append(filter, fmt.Sprintf("-A %s -d %s -j REJECT", chainOut, cidr))
	}
	ports := append([]string{}, f.Ports...)
	for _, port := range ports {
		spec := strings.Replace(port, "-", ":", 1)
		for _, proto := range []string{"tcp", "udp"} {
			filter = append(filter, fmt.Sprintf("-A %s -p %s --dport %s -j REJECT", chainOut, proto, spec))
		}
	}
	if f.BlockSMTP {
		filter = append(filter, fmt.Sprintf("-A %s -p tcp --dport 25 -j REJECT", chainOut))
	}
	filter = append(filter, fmt.Sprintf("-A %s -j ACCEPT", chainOut))
	out := map[string]string{}
	for _, table := range [][]string{filter, nat, mangle} {
		out[table[0][1:]] = strings.Join(append(table, "COMMIT"), "\n") + "\n"
	}
	return out
}

// Firewall applies Rules with the host's iptables backend (see internal/hostfw).
type Firewall struct {
	Backend string // "nft" or "legacy"
}

var chains = map[string][]string{
	"filter": {chainForward, chainOut, chainInput, chainLimit},
	"nat":    {chainDNAT, chainNAT},
	"mangle": {chainMSS},
}

func hostJumps() []hostfw.Jump {
	var out []hostfw.Jump
	for _, j := range jumps {
		out = append(out, hostfw.Jump{Table: j[0], Chain: j[1], Target: j[2]})
	}
	return out
}

func run(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	return hostfw.Run(ctx, stdin, name, args...)
}

// DetectBackend picks the iptables backend the host uses.
func DetectBackend(ctx context.Context) string { return hostfw.Detect(ctx) }

func (f *Firewall) host() *hostfw.Firewall { return &hostfw.Firewall{Backend: f.Backend} }

// Apply replaces the agent's chains and makes sure each is jumped to from its built-in chain.
func (f *Firewall) Apply(ctx context.Context, d ipsecproto.Desired, sas []ipsecproto.SA) error {
	if err := f.host().Restore(ctx, Rules(d, sas)); err != nil {
		return err
	}
	return f.EnsureJumps(ctx)
}

// EnsureJumps puts back a jump someone removed (for example a firewall reload).
func (f *Firewall) EnsureJumps(ctx context.Context) error {
	return f.host().EnsureJumps(ctx, hostJumps())
}

// Remove deletes the jumps and the agent's chains, leaving the host as it was.
func (f *Firewall) Remove(ctx context.Context) { f.host().Remove(ctx, hostJumps(), chains) }
