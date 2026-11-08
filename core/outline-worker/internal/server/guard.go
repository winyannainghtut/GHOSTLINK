// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// udpGuard repeats the address and port parts of the routing rules for single UDP packets.
// sing-box routes a UDP session once, by its first packet, and then sends every later packet
// wherever that packet says: Shadowsocks and VLESS carry an address with each packet, and the
// WireGuard stack keys sessions by the client's own address. Without this check a client could
// open a session to an allowed address and send the rest to the host's loopback, its network,
// the server itself or an address the administrator blocked. policedPacketConn asks the guard
// about every packet that goes anywhere other than where its session was routed.
//
// Site names cannot be checked per packet; a packet to another name is refused outright,
// because the engine would not resolve it anyway.
type udpGuard struct {
	// internal is always blocked, like internalBlock: private and reserved ranges, and the
	// server's own addresses.
	internal []netip.Prefix
	// ports are the server's own service ports, blocked on every address.
	ports  []uint16
	global blockList
	users  map[string]userGuard
}

type blockList struct {
	prefixes   []netip.Prefix
	ports      [][2]uint16
	bittorrent bool
}

type userGuard struct {
	own    blockList
	exempt bool
}

func newBlockList(rules Rules) blockList {
	list := blockList{bittorrent: rules.BlockBitTorrent}
	for _, cidr := range rules.BlockedIPs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			list.prefixes = append(list.prefixes, prefix)
		}
	}
	for _, entry := range rules.BlockedPorts {
		if lo, hi, err := portRange(entry); err == nil {
			list.ports = append(list.ports, [2]uint16{lo, hi})
		}
	}
	if rules.BlockSMTP {
		list.ports = append(list.ports, [2]uint16{25, 25})
	}
	return list
}

// newUDPGuard builds the guard for the engine configuration of s (see routeRules).
func newUDPGuard(s *State) *udpGuard {
	g := &udpGuard{ports: s.privatePorts(), global: newBlockList(s.Rules), users: map[string]userGuard{}}
	for _, cidr := range internalRanges {
		g.internal = append(g.internal, netip.MustParsePrefix(cidr))
	}
	for _, addr := range s.serverAddresses() {
		g.internal = append(g.internal, netip.PrefixFrom(addr, addr.BitLen()))
	}
	for _, u := range s.activeUsers() {
		g.users[u.Tag()] = userGuard{own: newBlockList(u.Rules), exempt: u.ExemptFromGlobalRules}
	}
	return g
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// isBitTorrent runs the engine's own packet sniffers, as the bittorrent rule does.
func isBitTorrent(packet []byte) bool {
	var metadata adapter.InboundContext
	return sniff.UTP(context.Background(), &metadata, packet) == nil ||
		sniff.UDPTracker(context.Background(), &metadata, packet) == nil
}

func (l blockList) blocks(addr netip.Addr, port uint16, packet []byte) bool {
	if containsAddr(l.prefixes, addr) {
		return true
	}
	for _, span := range l.ports {
		if port >= span[0] && port <= span[1] {
			return true
		}
	}
	return l.bittorrent && isBitTorrent(packet)
}

// allows reports whether user may send packet to destination, in the order of the routing
// rules: DNS, the always-blocked destinations, the user's own rules, then (unless the user is
// exempt) the rules for everyone.
func (g *udpGuard) allows(user string, destination M.Socksaddr, packet []byte) bool {
	if !destination.IsIP() {
		return false
	}
	addr, port := destination.Addr, destination.Port
	// All DNS goes to the server's resolver; another resolver's port is refused, not answered.
	if port == 53 {
		return false
	}
	if testInternalPort == 0 || port != testInternalPort {
		if !N.IsPublicAddr(addr) || containsAddr(g.internal, addr) {
			return false
		}
	}
	if slices.Contains(g.ports, port) {
		return false
	}
	u, ok := g.users[user]
	if ok && u.own.blocks(addr, port, packet) {
		return false
	}
	return u.exempt || !g.global.blocks(addr, port, packet)
}
