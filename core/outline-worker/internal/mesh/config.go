// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package mesh

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"ghostlink.local/outline-worker/internal/meshproto"
)

// keepalive keeps NAT mappings open and handshakes fresh, which is also how the coordinator
// sees that a direct link works.
const keepalive = 25

// Config builds the configuration of one active node. Its generation is a hash of the content,
// so it changes exactly when the node has something new to apply.
func (l *Live) Config(n *Network, node *Node, now time.Time) (*meshproto.Config, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config(n, node, now)
}

func (l *Live) config(n *Network, node *Node, now time.Time) (*meshproto.Config, error) {
	if node.Status != meshproto.StatusActive {
		return nil, errors.New("node is not active")
	}
	mesh, err := netip.ParsePrefix(n.CIDR)
	if err != nil {
		return nil, err
	}
	relay := l.relay(n, now)
	c := &meshproto.Config{
		Name: node.Name, MeshCIDR: mesh.String(), Address: netip.PrefixFrom(netip.MustParseAddr(node.Address), mesh.Bits()).String(),
		ListenPort: node.ListenPort, Peers: []meshproto.Peer{}, Routes: []string{}, Relay: node == relay,
		Shared: append([]string{}, node.ApprovedRoutes...), Masquerade: node.Masquerade && len(node.ApprovedRoutes) > 0,
		Firewall: compileFirewall(n, node), Hosts: []meshproto.Host{},
	}
	relayIndex := -1
	var relayed [][]string // AllowedIPs of peers reached through the relay
	for _, other := range activeNodes(n) {
		c.Hosts = append(c.Hosts, meshproto.Host{Name: other.Name, Address: other.Address})
		if other == node {
			continue
		}
		allowed := append([]string{other.Address + "/32"}, other.ApprovedRoutes...)
		c.Routes = append(c.Routes, other.ApprovedRoutes...)
		if relay != nil && other != relay && node != relay && l.relayed(node, other) {
			relayed = append(relayed, allowed)
			continue
		}
		c.Peers = append(c.Peers, meshproto.Peer{
			Name: other.Name, PublicKey: other.PublicKey, Endpoint: l.endpoint(node, other),
			AllowedIPs: allowed, Keepalive: keepalive,
		})
		if other == relay {
			relayIndex = len(c.Peers) - 1
		}
	}
	if relayIndex >= 0 {
		for _, allowed := range relayed {
			c.Peers[relayIndex].AllowedIPs = append(c.Peers[relayIndex].AllowedIPs, allowed...)
		}
	}
	slices.Sort(c.Routes)
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	// 53 bits, so JSON readers that use doubles (JavaScript, jq) keep it exact; never 0, which
	// means "nothing applied".
	c.Generation = binary.BigEndian.Uint64(sum[:8])&(1<<53-1) | 1
	return c, c.Validate()
}

// compileFirewall turns the rules into concrete source addresses for one receiving node, so the
// agent needs no knowledge of tags. Without rules, the mesh is open.
func compileFirewall(n *Network, dest *Node) meshproto.Firewall {
	fw := meshproto.Firewall{Ping: n.Ping, Allow: []meshproto.Allow{}}
	if len(n.Rules) == 0 {
		fw.Open = true
		return fw
	}
	destinations := append([]string{dest.Address + "/32"}, dest.ApprovedRoutes...)
	for _, r := range n.Rules {
		if !r.matches(r.To, dest) {
			continue
		}
		sources := []string{}
		for _, src := range activeNodes(n) {
			if src != dest && r.matches(r.From, src) {
				sources = append(sources, src.Address+"/32")
			}
		}
		if len(sources) == 0 {
			continue
		}
		ports := r.Ports
		if ports == nil {
			ports = []string{}
		}
		fw.Allow = append(fw.Allow, meshproto.Allow{Sources: sources, Destinations: destinations, Protocol: r.Protocol, Ports: ports})
	}
	return fw
}
