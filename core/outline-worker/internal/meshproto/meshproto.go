// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package meshproto is the contract between the Ghostlink mesh coordinator (inside the
// unprivileged ghostlink-server) and the ghostlink-mesh agent on each Linux node. Agents join
// with an invite, then keep one long-polling sync call open: they report their WireGuard state
// and receive their configuration. The agent re-validates every field before applying it;
// nothing reaches a shell, and keys, addresses and rules are checked here.
package meshproto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	// Version of the protocol; the coordinator refuses agents speaking another one.
	Version = 1
	// InvitePrefix marks a join invite: glmesh1:<base64url JSON Invite>.
	InvitePrefix = "glmesh1:"
	// DefaultPort is the agent's WireGuard UDP port.
	DefaultPort = 51820
	// MaxPeers bounds a configuration (and so every list in it).
	MaxPeers = 250
	// MaxRoutes bounds the subnets one node may advertise.
	MaxRoutes = 16
)

// Invite is what a join token carries: where the coordinator is, its certificate pin, and the
// one-time secret.
type Invite struct {
	URL   string `json:"url"`
	Pin   string `json:"pin"`
	Token string `json:"token"`
}

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	tagPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,22}[a-z0-9])?$`)
	pinPattern   = regexp.MustCompile(`^[0-9A-F]{64}$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// ValidName accepts a node name: lower-case letters, digits and hyphens, at most 32
// characters. It is also the node's host name in the mesh (<name>.mesh).
func ValidName(name string) bool { return namePattern.MatchString(name) }

// ValidTag accepts a tag used by access rules.
func ValidTag(tag string) bool { return tagPattern.MatchString(tag) }

// ValidKey accepts a WireGuard public or private key: 32 bytes, standard base64.
func ValidKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == key
}

// EncodeInvite renders an invite as a single copyable string.
func EncodeInvite(inv Invite) string {
	data, _ := json.Marshal(inv)
	return InvitePrefix + base64.RawURLEncoding.EncodeToString(data)
}

// DecodeInvite parses and checks an invite.
func DecodeInvite(text string) (Invite, error) {
	var inv Invite
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, InvitePrefix) {
		return inv, errors.New("this is not a Ghostlink mesh invite (it starts with glmesh1:)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, InvitePrefix))
	if err != nil {
		return inv, errors.New("the mesh invite is damaged; copy it again")
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		return inv, errors.New("the mesh invite is damaged; copy it again")
	}
	if !strings.HasPrefix(inv.URL, "https://") || strings.ContainsAny(inv.URL, " \r\n") || len(inv.URL) > 300 {
		return inv, errors.New("the mesh invite has an invalid coordinator address")
	}
	if !pinPattern.MatchString(inv.Pin) || !tokenPattern.MatchString(inv.Token) {
		return inv, errors.New("the mesh invite is damaged; copy it again")
	}
	return inv, nil
}

// JoinRequest is sent once, with the invite's token, to become a node.
type JoinRequest struct {
	Protocol        int      `json:"protocol"`
	Token           string   `json:"token"`
	Name            string   `json:"name"`
	PublicKey       string   `json:"public_key"`
	ListenPort      uint16   `json:"listen_port"`
	Endpoints       []string `json:"endpoints"`
	AdvertiseRoutes []string `json:"advertise_routes"`
	OS              string   `json:"os"`
	Version         string   `json:"version"`
}

// JoinResponse identifies the new node; the secret authenticates its sync calls.
type JoinResponse struct {
	NodeID  string `json:"node_id"`
	Secret  string `json:"secret"`
	Address string `json:"address"`
	Status  string `json:"status"`
}

// Node states, as the coordinator reports them.
const (
	StatusActive   = "active"
	StatusPending  = "pending"
	StatusDisabled = "disabled"
	StatusRemoved  = "removed"
)

// PeerStatus is the agent's view of one WireGuard peer.
type PeerStatus struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint,omitempty"`
	LastHandshake int64  `json:"last_handshake_unix"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
}

// Ping is the round trip to another node's mesh address (direct or through the relay); a
// RTTMicros of 0 means it did not answer.
type Ping struct {
	Address   string `json:"address"`
	RTTMicros int64  `json:"rtt_us"`
}

// SyncRequest reports the node's state and waits for configuration changes.
type SyncRequest struct {
	Protocol        int          `json:"protocol"`
	Version         string       `json:"version"`
	Applied         uint64       `json:"applied_generation"`
	ListenPort      uint16       `json:"listen_port"`
	Endpoints       []string     `json:"endpoints"`
	AdvertiseRoutes []string     `json:"advertise_routes"`
	Error           string       `json:"error,omitempty"`
	Peers           []PeerStatus `json:"peers"`
	Pings           []Ping       `json:"pings"`
}

// SyncResponse carries the node's status and, when it is active, its whole configuration.
type SyncResponse struct {
	Status string  `json:"status"`
	Config *Config `json:"config,omitempty"`
}

// Config is everything an agent applies.
type Config struct {
	Generation uint64 `json:"generation"`
	Name       string `json:"name"`
	MeshCIDR   string `json:"mesh_cidr"`
	// Address is the node's mesh address with the mesh prefix, e.g. 100.96.0.5/16.
	Address    string `json:"address"`
	ListenPort uint16 `json:"listen_port"`
	Peers      []Peer `json:"peers"`
	// Routes are other nodes' shared subnets, reached through the mesh interface.
	Routes []string `json:"routes"`
	// Relay is set when this node forwards traffic between peers that can't connect directly.
	Relay bool `json:"relay"`
	// Shared are this node's own approved subnets; traffic from the mesh to them is forwarded
	// (and masqueraded when Masquerade is set) under the firewall rules.
	Shared     []string `json:"shared"`
	Masquerade bool     `json:"masquerade"`
	Firewall   Firewall `json:"firewall"`
	Hosts      []Host   `json:"hosts"`
}

// Peer is one WireGuard peer.
type Peer struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips"`
	// Keepalive in seconds keeps NAT mappings open and handshakes fresh.
	Keepalive uint16 `json:"keepalive"`
}

// Firewall says what mesh traffic this node accepts. Open accepts everything from the mesh;
// otherwise only Allow entries (and pings when Ping is set) pass.
type Firewall struct {
	Open  bool    `json:"open"`
	Ping  bool    `json:"ping"`
	Allow []Allow `json:"allow"`
}

// Allow lets Sources reach Destinations (this node's address or shared subnets).
type Allow struct {
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
	// Protocol is tcp, udp, icmp or any; Ports ("5432", "8000-8100") apply to tcp and udp.
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
}

// Host is an entry for the managed /etc/hosts block (<name>.mesh).
type Host struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func prefix(text string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(text)
	if err != nil || !p.Addr().Is4() || p != p.Masked() {
		return p, fmt.Errorf("%q is not an IPv4 network", text)
	}
	return p, nil
}

// ValidRoute accepts a subnet a node may share: IPv4, at most /8 wide, not loopback,
// link-local, multicast or the default route.
func ValidRoute(text string) error {
	p, err := prefix(text)
	if err != nil {
		return err
	}
	if p.Bits() < 8 {
		return fmt.Errorf("%s is too wide to share", text)
	}
	a := p.Addr()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return fmt.Errorf("%s cannot be shared", text)
	}
	return nil
}

// ValidEndpoint accepts "IPv4:port".
func ValidEndpoint(text string) error {
	ap, err := netip.ParseAddrPort(text)
	if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
		return fmt.Errorf("%q is not an IPv4 address and port", text)
	}
	return nil
}

func validPorts(ports []string) error {
	for _, p := range ports {
		lo, hi, isRange := strings.Cut(p, "-")
		a, err := strconv.ParseUint(lo, 10, 16)
		if err != nil || a == 0 {
			return fmt.Errorf("invalid port %q", p)
		}
		if isRange {
			b, err := strconv.ParseUint(hi, 10, 16)
			if err != nil || b < a {
				return fmt.Errorf("invalid port range %q", p)
			}
		}
	}
	return nil
}

// Validate checks a configuration before the agent applies any of it.
func (c *Config) Validate() error {
	mesh, err := prefix(c.MeshCIDR)
	if err != nil || mesh.Bits() < 8 || mesh.Bits() > 28 {
		return errors.New("invalid mesh network")
	}
	addr, err := netip.ParsePrefix(c.Address)
	if err != nil || addr.Bits() != mesh.Bits() || !mesh.Contains(addr.Addr()) {
		return errors.New("invalid node address")
	}
	if !ValidName(c.Name) || c.ListenPort == 0 {
		return errors.New("invalid node name or port")
	}
	if len(c.Peers) > MaxPeers || len(c.Routes) > MaxPeers*MaxRoutes || len(c.Hosts) > MaxPeers+1 {
		return errors.New("configuration is too large")
	}
	// Peers may claim the mesh addresses of other nodes and approved subnets; no two peers may
	// claim the same range, and nobody may claim this node's own address.
	var claimed []netip.Prefix
	keys := map[string]bool{}
	for _, peer := range c.Peers {
		if !ValidKey(peer.PublicKey) || keys[peer.PublicKey] || !ValidName(peer.Name) {
			return errors.New("invalid or duplicate peer")
		}
		keys[peer.PublicKey] = true
		if peer.Endpoint != "" {
			if err := ValidEndpoint(peer.Endpoint); err != nil {
				return err
			}
		}
		if peer.Keepalive > 120 {
			return errors.New("invalid keepalive")
		}
		for _, text := range peer.AllowedIPs {
			p, err := prefix(text)
			if err != nil {
				return err
			}
			if mesh.Contains(p.Addr()) {
				if p.Bits() != 32 {
					return fmt.Errorf("peer %s claims a mesh range", peer.Name)
				}
			} else if err := ValidRoute(text); err != nil {
				return err
			}
			if p.Contains(addr.Addr()) {
				return fmt.Errorf("peer %s claims this node's address", peer.Name)
			}
			for _, other := range claimed {
				if other.Overlaps(p) {
					return fmt.Errorf("peer %s overlaps another peer's range", peer.Name)
				}
			}
			claimed = append(claimed, p)
		}
	}
	for _, list := range [][]string{c.Routes, c.Shared} {
		for _, text := range list {
			if err := ValidRoute(text); err != nil {
				return err
			}
			if p, _ := prefix(text); p.Overlaps(mesh) {
				return errors.New("a shared subnet overlaps the mesh network")
			}
		}
	}
	for _, a := range c.Firewall.Allow {
		switch a.Protocol {
		case "tcp", "udp":
			if err := validPorts(a.Ports); err != nil {
				return err
			}
		case "icmp", "any":
			if len(a.Ports) != 0 {
				return errors.New("ports apply to tcp and udp only")
			}
		default:
			return fmt.Errorf("invalid protocol %q", a.Protocol)
		}
		for _, list := range [][]string{a.Sources, a.Destinations} {
			for _, text := range list {
				if _, err := prefix(text); err != nil {
					return err
				}
			}
		}
	}
	for _, h := range c.Hosts {
		ip, err := netip.ParseAddr(h.Address)
		if err != nil || !mesh.Contains(ip) || !ValidName(h.Name) {
			return errors.New("invalid host entry")
		}
	}
	return nil
}

// Check validates a join request (on the coordinator).
func (r *JoinRequest) Check() error {
	if r.Protocol != Version {
		return fmt.Errorf("this agent speaks mesh protocol %d; the coordinator needs %d (upgrade one of them)", r.Protocol, Version)
	}
	if !ValidName(r.Name) {
		return errors.New("node names use lower-case letters, digits and hyphens (at most 32)")
	}
	if !ValidKey(r.PublicKey) {
		return errors.New("invalid WireGuard public key")
	}
	if r.ListenPort == 0 {
		return errors.New("invalid listen port")
	}
	return checkReported(r.Endpoints, r.AdvertiseRoutes, r.OS, r.Version)
}

// Check validates a sync request (on the coordinator).
func (r *SyncRequest) Check() error {
	if r.Protocol != Version {
		return fmt.Errorf("mesh protocol %d is not supported", r.Protocol)
	}
	if r.ListenPort == 0 || len(r.Peers) > MaxPeers || len(r.Pings) > MaxPeers+1 || len(r.Error) > 300 {
		return errors.New("invalid sync request")
	}
	for _, p := range r.Peers {
		if !ValidKey(p.PublicKey) {
			return errors.New("invalid peer status")
		}
		if p.Endpoint != "" {
			if _, err := netip.ParseAddrPort(p.Endpoint); err != nil {
				return errors.New("invalid peer endpoint")
			}
		}
	}
	for _, p := range r.Pings {
		if _, err := netip.ParseAddr(p.Address); err != nil || p.RTTMicros < 0 || p.RTTMicros > 60_000_000 {
			return errors.New("invalid ping result")
		}
	}
	return checkReported(r.Endpoints, r.AdvertiseRoutes, "linux", r.Version)
}

func checkReported(endpoints, routes []string, os, version string) error {
	if len(endpoints) > 16 || len(routes) > MaxRoutes || len(os) > 32 || len(version) > 64 {
		return errors.New("request is too large")
	}
	for _, e := range endpoints {
		if err := ValidEndpoint(e); err != nil {
			return err
		}
	}
	for _, r := range routes {
		if err := ValidRoute(r); err != nil {
			return err
		}
	}
	return nil
}
