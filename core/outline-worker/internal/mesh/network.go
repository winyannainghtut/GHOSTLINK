// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package mesh is the Ghostlink mesh coordinator: the stored network (nodes, invites, access
// rules, shared subnets), the live view agents report, the choice between direct and relayed
// paths, and the configuration each agent receives. It holds no private keys: nodes generate
// theirs and only send the public half.
package mesh

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"ghostlink.local/outline-worker/internal/meshproto"
)

// DefaultCIDR sits inside 100.64.0.0/10 (carrier-grade NAT space), which cloud VPCs and office
// networks almost never use, so mesh addresses rarely collide with existing routes.
const DefaultCIDR = "100.96.0.0/16"

const (
	maxNodes  = meshproto.MaxPeers
	maxTokens = 64
	maxRules  = 200
	// DefaultInviteHours is how long an invite works unless chosen otherwise.
	DefaultInviteHours = 24
)

// Network is the stored mesh.
type Network struct {
	Enabled bool   `json:"enabled"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	// Port is the coordinator's TCP port for agents (join and sync).
	Port uint16 `json:"port"`
	// Ping lets nodes ping each other even when rules restrict traffic (for latency on the map).
	Ping   bool     `json:"ping"`
	Nodes  []*Node  `json:"nodes"`
	Tokens []*Token `json:"tokens"`
	Rules  []Rule   `json:"rules"`
	NextID int      `json:"next_id"`
}

// Node is one member.
type Node struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	Address   string   `json:"address"`
	Tags      []string `json:"tags"`
	Status    string   `json:"status"`
	// Relay nodes forward traffic between nodes that can't connect directly. Only the
	// administrator sets it (an invite can carry it).
	Relay      bool     `json:"relay"`
	ListenPort uint16   `json:"listen_port"`
	Endpoints  []string `json:"endpoints"`
	// AdvertisedRoutes are the subnets the node offers; ApprovedRoutes the ones the
	// administrator accepted.
	AdvertisedRoutes []string `json:"advertised_routes"`
	ApprovedRoutes   []string `json:"approved_routes"`
	// Masquerade makes traffic from the mesh to the node's shared subnets appear to come from the
	// node, so machines there need no route back.
	Masquerade  bool   `json:"masquerade"`
	SecretHash  string `json:"secret_hash"`
	CreatedUnix int64  `json:"created_unix"`
	OS          string `json:"os"`
	Version     string `json:"version"`
}

// Token is an invite. Only its hash is stored.
type Token struct {
	ID          string   `json:"id"`
	Hash        string   `json:"hash"`
	CreatedUnix int64    `json:"created_unix"`
	ExpiresUnix int64    `json:"expires_unix"`
	UsesLeft    int      `json:"uses_left"`
	Tags        []string `json:"tags"`
	Relay       bool     `json:"relay"`
	// Approval makes nodes joining with this invite wait for the administrator.
	Approval bool   `json:"approval"`
	Note     string `json:"note,omitempty"`
}

// Rule allows traffic From some nodes To others. Selectors: "*", "tag:NAME" or "node:NAME".
// Ports apply to tcp and udp ("5432", "8000-8100"); an empty list means every port.
type Rule struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func sameHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// Enable creates the network on first use.
func (n *Network) Enable(cidr, name string, port uint16) error {
	if cidr == "" {
		cidr = DefaultCIDR
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 8 || p.Bits() > 24 {
		return errors.New("the mesh network must be an IPv4 range from /8 to /24, for example 100.96.0.0/16")
	}
	if n.ID == "" {
		n.ID = hex.EncodeToString(random(8))
		n.Ping = true
		n.Name = "Ghostlink mesh"
	}
	if len(n.Nodes) > 0 && cidr != n.CIDR {
		return errors.New("the mesh network can't change while it has nodes")
	}
	if name != "" {
		n.Name = name
	}
	n.CIDR, n.Port, n.Enabled = p.String(), port, true
	return nil
}

func (n *Network) newID() string {
	n.NextID++
	return strconv.Itoa(n.NextID)
}

// Node returns the node with this ID, or nil.
func (n *Network) Node(id string) *Node {
	for _, node := range n.Nodes {
		if node.ID == id {
			return node
		}
	}
	return nil
}

// NodeByName finds a node by name or ID.
func (n *Network) NodeByName(ref string) *Node {
	for _, node := range n.Nodes {
		if node.Name == ref || node.ID == ref {
			return node
		}
	}
	return nil
}

// InviteOptions are chosen when an invite is created.
type InviteOptions struct {
	Tags     []string `json:"tags"`
	Uses     int      `json:"uses"`
	Hours    int      `json:"expires_hours"`
	Relay    bool     `json:"relay"`
	Approval bool     `json:"approval"`
	Note     string   `json:"note"`
}

// CreateToken adds an invite and returns its secret (shown once).
func (n *Network) CreateToken(o InviteOptions, now time.Time) (*Token, string, error) {
	if !n.Enabled {
		return nil, "", errors.New("turn the mesh on first")
	}
	if o.Uses == 0 {
		o.Uses = 1
	}
	if o.Hours == 0 {
		o.Hours = DefaultInviteHours
	}
	if o.Uses < 1 || o.Uses > 1000 || o.Hours < 1 || o.Hours > 24*90 || len(o.Note) > 100 {
		return nil, "", errors.New("an invite works 1-1000 times for 1 hour to 90 days")
	}
	tags, err := cleanTags(o.Tags)
	if err != nil {
		return nil, "", err
	}
	n.pruneTokens(now)
	if len(n.Tokens) >= maxTokens {
		return nil, "", errors.New("too many open invites; revoke some first")
	}
	secret := base64.RawURLEncoding.EncodeToString(random(16))
	t := &Token{
		ID: n.newID(), Hash: hash(secret), CreatedUnix: now.Unix(), ExpiresUnix: now.Add(time.Duration(o.Hours) * time.Hour).Unix(),
		UsesLeft: o.Uses, Tags: tags, Relay: o.Relay, Approval: o.Approval, Note: strings.TrimSpace(o.Note),
	}
	n.Tokens = append(n.Tokens, t)
	return t, secret, nil
}

func (n *Network) pruneTokens(now time.Time) {
	n.Tokens = slices.DeleteFunc(n.Tokens, func(t *Token) bool { return t.UsesLeft <= 0 || now.Unix() >= t.ExpiresUnix })
}

// RevokeToken removes an invite.
func (n *Network) RevokeToken(id string) bool {
	before := len(n.Tokens)
	n.Tokens = slices.DeleteFunc(n.Tokens, func(t *Token) bool { return t.ID == id })
	return len(n.Tokens) != before
}

func cleanTags(tags []string) ([]string, error) {
	out := []string{}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if !meshproto.ValidTag(t) {
			return nil, fmt.Errorf("tag %q: use lower-case letters, digits and hyphens", t)
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) > 16 {
		return nil, errors.New("at most 16 tags")
	}
	return out, nil
}

// ErrInvite is returned for an unknown, used or expired invite (deliberately not saying which).
var ErrInvite = errors.New("this invite is not valid (it may have been used or have expired); create a new one")

// Join adds a node with a valid invite and returns its sync secret.
func (n *Network) Join(r *meshproto.JoinRequest, now time.Time) (*Node, string, error) {
	if !n.Enabled {
		return nil, "", errors.New("the mesh is turned off")
	}
	if err := r.Check(); err != nil {
		return nil, "", err
	}
	n.pruneTokens(now)
	h := hash(r.Token)
	var token *Token
	for _, t := range n.Tokens {
		if sameHash(t.Hash, h) {
			token = t
		}
	}
	if token == nil {
		return nil, "", ErrInvite
	}
	for _, node := range n.Nodes {
		if node.Name == r.Name {
			return nil, "", fmt.Errorf("a node called %s is already in the mesh; choose another name with --name", r.Name)
		}
		if node.PublicKey == r.PublicKey {
			return nil, "", errors.New("this WireGuard key is already in the mesh")
		}
	}
	if len(n.Nodes) >= maxNodes {
		return nil, "", fmt.Errorf("the mesh is full (%d nodes)", maxNodes)
	}
	address, err := n.nextAddress()
	if err != nil {
		return nil, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(random(32))
	status := meshproto.StatusActive
	if token.Approval {
		status = meshproto.StatusPending
	}
	node := &Node{
		ID: n.newID(), Name: r.Name, PublicKey: r.PublicKey, Address: address, Tags: append([]string{}, token.Tags...),
		Status: status, Relay: token.Relay, ListenPort: r.ListenPort, Endpoints: append([]string{}, r.Endpoints...),
		AdvertisedRoutes: append([]string{}, r.AdvertiseRoutes...), ApprovedRoutes: []string{}, Masquerade: true,
		SecretHash: hash(secret), CreatedUnix: now.Unix(), OS: r.OS, Version: r.Version,
	}
	n.Nodes = append(n.Nodes, node)
	token.UsesLeft--
	n.pruneTokens(now)
	return node, secret, nil
}

// Authenticate finds the node a sync secret belongs to ("ID.secret").
func (n *Network) Authenticate(credential string) *Node {
	id, secret, ok := strings.Cut(credential, ".")
	if !ok || secret == "" {
		return nil
	}
	node := n.Node(id)
	if node == nil || !sameHash(node.SecretHash, hash(secret)) {
		return nil
	}
	return node
}

func (n *Network) nextAddress() (string, error) {
	p, _ := netip.ParsePrefix(n.CIDR)
	used := map[netip.Addr]bool{}
	for _, node := range n.Nodes {
		if a, err := netip.ParseAddr(node.Address); err == nil {
			used[a] = true
		}
	}
	for a := p.Addr().Next(); p.Contains(a); a = a.Next() {
		if !used[a] && p.Contains(a.Next()) { // skip the broadcast address
			return a.String(), nil
		}
	}
	return "", errors.New("the mesh network has no free address")
}

// Remove deletes a node; every peer drops it on its next sync.
func (n *Network) Remove(id string) bool {
	before := len(n.Nodes)
	n.Nodes = slices.DeleteFunc(n.Nodes, func(node *Node) bool { return node.ID == id })
	return len(n.Nodes) != before
}

// NodeChange edits a node; nil fields stay as they are.
type NodeChange struct {
	Name           *string   `json:"name"`
	Tags           *[]string `json:"tags"`
	Status         *string   `json:"status"`
	Relay          *bool     `json:"relay"`
	ApprovedRoutes *[]string `json:"approved_routes"`
	Masquerade     *bool     `json:"masquerade"`
}

// Update applies a change to a node.
func (n *Network) Update(node *Node, c NodeChange) error {
	if c.Name != nil {
		if !meshproto.ValidName(*c.Name) {
			return errors.New("node names use lower-case letters, digits and hyphens (at most 32)")
		}
		for _, other := range n.Nodes {
			if other != node && other.Name == *c.Name {
				return fmt.Errorf("a node called %s already exists", *c.Name)
			}
		}
		node.Name = *c.Name
	}
	if c.Tags != nil {
		tags, err := cleanTags(*c.Tags)
		if err != nil {
			return err
		}
		node.Tags = tags
	}
	if c.Status != nil {
		switch *c.Status {
		case meshproto.StatusActive, meshproto.StatusDisabled:
			node.Status = *c.Status
		default:
			return errors.New("status is active or disabled")
		}
	}
	if c.Relay != nil {
		node.Relay = *c.Relay
	}
	if c.Masquerade != nil {
		node.Masquerade = *c.Masquerade
	}
	if c.ApprovedRoutes != nil {
		routes, err := n.checkRoutes(node, *c.ApprovedRoutes)
		if err != nil {
			return err
		}
		node.ApprovedRoutes = routes
	}
	return nil
}

// checkRoutes accepts only subnets the node advertised, that don't overlap the mesh or another
// node's approved subnets.
func (n *Network) checkRoutes(node *Node, routes []string) ([]string, error) {
	mesh, _ := netip.ParsePrefix(n.CIDR)
	out := []string{}
	for _, text := range routes {
		if err := meshproto.ValidRoute(text); err != nil {
			return nil, err
		}
		if !slices.Contains(node.AdvertisedRoutes, text) {
			return nil, fmt.Errorf("%s does not share %s (it advertises %s)", node.Name, text, strings.Join(node.AdvertisedRoutes, ", "))
		}
		p := netip.MustParsePrefix(text)
		if p.Overlaps(mesh) {
			return nil, fmt.Errorf("%s overlaps the mesh network", text)
		}
		for _, other := range n.Nodes {
			if other == node {
				continue
			}
			for _, r := range other.ApprovedRoutes {
				if netip.MustParsePrefix(r).Overlaps(p) {
					return nil, fmt.Errorf("%s overlaps %s, already shared by %s", text, r, other.Name)
				}
			}
		}
		for _, mine := range out {
			if netip.MustParsePrefix(mine).Overlaps(p) {
				return nil, fmt.Errorf("%s overlaps %s", text, mine)
			}
		}
		out = append(out, text)
	}
	return out, nil
}

// SetRules replaces the access rules after checking them.
func (n *Network) SetRules(rules []Rule) error {
	if len(rules) > maxRules {
		return fmt.Errorf("at most %d rules", maxRules)
	}
	for i, r := range rules {
		for _, sel := range []string{r.From, r.To} {
			if err := checkSelector(sel); err != nil {
				return fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
		switch r.Protocol {
		case "tcp", "udp":
		case "icmp", "any":
			if len(r.Ports) > 0 {
				return fmt.Errorf("rule %d: ports apply to tcp and udp only", i+1)
			}
		default:
			return fmt.Errorf("rule %d: protocol is tcp, udp, icmp or any", i+1)
		}
		for _, p := range r.Ports {
			if err := checkPort(p); err != nil {
				return fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
		if rules[i].Ports == nil {
			rules[i].Ports = []string{}
		}
	}
	n.Rules = rules
	return nil
}

func checkSelector(sel string) error {
	switch {
	case sel == "*":
		return nil
	case strings.HasPrefix(sel, "tag:") && meshproto.ValidTag(strings.TrimPrefix(sel, "tag:")):
		return nil
	case strings.HasPrefix(sel, "node:") && meshproto.ValidName(strings.TrimPrefix(sel, "node:")):
		return nil
	}
	return fmt.Errorf("%q: use *, tag:NAME or node:NAME", sel)
}

func checkPort(p string) error {
	lo, hi, isRange := strings.Cut(p, "-")
	a, err := strconv.ParseUint(lo, 10, 16)
	if err != nil || a == 0 {
		return fmt.Errorf("invalid port %q", p)
	}
	if isRange {
		if b, err := strconv.ParseUint(hi, 10, 16); err != nil || b < a {
			return fmt.Errorf("invalid port range %q", p)
		}
	}
	return nil
}

func (r Rule) matches(sel string, node *Node) bool {
	switch {
	case sel == "*":
		return true
	case strings.HasPrefix(sel, "tag:"):
		return slices.Contains(node.Tags, strings.TrimPrefix(sel, "tag:"))
	case strings.HasPrefix(sel, "node:"):
		return node.Name == strings.TrimPrefix(sel, "node:")
	}
	return false
}
