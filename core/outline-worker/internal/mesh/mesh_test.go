// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package mesh

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/meshproto"
)

func publicKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

type fixture struct {
	t   *testing.T
	n   *Network
	l   *Live
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, n: &Network{}, l: NewLive(), now: time.Unix(1_800_000_000, 0)}
	if err := f.n.Enable("", "", 20000); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) join(name string, o InviteOptions, endpoints ...string) *Node {
	f.t.Helper()
	_, secret, err := f.n.CreateToken(o, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	node, _, err := f.n.Join(&meshproto.JoinRequest{Protocol: meshproto.Version, Token: secret, Name: name,
		PublicKey: publicKey(f.t), ListenPort: 51820, Endpoints: endpoints, OS: "linux", Version: "test"}, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return node
}

// sync records a report from node: remote is where the coordinator sees it from, and
// handshakes lists the peers it has a fresh handshake with.
func (f *fixture) sync(node *Node, remote string, handshakes ...*Node) {
	f.t.Helper()
	r := &meshproto.SyncRequest{Protocol: meshproto.Version, ListenPort: 51820}
	for _, peer := range handshakes {
		r.Peers = append(r.Peers, meshproto.PeerStatus{PublicKey: peer.PublicKey, LastHandshake: f.now.Add(-10 * time.Second).Unix(), RxBytes: 1000, TxBytes: 2000})
		r.Pings = append(r.Pings, meshproto.Ping{Address: peer.Address, RTTMicros: 4200})
	}
	f.l.Record(node.ID, netip.MustParseAddr(remote), r, f.now)
}

func (f *fixture) config(node *Node) *meshproto.Config {
	f.t.Helper()
	c, err := f.l.Config(f.n, node, f.now)
	if err != nil {
		f.t.Fatalf("config for %s: %v", node.Name, err)
	}
	return c
}

func peerNamed(c *meshproto.Config, name string) *meshproto.Peer {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return &c.Peers[i]
		}
	}
	return nil
}

func TestInvitesAndJoining(t *testing.T) {
	f := newFixture(t)
	token, secret, err := f.n.CreateToken(InviteOptions{Tags: []string{"Web", "web"}}, f.now)
	if err != nil || token.UsesLeft != 1 || !slices.Equal(token.Tags, []string{"web"}) || strings.Contains(token.Hash, secret) {
		t.Fatalf("token: %+v %v", token, err)
	}
	request := func(name, secret string) *meshproto.JoinRequest {
		return &meshproto.JoinRequest{Protocol: meshproto.Version, Token: secret, Name: name, PublicKey: publicKey(t), ListenPort: 51820}
	}
	a, nodeSecret, err := f.n.Join(request("alpha", secret), f.now)
	if err != nil || a.Address != "100.96.0.1" || a.Status != meshproto.StatusActive || !slices.Equal(a.Tags, []string{"web"}) {
		t.Fatalf("join: %+v %v", a, err)
	}
	if _, _, err := f.n.Join(request("beta", secret), f.now); err != ErrInvite {
		t.Fatalf("a single-use invite worked twice: %v", err)
	}
	if f.n.Authenticate(a.ID+"."+nodeSecret) != a || f.n.Authenticate(a.ID+".wrong") != nil || f.n.Authenticate(nodeSecret) != nil {
		t.Fatal("node authentication")
	}
	_, expiring, _ := f.n.CreateToken(InviteOptions{Hours: 1}, f.now)
	if _, _, err := f.n.Join(request("beta", expiring), f.now.Add(2*time.Hour)); err != ErrInvite {
		t.Fatalf("an expired invite worked: %v", err)
	}
	_, approval, _ := f.n.CreateToken(InviteOptions{Approval: true, Uses: 2}, f.now)
	b, _, err := f.n.Join(request("beta", approval), f.now)
	if err != nil || b.Status != meshproto.StatusPending || b.Address != "100.96.0.2" {
		t.Fatalf("approval invite: %+v %v", b, err)
	}
	if _, _, err := f.n.Join(request("beta", approval), f.now); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, _, err := f.n.Join(request("Bad Name", approval), f.now); err == nil {
		t.Fatal("an invalid name joined")
	}
	if _, err := f.l.Config(f.n, b, f.now); err == nil {
		t.Fatal("a pending node got a configuration")
	}
	if f.n.Remove(a.ID); f.n.Node(a.ID) != nil {
		t.Fatal("remove")
	}
	if err := f.n.Enable("10.0.0.0/8", "", 20000); err == nil {
		t.Fatal("the network changed while it has nodes")
	}
}

// Public nodes connect directly; two nodes behind NAT go through the relay, and their ranges
// move into the relay peer without ever overlapping.
func TestDirectAndRelayedPaths(t *testing.T) {
	f := newFixture(t)
	relay := f.join("relay", InviteOptions{Relay: true}, "203.0.113.1:51820")
	public := f.join("public", InviteOptions{})
	natA := f.join("office-a", InviteOptions{}, "192.168.1.10:51820")
	natB := f.join("office-b", InviteOptions{}, "192.168.7.20:51820")
	f.sync(relay, "203.0.113.1")
	f.sync(public, "198.51.100.7")
	f.sync(natA, "198.51.100.50")  // behind a NAT router; its listen port is not reachable
	f.sync(natB, "198.51.100.200") // behind another one
	// Both offices are reachable at their observed public address only if the NAT is 1:1; the
	// coordinator tries direct first.
	f.l.Tick(f.n, f.now)
	if f.l.relayed(natA, natB) {
		t.Fatal("pair relayed before trying direct")
	}
	// No handshake within the grace period: relay.
	f.now = f.now.Add(directGrace + time.Second)
	f.sync(relay, "203.0.113.1", public, natA, natB)
	f.sync(public, "198.51.100.7", relay, natA, natB)
	f.sync(natA, "198.51.100.50", relay, public)
	f.sync(natB, "198.51.100.200", relay, public)
	if !f.l.Tick(f.n, f.now) || !f.l.relayed(natA, natB) || f.l.relayed(public, natA) {
		t.Fatal("the office pair should be relayed, the rest direct")
	}
	ca := f.config(natA)
	if peerNamed(ca, "office-b") != nil || !slices.Contains(peerNamed(ca, "relay").AllowedIPs, natB.Address+"/32") {
		t.Fatalf("office-a reaches office-b through the relay: %+v", ca.Peers)
	}
	if peerNamed(ca, "public").Endpoint != "198.51.100.7:51820" || peerNamed(ca, "relay").Endpoint != "203.0.113.1:51820" {
		t.Fatalf("endpoints: %+v", ca.Peers)
	}
	if cr := f.config(relay); !cr.Relay || len(cr.Peers) != 3 || peerNamed(cr, "office-a").Keepalive != keepalive {
		t.Fatalf("relay config: %+v", cr)
	}
	topo := f.l.Topology(f.n, f.now)
	var officeLink LinkView
	for _, link := range topo.Links {
		if (link.A == natA.ID && link.B == natB.ID) || (link.A == natB.ID && link.B == natA.ID) {
			officeLink = link
		}
	}
	if officeLink.Path != "relay" || officeLink.Via != relay.ID {
		t.Fatalf("office link: %+v", officeLink)
	}
	// After the relay period, direct is tried again.
	f.now = f.now.Add(relayFor + time.Second)
	f.l.Tick(f.n, f.now)
	if f.l.relayed(natA, natB) {
		t.Fatal("direct was not retried")
	}
	// Nodes behind the same public address use their private addresses.
	f.sync(natB, "198.51.100.50")
	if e := f.l.endpoint(natA, natB); e != "192.168.7.20:51820" {
		t.Fatalf("same-site endpoint: %s", e)
	}
}

func TestGenerationFollowsContent(t *testing.T) {
	f := newFixture(t)
	a := f.join("alpha", InviteOptions{})
	b := f.join("beta", InviteOptions{})
	f.sync(a, "203.0.113.1")
	f.sync(b, "203.0.113.2")
	first := f.config(a).Generation
	if again := f.config(a).Generation; again != first || first == 0 {
		t.Fatal("generation is not stable")
	}
	tags := []string{"db"}
	if err := f.n.Update(b, NodeChange{Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	if err := f.n.SetRules([]Rule{{From: "*", To: "tag:db", Protocol: "tcp", Ports: []string{"5432"}}}); err != nil {
		t.Fatal(err)
	}
	if f.config(a).Generation == first {
		t.Fatal("generation did not change with the rules")
	}
}

func TestRulesCompileToSources(t *testing.T) {
	f := newFixture(t)
	web := f.join("web", InviteOptions{Tags: []string{"web"}})
	db := f.join("db", InviteOptions{Tags: []string{"db"}})
	other := f.join("other", InviteOptions{})
	if c := f.config(db); !c.Firewall.Open {
		t.Fatal("a mesh without rules must be open")
	}
	for _, bad := range [][]Rule{
		{{From: "web", To: "tag:db", Protocol: "tcp"}},
		{{From: "*", To: "tag:db", Protocol: "icmp", Ports: []string{"1"}}},
		{{From: "*", To: "*", Protocol: "sctp"}},
		{{From: "*", To: "*", Protocol: "tcp", Ports: []string{"70000"}}},
	} {
		if err := f.n.SetRules(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if err := f.n.SetRules([]Rule{{From: "tag:web", To: "tag:db", Protocol: "tcp", Ports: []string{"5432"}}, {From: "node:db", To: "*", Protocol: "icmp"}}); err != nil {
		t.Fatal(err)
	}
	fw := f.config(db).Firewall
	if fw.Open || len(fw.Allow) != 1 || !slices.Equal(fw.Allow[0].Sources, []string{web.Address + "/32"}) ||
		!slices.Equal(fw.Allow[0].Destinations, []string{db.Address + "/32"}) || fw.Allow[0].Protocol != "tcp" {
		t.Fatalf("db firewall: %+v", fw)
	}
	if fw := f.config(other).Firewall; len(fw.Allow) != 1 || fw.Allow[0].Protocol != "icmp" || fw.Allow[0].Sources[0] != db.Address+"/32" {
		t.Fatalf("other firewall: %+v", fw)
	}
}

func TestSharedSubnets(t *testing.T) {
	f := newFixture(t)
	_, secret, _ := f.n.CreateToken(InviteOptions{}, f.now)
	router, _, err := f.n.Join(&meshproto.JoinRequest{Protocol: meshproto.Version, Token: secret, Name: "office", PublicKey: publicKey(t),
		ListenPort: 51820, AdvertiseRoutes: []string{"192.168.50.0/24", "10.20.0.0/16"}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	other := f.join("cloud", InviteOptions{})
	if c := f.config(other); len(c.Routes) != 0 || len(peerNamed(c, "office").AllowedIPs) != 1 {
		t.Fatal("a subnet was shared before approval")
	}
	for _, bad := range [][]string{{"172.16.0.0/12"}, {"100.96.0.0/24"}, {"192.168.50.0/24", "192.168.50.0/25"}} {
		if err := f.n.Update(router, NodeChange{ApprovedRoutes: &bad}); err == nil {
			t.Fatalf("approved %v", bad)
		}
	}
	approve := []string{"192.168.50.0/24"}
	if err := f.n.Update(router, NodeChange{ApprovedRoutes: &approve}); err != nil {
		t.Fatal(err)
	}
	c := f.config(other)
	if !slices.Equal(c.Routes, approve) || !slices.Contains(peerNamed(c, "office").AllowedIPs, "192.168.50.0/24") {
		t.Fatalf("cloud config: %+v", c)
	}
	if r := f.config(router); !slices.Equal(r.Shared, approve) || !r.Masquerade {
		t.Fatalf("router config: %+v", r)
	}
	if hosts := c.Hosts; len(hosts) != 2 {
		t.Fatalf("hosts: %+v", hosts)
	}
}

func TestConfigValidationRefusesUnsafeInput(t *testing.T) {
	f := newFixture(t)
	a := f.join("alpha", InviteOptions{})
	f.join("beta", InviteOptions{})
	good := f.config(a)
	for name, mutate := range map[string]func(c *meshproto.Config){
		"peer claims own address": func(c *meshproto.Config) { c.Peers[0].AllowedIPs = append(c.Peers[0].AllowedIPs, a.Address+"/32") },
		"peer claims mesh range":  func(c *meshproto.Config) { c.Peers[0].AllowedIPs = []string{"100.96.0.0/24"} },
		"default route":           func(c *meshproto.Config) { c.Peers[0].AllowedIPs = append(c.Peers[0].AllowedIPs, "0.0.0.0/0") },
		"bad key":                 func(c *meshproto.Config) { c.Peers[0].PublicKey = "x" },
		"bad endpoint":            func(c *meshproto.Config) { c.Peers[0].Endpoint = "example.com:1" },
		"name injection":          func(c *meshproto.Config) { c.Peers[0].Name = "a\nb" },
		"bad protocol":            func(c *meshproto.Config) { c.Firewall.Allow = []meshproto.Allow{{Protocol: "gre"}} },
		"host outside mesh":       func(c *meshproto.Config) { c.Hosts = []meshproto.Host{{Name: "x", Address: "8.8.8.8"}} },
		"address outside mesh":    func(c *meshproto.Config) { c.Address = "10.0.0.1/16" },
	} {
		c := *good
		c.Peers = append([]meshproto.Peer{}, good.Peers...)
		c.Peers[0].AllowedIPs = append([]string{}, good.Peers[0].AllowedIPs...)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	invite := meshproto.EncodeInvite(meshproto.Invite{URL: "https://203.0.113.1:20000", Pin: strings.Repeat("A", 64), Token: "abcdefghijklmnopqrstuv"})
	if got, err := meshproto.DecodeInvite("  " + invite + "\n"); err != nil || got.URL != "https://203.0.113.1:20000" {
		t.Fatalf("invite round trip: %+v %v", got, err)
	}
	if _, err := meshproto.DecodeInvite("glmesh1:not-base64!"); err == nil {
		t.Fatal("a damaged invite decoded")
	}
}
