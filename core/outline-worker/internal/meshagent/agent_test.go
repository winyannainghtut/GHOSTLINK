// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package meshagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"ghostlink.local/outline-worker/internal/hostfw"
	"ghostlink.local/outline-worker/internal/meshproto"
)

func key(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func TestFirewallRules(t *testing.T) {
	c := &meshproto.Config{MeshCIDR: "100.96.0.0/16", Address: "100.96.0.5/16", Shared: []string{"192.168.50.0/24"}, Masquerade: true, Relay: true,
		Firewall: meshproto.Firewall{Ping: true, Allow: []meshproto.Allow{
			{Sources: []string{"100.96.0.1/32", "100.96.0.2/32"}, Destinations: []string{"100.96.0.5/32"}, Protocol: "tcp", Ports: []string{"5432", "8000-8100"}},
			{Sources: []string{"100.96.0.3/32"}, Destinations: []string{"100.96.0.5/32", "192.168.50.0/24"}, Protocol: "any"},
		}}}
	rules := Rules(c, "glmesh0")
	filter := rules["filter"]
	for _, want := range []string{
		"-A GHOSTLINK-MESH-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A GHOSTLINK-MESH-IN -d 100.96.0.5/32 -p icmp --icmp-type echo-request -j ACCEPT",
		"-A GHOSTLINK-MESH-IN -s 100.96.0.2/32 -d 100.96.0.5/32 -p tcp --dport 8000:8100 -j ACCEPT",
		"-A GHOSTLINK-MESH-IN -s 100.96.0.3/32 -d 100.96.0.5/32 -j ACCEPT",
		"-A GHOSTLINK-MESH-FWD -o glmesh0 -j ACCEPT",
		"-A GHOSTLINK-MESH-FWD -s 100.96.0.3/32 -d 192.168.50.0/24 -j ACCEPT",
		"-A GHOSTLINK-MESH-OUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		// Published container ports (DNAT from the mesh address) follow the same rules, by the
		// port the peer connected to.
		"-A GHOSTLINK-MESH-FWD -s 100.96.0.2/32 -m conntrack --ctstate DNAT --ctorigdst 100.96.0.5/32 -p tcp --ctorigdstport 8000:8100 -j ACCEPT",
		"-A GHOSTLINK-MESH-FWD -s 100.96.0.3/32 -m conntrack --ctstate DNAT --ctorigdst 100.96.0.5/32 -j ACCEPT",
		// The node's own address in its shared subnet (a LAN gateway) is part of the node.
		"-A GHOSTLINK-MESH-IN -s 100.96.0.3/32 -d 192.168.50.0/24 -j ACCEPT",
		"-A GHOSTLINK-MESH-IN -d 192.168.50.0/24 -p icmp --icmp-type echo-request -j ACCEPT",
	} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter lacks %q", want)
		}
	}
	if strings.Contains(filter, "-s 100.96.0.1/32 -d 192.168.50.0/24") {
		t.Error("a rule for this node was applied to its shared subnet")
	}
	// Each chain ends by dropping what was not allowed.
	if strings.Index(filter, "-A GHOSTLINK-MESH-IN -j DROP") < strings.LastIndex(filter, "-A GHOSTLINK-MESH-IN -s") ||
		strings.Index(filter, "-A GHOSTLINK-MESH-FWD -j DROP") < strings.LastIndex(filter, "-A GHOSTLINK-MESH-FWD -s") {
		t.Error("chains must end with DROP after the accepts")
	}
	if !strings.Contains(rules["nat"], "-A GHOSTLINK-MESH-POST -s 100.96.0.0/16 -d 192.168.50.0/24 ! -o glmesh0 -j MASQUERADE") {
		t.Errorf("nat: %s", rules["nat"])
	}
	// The guards (mangle): replies and ICMP errors go on, everything else a peer sends must match
	// the same rules on every packet, and what does not is dropped before the filter table, where
	// Docker's accept rules may come first (code review 2026-11-10, R1).
	mangle := rules["mangle"]
	for _, want := range []string{
		":GHOSTLINK-MESH-GUARD-IN - [0:0]",
		"-A GHOSTLINK-MESH-GUARD-IN -m conntrack --ctdir REPLY -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-IN -m conntrack --ctstate RELATED -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-IN -d 100.96.0.5/32 -p icmp --icmp-type echo-request -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-IN -s 100.96.0.2/32 -d 100.96.0.5/32 -p tcp --dport 8000:8100 -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-IN -s 100.96.0.3/32 -d 192.168.50.0/24 -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-FWD -m conntrack --ctdir REPLY -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-FWD -s 100.96.0.2/32 -m conntrack --ctstate DNAT --ctorigdst 100.96.0.5/32 -p tcp --ctorigdstport 8000:8100 -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-FWD -o glmesh0 -j RETURN",
		"-A GHOSTLINK-MESH-GUARD-FWD -s 100.96.0.3/32 -d 192.168.50.0/24 -j RETURN",
	} {
		if !strings.Contains(mangle, want) {
			t.Errorf("mangle lacks %q", want)
		}
	}
	for _, chain := range []string{"GHOSTLINK-MESH-GUARD-IN", "GHOSTLINK-MESH-GUARD-FWD"} {
		if strings.Index(mangle, "-A "+chain+" -j DROP") < strings.LastIndex(mangle, "-A "+chain+" -") {
			t.Errorf("%s must end with DROP", chain)
		}
	}
	// A guard never lets a connection through for being established: that is how one opened
	// while the rules were missing would outlive them.
	if strings.Contains(mangle, "ESTABLISHED") || strings.Contains(mangle, "GUARD-FWD -j ACCEPT") || strings.Contains(mangle, "GUARD-IN -j ACCEPT") {
		t.Errorf("a guard accepts established connections or ends early:\n%s", mangle)
	}
	guards := 0
	for _, j := range Jumps("glmesh0") {
		if j.Table == "mangle" && (j.Target == "GHOSTLINK-MESH-GUARD-IN" || j.Target == "GHOSTLINK-MESH-GUARD-FWD") {
			guards++
			if strings.Join(j.Match, " ") != "-i glmesh0" || j.Docker {
				t.Errorf("guard jump %+v", j)
			}
		}
	}
	if guards != 2 || !slices.Contains(Chains()["mangle"], "GHOSTLINK-MESH-GUARD-FWD") || !slices.Contains(Chains()["mangle"], "GHOSTLINK-MESH-GUARD-IN") {
		t.Errorf("guard jumps %d, mangle chains %v", guards, Chains()["mangle"])
	}
	open := &meshproto.Config{MeshCIDR: "100.96.0.0/16", Address: "100.96.0.5/16", Firewall: meshproto.Firewall{Open: true}}
	if f := Rules(open, "glmesh0")["filter"]; !strings.Contains(f, "-A GHOSTLINK-MESH-IN -d 100.96.0.5/32 -j ACCEPT") || strings.Contains(f, "-o glmesh0 -j ACCEPT") ||
		!strings.Contains(f, "-A GHOSTLINK-MESH-FWD -m conntrack --ctstate DNAT --ctorigdst 100.96.0.5/32 -j ACCEPT") {
		t.Errorf("open, not relay: %s", f)
	}
	for _, j := range Jumps("glmesh0") {
		if j.Table == "filter" && len(j.Match) != 2 {
			t.Errorf("filter jump %s must match the mesh interface", j.Chain)
		}
	}
}

func TestHostsBlock(t *testing.T) {
	original := "127.0.0.1 localhost\n::1 localhost\n"
	entries := []meshproto.Host{{Name: "web-1", Address: "100.96.0.1"}, {Name: "db-1", Address: "100.96.0.2"}}
	once := RenderHosts(original, entries)
	if !strings.HasPrefix(once, original) || !strings.Contains(once, "100.96.0.2\tdb-1.mesh\n") {
		t.Fatalf("hosts: %q", once)
	}
	if again := RenderHosts(once, entries); again != once {
		t.Fatal("rendering twice changed the file")
	}
	if updated := RenderHosts(once, entries[:1]); strings.Contains(updated, "db-1") || strings.Count(updated, hostsBegin) != 1 {
		t.Fatalf("update: %q", updated)
	}
	if removed := RenderHosts(once, nil); removed != original {
		t.Fatalf("removing the block left %q", removed)
	}
}

func TestPeerChangesKeepSessions(t *testing.T) {
	kept, gone, added := key(t), key(t), key(t)
	_, allowed, _ := net.ParseCIDR("100.96.0.2/32")
	current := []wgtypes.Peer{{PublicKey: kept, AllowedIPs: []net.IPNet{*allowed}}, {PublicKey: gone}}
	wanted := []meshproto.Peer{
		{Name: "kept", PublicKey: kept.String(), Endpoint: "203.0.113.2:51820", AllowedIPs: []string{"100.96.0.2/32", "10.20.0.0/24"}, Keepalive: 25},
		{Name: "added", PublicKey: added.String(), AllowedIPs: []string{"100.96.0.3/32"}, Keepalive: 25},
	}
	changes, applied, err := PeerChanges(current, wanted, map[string]string{kept.String(): "203.0.113.2:51820"})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[wgtypes.Key]wgtypes.PeerConfig{}
	for _, c := range changes {
		byKey[c.PublicKey] = c
	}
	if c := byKey[kept]; !c.UpdateOnly || c.Remove || !c.ReplaceAllowedIPs || len(c.AllowedIPs) != 2 || c.Endpoint != nil {
		t.Fatalf("kept peer: %+v (the endpoint must not be reset while unchanged)", c)
	}
	if c := byKey[added]; c.UpdateOnly || c.Endpoint != nil || *c.PersistentKeepaliveInterval == 0 {
		t.Fatalf("added peer: %+v", c)
	}
	if c := byKey[gone]; !c.Remove {
		t.Fatalf("gone peer: %+v", c)
	}
	if applied[kept.String()] != "203.0.113.2:51820" {
		t.Fatalf("applied endpoints: %v", applied)
	}
	// A new suggestion from the coordinator is applied.
	wanted[0].Endpoint = "198.51.100.9:51820"
	changes, _, _ = PeerChanges(current, wanted, applied)
	for _, c := range changes {
		if c.PublicKey == kept && (c.Endpoint == nil || c.Endpoint.String() != "198.51.100.9:51820") {
			t.Fatalf("changed endpoint not applied: %+v", c)
		}
	}
	if _, _, err := PeerChanges(nil, []meshproto.Peer{{Name: "x", PublicKey: "bad"}}, nil); err == nil {
		t.Fatal("a bad key was accepted")
	}
}

// Without the node's own consent it neither relays nor shares subnets, whatever the
// coordinator says, even where IPv4 forwarding is already on.
func TestForwardingNeedsConsent(t *testing.T) {
	c := &meshproto.Config{MeshCIDR: "100.96.0.0/16", Address: "100.96.0.5/16", Relay: true, Shared: []string{"192.168.50.0/24"},
		Masquerade: true, Firewall: meshproto.Firewall{Open: true}}
	without := (&Node{Interface: "glmesh0"}).rules(c)
	if strings.Contains(without["filter"], "-o glmesh0 -j ACCEPT") || strings.Contains(without["filter"], "192.168.50.0/24") ||
		strings.Contains(without["nat"], "MASQUERADE") {
		t.Fatalf("forwarding rules without consent:\n%s%s", without["filter"], without["nat"])
	}
	with := (&Node{Interface: "glmesh0", Forwarding: true}).rules(c)
	if !strings.Contains(with["filter"], "-A GHOSTLINK-MESH-FWD -o glmesh0 -j ACCEPT") || !strings.Contains(with["nat"], "MASQUERADE") {
		t.Fatalf("forwarding rules with consent:\n%s%s", with["filter"], with["nat"])
	}
	if !c.Relay || len(c.Shared) != 1 {
		t.Fatal("rendering changed the configuration itself")
	}
}

// The firewall goes in before the interface: when it fails, nothing is open to the mesh.
func TestFirewallBeforeInterface(t *testing.T) {
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Dir: t.TempDir(), Node: &Node{Name: "alpha", Interface: "gltest9", PrivateKey: private.String(), Forwarding: true},
		FW: &hostfw.Firewall{}} // an unknown backend: every firewall call fails
	c := &meshproto.Config{Name: "alpha", MeshCIDR: "100.96.0.0/16", Address: "100.96.0.5/16", ListenPort: 51820, Relay: true,
		Firewall: meshproto.Firewall{Open: true}, Peers: []meshproto.Peer{
			{Name: "beta", PublicKey: key(t).String(), Endpoint: "203.0.113.2:51820", AllowedIPs: []string{"100.96.0.6/32"}, Keepalive: 25}}}
	err = a.apply(c)
	if err == nil || !strings.HasPrefix(err.Error(), "firewall:") || a.dev != nil || a.applied != nil {
		t.Fatalf("apply: %v (interface opened: %v)", err, a.dev != nil)
	}
}

// Other nodes' shared subnets are not routed into the mesh where that would replace one of this
// machine's routes, cut it off from its own LAN, or loop its traffic to a peer.
func TestMeshRoutesLeaveLocalNetworks(t *testing.T) {
	prefixes := func(list ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, p := range list {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}
	// A LAN host: on 192.168.50.0/24, with another VPN routing 10.20.0.0/16 and 172.16.0.0/12.
	connected := prefixes("192.168.50.0/24")
	routed := prefixes("192.168.50.0/24", "10.20.0.0/16", "172.16.0.0/12")
	keep, skip := meshRoutes([]string{"192.168.50.0/24", "192.168.50.0/25", "10.20.0.0/16", "10.30.0.0/16", "172.16.5.0/24", "192.168.0.0/16"},
		connected, routed, []netip.Addr{netip.MustParseAddr("192.168.50.7")})
	// Wider or narrower than someone else's route is fine: the more specific route wins, and the
	// LAN route keeps the peer at 192.168.50.7 off the mesh route 192.168.0.0/16.
	if !slices.Equal(keep, []string{"10.30.0.0/16", "172.16.5.0/24", "192.168.0.0/16"}) ||
		!slices.Equal(skip, []string{"192.168.50.0/24", "192.168.50.0/25", "10.20.0.0/16"}) {
		t.Fatalf("LAN host: keep %v, skip %v", keep, skip)
	}
	// A cloud VM with a /32 address: the subnet router in its VPC is a peer at 10.128.0.9, so
	// routing the VPC range into the mesh would loop.
	keep, skip = meshRoutes([]string{"10.128.0.0/20", "10.140.0.0/20"}, prefixes("10.128.0.5/32"), prefixes("10.128.0.1/32"),
		[]netip.Addr{netip.MustParseAddr("10.128.0.9"), netip.MustParseAddr("203.0.113.4")})
	if !slices.Equal(keep, []string{"10.140.0.0/20"}) || !slices.Equal(skip, []string{"10.128.0.0/20"}) {
		t.Fatalf("cloud VM: keep %v, skip %v", keep, skip)
	}
}

// Leaving keeps IPv4 forwarding on where container or VM networking may rely on it.
func TestForwardingUsers(t *testing.T) {
	if got := forwardingUsers([]string{"lo", "eth0", "ens3"}); len(got) != 0 {
		t.Fatalf("plain server: %v", got)
	}
	if got := forwardingUsers([]string{"lo", "eth0", "docker0", "br-3f2a19c0", "virbr0"}); !slices.Equal(got, []string{"Docker", "libvirt"}) {
		t.Fatalf("Docker and libvirt host: %v", got)
	}
}

// fakeCoordinator answers every sync with status and counts them.
func fakeCoordinator(t *testing.T, status string) (*Node, *atomic.Int32) {
	t.Helper()
	syncs := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncs.Add(1)
		_ = json.NewEncoder(w).Encode(meshproto.SyncResponse{Status: status})
	}))
	t.Cleanup(server.Close)
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(server.Certificate().Raw)
	// Hosts stays off and the firewall backend unknown, so the agent touches nothing on this machine.
	return &Node{URL: server.URL, Pin: hex.EncodeToString(sum[:]), NodeID: "1", Secret: "1.secret", PrivateKey: private.String(),
		Name: "alpha", Address: "100.96.0.5", Interface: "gltest9", ListenPort: 51820}, syncs
}

// A node waiting for approval asks again only after a pause, even when the coordinator answers
// at once.
func TestWaitingNodeDoesNotBusyLoop(t *testing.T) {
	node, syncs := fakeCoordinator(t, meshproto.StatusPending)
	dir := t.TempDir()
	if err := node.Save(dir); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Dir: dir, Node: node, Log: log.New(io.Discard, "", 0), FW: &hostfw.Firewall{}, Version: "test"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Serve(ctx); err != nil {
		t.Fatal(err)
	}
	if n := syncs.Load(); n != 1 {
		t.Fatalf("%d syncs in 3 s while waiting for approval", n)
	}
	if s, err := ReadStatus(dir); err != nil || s.State != meshproto.StatusPending {
		t.Fatalf("status: %+v %v", s, err)
	}
}

// A node told it is disabled while it has a configuration takes it down and asks again without
// a pause (a current coordinator then waits for a change); it pauses only once there is nothing
// left to take down.
func TestDisabledNodeAsksAgainAfterTeardown(t *testing.T) {
	node, syncs := fakeCoordinator(t, meshproto.StatusDisabled)
	dir := t.TempDir()
	if err := node.Save(dir); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Dir: dir, Node: node, Log: log.New(io.Discard, "", 0), FW: &hostfw.Firewall{}, Version: "test",
		applied: &meshproto.Config{Generation: 7}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Serve(ctx); err != nil {
		t.Fatal(err)
	}
	if n := syncs.Load(); n != 2 || a.applied != nil {
		t.Fatalf("%d syncs in 3 s, applied %v", n, a.applied)
	}
}

// After `ghostlink-mesh leave` removed the node here (the coordinator could not be told), the
// running agent stops instead of setting the node up again.
func TestAgentStopsAfterLeave(t *testing.T) {
	node, syncs := fakeCoordinator(t, meshproto.StatusActive)
	dir := t.TempDir()
	a := &Agent{Dir: dir, Node: node, Log: log.New(io.Discard, "", 0), FW: &hostfw.Firewall{}, Version: "test"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if err := a.Serve(ctx); err != nil || time.Since(started) > 2*time.Second || syncs.Load() != 0 {
		t.Fatalf("serve: %v after %v, %d syncs", err, time.Since(started), syncs.Load())
	}
}
