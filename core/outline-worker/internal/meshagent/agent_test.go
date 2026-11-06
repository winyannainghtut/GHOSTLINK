// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package meshagent

import (
	"net"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
		!strings.Contains(filter, "-A GHOSTLINK-MESH-FWD -j DROP") {
		t.Error("chains must end with DROP after the accepts")
	}
	if !strings.Contains(rules["nat"], "-A GHOSTLINK-MESH-POST -s 100.96.0.0/16 -d 192.168.50.0/24 ! -o glmesh0 -j MASQUERADE") {
		t.Errorf("nat: %s", rules["nat"])
	}
	open := &meshproto.Config{MeshCIDR: "100.96.0.0/16", Address: "100.96.0.5/16", Firewall: meshproto.Firewall{Open: true}}
	if f := Rules(open, "glmesh0")["filter"]; !strings.Contains(f, "-A GHOSTLINK-MESH-IN -d 100.96.0.5/32 -j ACCEPT") || strings.Contains(f, "-o glmesh0 -j ACCEPT") {
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
