// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// busyServer starts a server whose Shadowsocks port (with a key, so the engine binds it) is
// held by another program.
func busyServer(t *testing.T) (*testServer, net.Listener, uint16) {
	t.Helper()
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { busy.Close() })
	port := uint16(busy.Addr().(*net.TCPAddr).Port)
	server := newTestServer(t, func(s *State) {
		s.Shadowsocks.Port = port
		u := &User{ID: s.newID(), Name: "Early", Enabled: true, Keys: []*Key{}}
		key, err := s.NewKey(u, Shadowsocks)
		if err != nil {
			t.Fatal(err)
		}
		u.Keys = append(u.Keys, key)
		s.Users = append(s.Users, u)
	})
	if health := server.service.Health(); health.EngineError == "" {
		t.Fatal("the engine started on a port another program holds")
	}
	return server, busy, port
}

// A port another program holds when the server starts keeps the VPN engine down, but not the
// management API: the server's own commands can fix it, and the engine starts once it can.
func TestEngineThatCannotStartLeavesTheAPIUp(t *testing.T) {
	server, busy, port := busyServer(t)
	server.must(t, http.StatusOK, "GET", "/server", nil, nil)
	server.service.ensureEngine()
	if running, _ := server.service.engine.Running(); running {
		t.Fatal("the engine started while the port is still held")
	}

	busy.Close()
	server.service.ensureEngine()
	if running, _ := server.service.engine.Running(); !running || server.service.Health().EngineError != "" {
		t.Fatalf("the engine did not start once the port was free: %s", server.service.Health().EngineError)
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err != nil {
		t.Fatalf("Shadowsocks does not listen: %v", err)
	} else {
		conn.Close()
	}

	// A failed restart is retried too: the engine is down after a change it could not apply
	// and could not undo.
	server.service.engine.Close()
	server.service.ensureEngine()
	if running, _ := server.service.engine.Running(); !running {
		t.Fatal("a stopped engine was not started again")
	}
}

// The busy port can be moved with the server's own API, which brings the engine up at once.
func TestABusyPortCanBeMovedAway(t *testing.T) {
	server, _, _ := busyServer(t)
	move := map[string]any{"protocols": map[string]any{Shadowsocks: map[string]any{"port": freeTCPPort(t)}}}
	server.must(t, http.StatusOK, "PATCH", "/server", move, nil)
	if running, _ := server.service.engine.Running(); !running || server.service.Health().EngineError != "" {
		t.Fatalf("the engine is not up after the port moved: %s", server.service.Health().EngineError)
	}
}

// Ports a change moves the dashboard or a protocol to are tried at once, also for protocols
// whose port the engine binds only once they have keys.
func TestPortsAreTriedBeforeTheyAreSaved(t *testing.T) {
	server := newTestServer(t, nil)
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	var before serverInfo
	server.must(t, http.StatusOK, "GET", "/server", nil, &before)
	for _, patch := range []map[string]any{
		{"protocols": map[string]any{VLESS: map[string]any{"port": port}}},
		{"dashboard_port": port},
	} {
		if status := server.call(t, "PATCH", "/server", patch, nil); status != http.StatusBadRequest || !strings.Contains(server.last, "another program") {
			t.Fatalf("%v: status %d: %s", patch, status, server.last)
		}
	}
	// Two protocols may swap their ports.
	swap := map[string]any{"protocols": map[string]any{
		VLESS: map[string]any{"port": before.Protocols[Shadowsocks].Port}, Shadowsocks: map[string]any{"port": before.Protocols[VLESS].Port}}}
	var after serverInfo
	server.must(t, http.StatusOK, "PATCH", "/server", swap, &after)
	if after.Protocols[VLESS].Port != before.Protocols[Shadowsocks].Port || after.Protocols[Shadowsocks].Port != before.Protocols[VLESS].Port {
		t.Fatalf("ports were not swapped: %+v", after.Protocols)
	}
}

// Traffic that could not be saved is counted at the next accounting, not lost.
func TestUsageIsKeptWhenItCannotBeSaved(t *testing.T) {
	server := newTestServer(t, nil)
	user := server.user(t, map[string]any{"name": "Saver"})
	server.service.monitor.user("u" + user.ID).pending.Add(1234)
	dir := server.store.dir
	server.store.dir = filepath.Join(dir, "missing") // every save fails, like a full disk
	if err := server.service.Account(); err == nil {
		t.Fatal("accounting saved into a missing directory")
	}
	server.store.dir = dir
	if err := server.service.Account(); err != nil {
		t.Fatal(err)
	}
	var got userView
	server.must(t, http.StatusOK, "GET", "/users/"+user.ID, nil, &got)
	if got.UsageBytes != 1234 {
		t.Fatalf("usage %d, want 1234", got.UsageBytes)
	}
}

// A port problem in a hand-edited state blocks changes, which say what to fix, but not usage
// accounting, which data limits depend on.
func TestAccountingGoesOnWithAPortProblem(t *testing.T) {
	server := newTestServer(t, func(s *State) {
		s.Dashboard.Port = 80
		s.Users = append(s.Users, &User{ID: s.newID(), Name: "Kept", Enabled: true, Keys: []*Key{}})
	})
	var id string
	server.service.Read(func(s *State) { id = s.Users[0].ID })
	server.service.monitor.user("u" + id).pending.Add(500)
	if err := server.service.Account(); err != nil {
		t.Fatalf("accounting: %v", err)
	}
	var got userView
	server.must(t, http.StatusOK, "GET", "/users/"+id, nil, &got)
	if got.UsageBytes != 500 {
		t.Fatalf("usage %d, want 500", got.UsageBytes)
	}
	if status := server.call(t, "PATCH", "/users/"+id, map[string]any{"name": "Renamed"}, nil); status != http.StatusBadRequest || !strings.Contains(server.last, "dashboard") {
		t.Fatalf("a change in a state with a port problem: %d %s", status, server.last)
	}
}

// The IKEv2/IPsec server certificate is renewed when the server starts, not only after a full
// day of uptime: "setup --hostname" restarts it with a new address, and a server restarted
// daily would otherwise never renew.
func TestIPsecCertificateIsRenewedAtStart(t *testing.T) {
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	server.service.Close()
	server.store.Lock()
	server.store.State.Hostname = "vpn.example.test" // as an older setup --hostname left it
	err := server.store.Save()
	server.store.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	monitor := NewMonitor()
	restarted := NewService(server.store, NewEngine(monitor, "off"), monitor)
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Close() })
	waitFor(t, "a certificate for the new address", func() bool {
		renewed := false
		restarted.Read(func(s *State) { renewed = strings.HasPrefix(s.IPsec.ServerFor, "vpn.example.test") })
		return renewed
	})
}

// A saved hostname change answers 200 even when the management key file cannot be rewritten.
func TestHostnameChangeSurvivesAKeyFileFailure(t *testing.T) {
	server := newTestServer(t, nil)
	var mu sync.Mutex
	var reported []string
	server.service.SetReporter(func(what string, err error) {
		mu.Lock()
		defer mu.Unlock()
		reported = append(reported, fmt.Sprintf("%s: %v", what, err))
	})
	// A directory where the file should go: writing it fails.
	if err := os.MkdirAll(filepath.Join(server.store.Dir(), ManagementKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	var info serverInfo
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"hostname": "vpn.example.test"}, &info)
	if info.Hostname != "vpn.example.test" {
		t.Fatalf("hostname %q", info.Hostname)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 1 || !strings.Contains(reported[0], "management key") {
		t.Fatalf("reported: %v", reported)
	}
}
