// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The server-side commands run against the real API listener, as on a server.
func TestAdminCommands(t *testing.T) {
	server := newTestServer(t, func(s *State) {
		s.API.Port = freeTCPPort(t)
		s.Dashboard = DashboardConfig{Port: freeTCPPort(t), Token: "dashboard-token-for-test"}
	})
	if err := server.store.WriteManagementKey(); err != nil {
		t.Fatal(err)
	}
	api := NewAPI(server.service, "test")
	httpServer, listener, err := api.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go httpServer.ServeTLS(listener, "", "")
	t.Cleanup(func() { httpServer.Close() })
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := RunAdmin(server.store.Dir(), args, &out)
		return out.String(), err
	}
	must := func(want string, args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("%v: output lacks %q:\n%s", args, want, out)
		}
		return out
	}
	refused := func(want string, args ...string) {
		t.Helper()
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%v should fail with %q, got %v", args, want, err)
		}
	}

	must("Added Alice (id 1)", "user", "add", "Alice", "--limit", "5GB")
	must("5.0 GB", "users")
	refused("already called", "user", "add", "alice")
	key := must("vpn://", "key", "add", "alice", "amneziawg")
	if !strings.Contains(key, "[Interface]") || !strings.ContainsAny(key, "▀▄█") {
		t.Fatalf("key add should print the .conf and a QR code:\n%s", key)
	}
	if out := must("AmneziaWG", "keys", "Alice"); strings.Contains(out, "vpn://") {
		t.Fatal("keys printed key text without --show")
	}
	must("vpn://", "keys", "Alice", "--show")
	keyID := regexp.MustCompile(`\(id (\d+)\)`).FindStringSubmatch(key)[1]
	must("▀", "key", "qr", "Alice", keyID, "--content", "key")
	must("example.com", "rules", "set", "--user", "Alice", "--block-site", "Example.COM")
	must("ads.example", "rules", "set", "--block-site", "ads.example", "--block-bittorrent")
	must("Block BitTorrent   true", "rules")
	must("recorded", "site-stats", "on")
	must("Top sites per user: on", "settings")
	must("Alice", "top", "--once")
	must("Traffic for Alice", "stats", "Alice", "--range", "24h")
	must("Total:", "usage")
	must("No connections", "clients")
	must("<!doctype html>", "kit", "Alice")
	dashboard := must("ssh -N -L 8080:127.0.0.1:", "dashboard")
	if !strings.Contains(dashboard, "#t=dashboard-token-for-test") {
		t.Fatalf("dashboard link: %s", dashboard)
	}
	refused("not 443", "dashboard", "--port", "443")
	must("signed out", "dashboard", "--reset-token")
	// IKEv2/IPsec need the component; then keys come with an Apple profile.
	must("not running", "settings")
	refused("ipsec enable", "set", "--enable", "ikev2")
	fakeAgent(t, server, nil)
	must("Saved", "set", "--enable", "ikev2", "--enable", "ipsec")
	must("IPsec component: running", "settings")
	apple := must("profile Alice", "key", "add", "Alice", "ikev2", "--auth", "certificate", "--remote-id", "vpn.example.test")
	if !strings.Contains(apple, "remote id       vpn.example.test") || strings.ContainsAny(apple, "▀▄█") {
		t.Fatalf("IKEv2 key add output:\n%s", apple)
	}
	appleID := regexp.MustCompile(`\(id (\d+)\)`).FindStringSubmatch(apple)[1]
	must("Warning: IPsec with a pre-shared key is weak", "key", "add", "Alice", "ipsec", "--auth", "psk")
	refused("IKEv2 keys use auth", "key", "add", "Alice", "ikev2", "--auth", "psk")
	must("IKEv2 (iPhone, iPad, Mac) · certificate", "keys", "Alice")
	if profile := must("com.apple.vpn.managed", "profile", "Alice", appleID, "--on-demand"); !strings.Contains(profile, "OnDemandEnabled") {
		t.Fatal("profile --on-demand did not turn on demand on")
	}
	must("reinstall every IPsec PSK profile", "set", "--rotate-ipsec-psk")
	must("Saved", "set", "--disable", "wireguard", "--history-days", "60")
	refused("site_days cannot be longer", "set", "--site-days", "90")
	must("Updated Alice", "user", "limit", "Alice", "none")
	must("Updated Alice", "user", "disable", "Alice")
	out := must("[", "--json", "users")
	var users []adminUser
	if err := json.Unmarshal([]byte(out), &users); err != nil || users[0].Enabled || users[0].DataLimitBytes != 0 {
		t.Fatalf("json users: %v %+v", err, users)
	}
	// Speed limits, in bytes per second.
	must("Updated Alice", "user", "speed", "Alice", "2MB")
	must("2.0 MB/s", "users")
	must("Saved", "set", "--speed-limit", "500KB/s")
	must("Default speed limit: 500 KB/s per client", "settings")
	must("Updated Alice", "user", "speed", "Alice", "default")
	must("500 KB/s (default)", "users")
	must("Updated Alice", "user", "speed", "Alice", "none")
	must("no limit", "users")
	refused("look like 2MB", "user", "speed", "Alice", "fast")
	refused("up to 1.25GB", "user", "speed", "Alice", "5GB")
	must("Added Bob", "user", "add", "Bob", "--speed", "1.5MB")
	if out := must("[", "--json", "users"); !strings.Contains(out, `"speed_limit_bps": 1500000`) {
		t.Fatalf("Bob's speed limit: %s", out)
	}
	must("Saved", "set", "--speed-limit", "none")
	must("Default speed limit: none", "settings")
	refused("no user called", "user", "remove", "Mallory")
	must("Removed Alice", "user", "remove", "Alice")
	must("Removed Bob", "user", "remove", "Bob")
	must("No users yet", "users")

	// Outline's files, imported from a directory (which is left as it was).
	dir := t.TempDir()
	refused("cannot read Outline's shadowbox_config.json", "import-outline", "--dir", dir)
	port := freeSharedPort(t)
	serverJSON, keysJSON := outlineFiles("127.0.0.1", port, nil,
		map[string]any{"name": "Phone", "password": "cGhvbmUtcGFzc3dvcmQ", "port": port},
		map[string]any{"name": "Old", "password": "b2xkLXBhc3N3b3Jk", "port": 80})
	for name, data := range map[string][]byte{outlineServerFile: serverJSON, outlineKeysFile: keysJSON} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	check := must("Check only", "import-outline", "--dir", dir, "--check")
	if !strings.Contains(check, "2 clients") || !strings.Contains(check, "Old: it uses port 80") {
		t.Fatalf("import-outline --check:\n%s", check)
	}
	must("No users yet", "users")
	must("Imported from Outline", "import-outline", "--dir", dir)
	must("Phone", "users")
	if _, err := os.Stat(filepath.Join(dir, outlineKeysFile)); err != nil {
		t.Fatalf("import-outline touched its input: %v", err)
	}
	refused("already has clients", "import-outline", "--dir", dir)
}
