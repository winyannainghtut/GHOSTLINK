// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Speeds are bytes per second. A lower-case b is a bit, so those spellings are refused rather
// than read as eight times the speed meant.
func TestParseSpeed(t *testing.T) {
	for text, want := range map[string]int64{
		"2MB": 2_000_000, "2mB": 2_000_000, "500KB/s": 500_000, "500KB/S": 500_000, "2MBps": 2_000_000,
		"2MBPS": 2_000_000, "2 MB/s": 2_000_000, "1.5MB": 1_500_000, "2M": 2_000_000, "64k": 64_000, "1.25GB": 1_250_000_000,
	} {
		if got, keyword, err := parseSpeed(text); err != nil || keyword != "" || got != want {
			t.Errorf("parseSpeed(%q) = %d %q %v, want %d", text, got, keyword, err, want)
		}
	}
	for text, keyword := range map[string]string{"none": "none", "Off": "none", "unlimited": "none", "default": "default"} {
		if _, got, err := parseSpeed(text); err != nil || got != keyword {
			t.Errorf("parseSpeed(%q) keyword %q %v, want %q", text, got, err, keyword)
		}
	}
	for _, text := range []string{"10Mbps", "10mbps", "10Mb/s", "10Mb", "10 mb", "500kb", "8mbit", "8Mbit/s", "2Mps", "2b/s"} {
		if _, _, err := parseSpeed(text); err == nil || !strings.Contains(err.Error(), "bytes per second") {
			t.Errorf("parseSpeed(%q) should be refused as bits, got %v", text, err)
		}
	}
	for text, want := range map[string]string{"fast": "look like 2MB", "2": "look like 2MB", "500B": "look like 2MB", "0MB": "look like 2MB", "5GB": "up to 1.25GB"} {
		if _, _, err := parseSpeed(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseSpeed(%q) should fail with %q, got %v", text, want, err)
		}
	}
}

// adminCommands serves the test server's API on its real listener, as on a server, and returns
// a runner for the server-side commands.
func adminCommands(t *testing.T, server *testServer) func(args ...string) (string, error) {
	t.Helper()
	if err := server.store.WriteManagementKey(); err != nil {
		t.Fatal(err)
	}
	httpServer, listener, err := NewAPI(server.service, "test").Listen()
	if err != nil {
		t.Fatal(err)
	}
	go httpServer.ServeTLS(listener, "", "")
	t.Cleanup(func() { httpServer.Close() })
	return func(args ...string) (string, error) {
		var out bytes.Buffer
		err := RunAdmin(server.store.Dir(), args, &out)
		return out.String(), err
	}
}

// The server-side commands run against the real API listener, as on a server.
func TestAdminCommands(t *testing.T) {
	server := newTestServer(t, func(s *State) {
		s.API.Port = freeTCPPort(t)
		s.Dashboard = DashboardConfig{Port: freeTCPPort(t), Token: "dashboard-token-for-test"}
	})
	run := adminCommands(t, server)
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
	// A word left over is refused, not dropped: a switch takes no value, so "--exempt false"
	// would turn it on and lose --limit.
	refused(`unexpected "false"`, "user", "add", "Bob", "--exempt", "false", "--limit", "5GB")
	refused(`unexpected "Carol"`, "user", "add", "Bob", "Carol")
	if out := must("Alice", "users"); strings.Contains(out, "Bob") {
		t.Fatalf("a refused user add created Bob:\n%s", out)
	}
	refused("one user at a time", "user", "disable", "Alice", "Bob")
	refused(`unexpected "once"`, "top", "once")
	refused(`unexpected "false"`, "mesh", "invite", "--relay", "false", "--tags", "web")
	key := must("vpn://", "key", "add", "alice", "amneziawg")
	if !strings.Contains(key, "[Interface]") || !strings.ContainsAny(key, "▀▄█") {
		t.Fatalf("key add should print the .conf and a QR code:\n%s", key)
	}
	if out := must("AmneziaWG", "keys", "Alice"); strings.Contains(out, "vpn://") {
		t.Fatal("keys printed key text without --show")
	}
	must("vpn://", "keys", "Alice", "--show")
	refused(`unexpected "extra"`, "keys", "Alice", "--show", "extra")
	keyID := regexp.MustCompile(`\(id (\d+)\)`).FindStringSubmatch(key)[1]
	must("▀", "key", "qr", "Alice", keyID, "--content", "key")
	// "key qr" exists only to show the QR code, so a missing one is an error.
	refused("no QR code", "key", "qr", "Alice", "999")
	refused("no QR code", "key", "qr", "Alice", keyID, "--content", "nonsense")
	must("example.com", "rules", "set", "--user", "Alice", "--block-site", "Example.COM")
	must("ads.example", "rules", "set", "--block-site", "ads.example", "--block-bittorrent")
	must("Block BitTorrent   true", "rules")
	// "rules set" replaces every rule, so a stray word must not drop or flip any of them.
	refused(`unexpected "b.example"`, "rules", "set", "--block-site", "a.example", "b.example")
	refused(`unexpected "false"`, "rules", "set", "--block-bittorrent", "false", "--block-smtp")
	if out := must("Block BitTorrent   true", "rules"); !strings.Contains(out, "ads.example") || strings.Contains(out, "a.example,") {
		t.Fatalf("a refused rules set changed the rules:\n%s", out)
	}
	must("recorded", "site-stats", "on")
	must("Top sites per user: on", "settings")
	// --json works with set, site-stats and dashboard too: the settings after the change.
	var settings serverInfo
	if out := must("{", "--json", "site-stats", "on"); json.Unmarshal([]byte(out), &settings) != nil || !settings.SiteStats {
		t.Fatalf("--json site-stats on:\n%s", out)
	}
	must("Alice", "top", "--once")
	must("Traffic for Alice", "stats", "Alice", "--range", "24h")
	refused(`unexpected "Alice"`, "stats", "--range", "24h", "Alice")
	must("Total:", "usage")
	must("No connections", "clients")
	must("<!doctype html>", "kit", "Alice")
	dashboard := must("ssh -N -L 8080:127.0.0.1:", "dashboard")
	if !strings.Contains(dashboard, "#t=dashboard-token-for-test") {
		t.Fatalf("dashboard link: %s", dashboard)
	}
	refused("not 443", "dashboard", "--port", "443")
	refused(`unexpected "false"`, "dashboard", "--public", "false")
	must("Dashboard: private", "dashboard")
	var board struct {
		Port   uint16 `json:"port"`
		Public bool   `json:"public"`
		Token  string `json:"token"`
	}
	if out := must("{", "--json", "dashboard"); json.Unmarshal([]byte(out), &board) != nil || board.Token != "dashboard-token-for-test" || board.Public || board.Port == 0 {
		t.Fatalf("--json dashboard:\n%s", out)
	}
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
	// Without --auth, "certificate" would be dropped and an EAP key created.
	refused(`unexpected "certificate"`, "key", "add", "Alice", "ikev2", "certificate")
	refused(`unexpected "extra"`, "profile", "Alice", appleID, "--on-demand", "extra")
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
	if out := must("{", "--json", "set", "--speed-limit", "400KB"); json.Unmarshal([]byte(out), &settings) != nil || settings.DefaultSpeedLimitBps != 400_000 {
		t.Fatalf("--json set:\n%s", out)
	}
	refused(`unexpected "extra"`, "set", "--speed-limit", "500KB/s", "extra")
	must("Saved", "set", "--speed-limit", "500KB/s")
	must("Updated Alice", "user", "speed", "Alice", "default")
	must("500 KB/s (default)", "users")
	must("Updated Alice", "user", "speed", "Alice", "none")
	must("no limit", "users")
	refused("look like 2MB", "user", "speed", "Alice", "fast")
	refused("bytes per second", "user", "speed", "Alice", "10Mbps")
	refused("bytes per second", "user", "speed", "Alice", "10Mb/s")
	refused("bytes per second", "set", "--speed-limit", "8mbit")
	must("Updated Alice", "user", "speed", "Alice", "2MBps")
	must("2.0 MB/s", "users")
	must("Updated Alice", "user", "speed", "Alice", "none")
	refused("up to 1.25GB", "user", "speed", "Alice", "5GB")
	must("Added Bob", "user", "add", "Bob", "--speed", "1.5MB")
	if out := must("[", "--json", "users"); !strings.Contains(out, `"speed_limit_bps": 1500000`) {
		t.Fatalf("Bob's speed limit: %s", out)
	}
	must("Saved", "set", "--speed-limit", "none")
	must("Default speed limit: none", "settings")
	refused("no user called", "user", "remove", "Mallory")
	refused("one user at a time", "user", "remove", "Alice", "Bob")
	if out := must("Bob", "users"); !strings.Contains(out, "Alice") {
		t.Fatalf("a refused user remove removed Alice:\n%s", out)
	}
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

// On a new server the commands point at Shadowsocks, and turning a protocol on, or moving one,
// says which port to allow.
func TestAdminCommandsOnANewServer(t *testing.T) {
	server := newTestServer(t, func(s *State) {
		onlyShadowsocks(s)
		s.API.Port = freeTCPPort(t)
	})
	run := adminCommands(t, server)
	if out, err := run("user", "add", "Alice"); err != nil || !strings.Contains(out, "Added Alice (id 1). Next: sudo ghostlink-server key add Alice shadowsocks\n") {
		t.Fatalf("user add: %v %s", err, out)
	}
	if out, err := run("keys", "Alice"); err != nil || !strings.Contains(out, "Create one: sudo ghostlink-server key add Alice shadowsocks\n") {
		t.Fatalf("keys of a user without any: %v %s", err, out)
	}
	if out, err := run("settings"); err != nil || !strings.Contains(out, "Off: amneziawg, wireguard, vless. Turn one on (it prints the port to allow): sudo ghostlink-server set --enable PROTOCOL\n") {
		t.Fatalf("settings on a new server: %v\n%s", err, out)
	}
	if _, err := run("key", "add", "Alice", "amneziawg"); err == nil ||
		!strings.Contains(err.Error(), "amneziawg is turned off on this server; turn it on first (its switch in the app or dashboard, or sudo ghostlink-server set --enable amneziawg)") {
		t.Fatalf("key add for a protocol that is off: %v", err)
	}
	if out, err := run("key", "add", "Alice", "shadowsocks", "--no-qr"); err != nil || !strings.Contains(out, "ss://") {
		t.Fatalf("key add shadowsocks: %v %s", err, out)
	}

	out, err := run("set", "--enable", "amneziawg")
	var port uint16
	server.service.Read(func(s *State) { port = s.AmneziaWG.Port })
	want := fmt.Sprintf("AmneziaWG is on, on UDP %d (it listens once it has a key): allow %d/udp in this server's firewall and your cloud security group (for example: sudo ufw allow %d/udp).\n", port, port, port)
	if err != nil || !strings.HasPrefix(out, "Saved.") || !strings.Contains(out, want) || strings.Count(out, " is on, on ") != 1 {
		t.Fatalf("set --enable amneziawg: %v\n%s", err, out)
	}
	// Shadowsocks listens on TCP and UDP; its new port is one the server would pick itself.
	server.service.Read(func(s *State) { port, err = pickPort(s.usedPorts(), portFree, "tcp", "udp") })
	if err != nil {
		t.Fatal(err)
	}
	out, err = run("set", "--port", fmt.Sprintf("shadowsocks=%d", port))
	want = fmt.Sprintf("Shadowsocks (Outline) is on, on TCP and UDP %d (it listens once it has a key): allow %d/tcp and %d/udp in this server's firewall and your cloud security group (for example: sudo ufw allow %d/tcp && sudo ufw allow %d/udp).\n", port, port, port, port, port)
	if err != nil || !strings.Contains(out, want) || strings.Count(out, " is on, on ") != 1 {
		t.Fatalf("set --port shadowsocks: %v\n%s", err, out)
	}
	// Other changes, and turning a protocol off, name no port.
	for _, args := range [][]string{{"set", "--speed-limit", "none"}, {"set", "--disable", "vless"}} {
		if out, err := run(args...); err != nil || strings.Contains(out, " is on, on ") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}

	if out, err := run("key", "add", "Alice", "amneziawg", "--no-qr"); err != nil || !strings.Contains(out, "[Interface]") {
		t.Fatalf("key add amneziawg once it is on: %v %s", err, out)
	}
	var settings serverInfo
	if out, err := run("--json", "settings"); err != nil || json.Unmarshal([]byte(out), &settings) != nil ||
		!settings.Protocols[AmneziaWG].Enabled || settings.Protocols[VLESS].Enabled || settings.Protocols[WireGuard].Enabled {
		t.Fatalf("--json settings: %v %s", err, out)
	}
	if out, err := run("settings"); err != nil || !strings.Contains(out, "Off: wireguard, vless. Turn one on") {
		t.Fatalf("settings with AmneziaWG on: %v\n%s", err, out)
	}
}
