// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// outlineFiles builds Outline's two files as shadowbox writes them.
func outlineFiles(hostname string, portForNew int, defaultLimit any, keys ...map[string]any) (json.RawMessage, json.RawMessage) {
	server := map[string]any{"serverId": "7f1c", "metricsEnabled": false, "createdTimestampMs": 1_700_000_000_000,
		"hostname": hostname, "portForNewAccessKeys": portForNew, "name": "My Outline", "experimental": map[string]any{}}
	if defaultLimit != nil {
		server["accessKeyDataLimit"] = map[string]any{"bytes": defaultLimit}
	}
	for i, k := range keys {
		if _, ok := k["id"]; !ok {
			k["id"] = strconv.Itoa(i)
		}
		k["metricsId"] = fmt.Sprintf("m-%d", i)
	}
	serverJSON, _ := json.Marshal(server)
	keysJSON, _ := json.Marshal(map[string]any{"accessKeys": keys, "nextId": len(keys)})
	return serverJSON, keysJSON
}

func decodeOutline(t *testing.T, serverJSON, keysJSON json.RawMessage) (outlineServer, []outlineKey) {
	t.Helper()
	var server outlineServer
	var keys outlineKeys
	if err := json.Unmarshal(serverJSON, &server); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		t.Fatal(err)
	}
	return server, keys.AccessKeys
}

// freeSharedPort is a port free on TCP and UDP alike, as Shadowsocks needs.
func freeSharedPort(t *testing.T) int {
	t.Helper()
	for range 50 {
		port := freeTCPPort(t)
		if portFree("udp", port) && portFree("tcp", port) {
			return int(port)
		}
	}
	t.Fatal("no port is free on both TCP and UDP")
	return 0
}

// outlineURL is the key an Outline client already has.
func outlineURL(method, password, host string, port int) string {
	credential := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	return fmt.Sprintf("ss://%s@%s:%d/?outline=1", credential, host, port)
}

// shadowsocksEndpointOf reads the cipher, password and port out of an ss:// key.
func shadowsocksEndpointOf(t *testing.T, accessKey string) (string, string, string, string) {
	t.Helper()
	link, err := url.Parse(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := base64.RawURLEncoding.DecodeString(link.User.Username())
	if err != nil {
		t.Fatal(err)
	}
	method, password, _ := strings.Cut(string(credential), ":")
	return method, password, link.Hostname(), link.Port()
}

// What an import keeps, what it cannot, and how it fits Outline's ports around Ghostlink's.
func TestOutlineImportPlan(t *testing.T) {
	state, err := NewState(InitOptions{Hostname: "198.51.100.1", PortFree: func(string, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	main := 41_234
	extra := int(state.VLESS.Port) // Bob's port: VLESS has to make way
	api := int(state.API.Port)
	serverJSON, keysJSON := outlineFiles("203.0.113.7", main, 10_000_000_000,
		map[string]any{"name": "Alice", "password": "alicepass", "port": main, "dataLimit": map[string]any{"bytes": 5_000_000_000}},
		map[string]any{"name": "", "password": "nonamepass", "port": main, "encryptionMethod": "chacha20-ietf-poly1305"},
		map[string]any{"name": "alice", "password": "alice2pass", "port": main},
		map[string]any{"name": "Bob", "password": "bobpass", "port": extra, "encryptionMethod": "aes-256-gcm"},
		map[string]any{"name": "Low", "password": "lowpass", "port": 443},
		map[string]any{"name": "Paused", "password": "pausedpass", "port": main, "dataLimit": map[string]any{"bytes": 0}},
		map[string]any{"name": "Mixed", "password": "mixedpass", "port": main, "encryptionMethod": "aes-128-gcm"},
		map[string]any{"name": "Api", "password": "apipass", "port": api},
		map[string]any{"name": "Twin", "password": "alicepass", "port": main},
		map[string]any{"name": "Odd", "password": "oddpass", "port": main + 1, "encryptionMethod": "rc4-md5"},
		map[string]any{"name": "Sneaky\u0007 name", "password": "bad\npass", "port": main},
	)
	server, keys := decodeOutline(t, serverJSON, keysJSON)
	before := state.VLESS.Port
	report, err := state.importOutline(server, keys, func(string, uint16) bool { return true }, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := state.CheckPorts(); err != nil {
		t.Fatal(err)
	}

	if report.Port != uint16(main) || report.Method != "chacha20-ietf-poly1305" || !slices.Equal(report.ExtraPorts, []uint16{uint16(extra)}) {
		t.Fatalf("ports: %+v", report)
	}
	if !report.HostnameChanged || state.Hostname != "203.0.113.7" || state.Name != "My Outline" {
		t.Fatalf("server: hostname %q (changed %v), name %q", state.Hostname, report.HostnameChanged, state.Name)
	}
	if len(report.Moved) != 1 || report.Moved[0].Service != "VLESS" || report.Moved[0].From != before || state.VLESS.Port == before ||
		int(state.VLESS.Port) == main || int(state.VLESS.Port) == extra {
		t.Fatalf("VLESS should have moved off Bob's port: %+v, now %d", report.Moved, state.VLESS.Port)
	}
	if report.Clients != 11 || report.Kept != 6 {
		t.Fatalf("clients %d, kept %d", report.Clients, report.Kept)
	}
	reasons := map[string]string{}
	for _, k := range report.NewKeys {
		reasons[k.Client] = k.Reason
	}
	for name, want := range map[string]string{"Low": "below 1024", "Mixed": "another cipher", "Api": "management API",
		"Odd": "cipher", "Sneaky name": "password"} {
		if !strings.Contains(reasons[name], want) {
			t.Fatalf("%s should get a new key (%q), got %q (all: %v)", name, want, reasons[name], reasons)
		}
	}
	if len(reasons) != 5 {
		t.Fatalf("new keys: %v", reasons)
	}
	if !slices.Equal(report.Disabled, []string{"Paused"}) {
		t.Fatalf("disabled: %v", report.Disabled)
	}
	// Outline's limits count the last 30 days, Ghostlink's from now on: the report says so.
	if len(report.Notes) != 2 || !strings.Contains(report.Notes[0], "Twin has the same key as Alice") ||
		!strings.Contains(report.Notes[1], "10 clients keep their Outline data limit") || !strings.Contains(report.Notes[1], "last 30 days") {
		t.Fatalf("notes: %v", report.Notes)
	}
	// The report never carries a password.
	raw, _ := json.Marshal(report)
	for _, k := range keys {
		if k.Password != "" && strings.Contains(string(raw), k.Password) {
			t.Fatalf("the report leaks %q", k.Password)
		}
	}

	names := []string{}
	for _, u := range state.Users {
		names = append(names, u.Name)
	}
	if want := []string{"Alice", "Key 1", "alice (2)", "Bob", "Low", "Paused", "Mixed", "Api", "Twin", "Odd", "Sneaky name"}; !slices.Equal(names, want) {
		t.Fatalf("names %q, want %q", names, want)
	}
	byName := map[string]*User{}
	for _, u := range state.Users {
		byName[u.Name] = u
	}
	if byName["Alice"].DataLimitBytes != 5_000_000_000 || byName["Bob"].DataLimitBytes != 10_000_000_000 || byName["Bob"].UsageBytes != 0 {
		t.Fatalf("data limits: Alice %d, Bob %d", byName["Alice"].DataLimitBytes, byName["Bob"].DataLimitBytes)
	}
	if byName["Paused"].Enabled || !byName["Alice"].Enabled {
		t.Fatal("a key with Outline's 0-byte limit should be imported turned off")
	}

	// Every kept key renders as the ss:// key its owner already has.
	for i, name := range names {
		u := byName[name]
		rendered, err := state.Render(u, u.Keys[0])
		if err != nil {
			t.Fatal(err)
		}
		method, password, host, port := shadowsocksEndpointOf(t, rendered.AccessKey)
		if _, renewed := reasons[name]; renewed {
			if password == keys[i].Password || port != strconv.Itoa(main) || method != "chacha20-ietf-poly1305" {
				t.Fatalf("%s: a new key should be on the main port with a new password: %s:%s", name, method, port)
			}
			continue
		}
		wantMethod := keys[i].Method
		if wantMethod == "" {
			wantMethod = "chacha20-ietf-poly1305"
		}
		if method != wantMethod || password != keys[i].Password || host != "203.0.113.7" || port != strconv.Itoa(keys[i].Port) {
			t.Fatalf("%s renders %s %s:%s, want %s port %d", name, method, host, port, wantMethod, keys[i].Port)
		}
	}
	if k := byName["Bob"].Keys[0]; k.Port != uint16(extra) || k.Method != "aes-256-gcm" {
		t.Fatalf("Bob's key keeps its own port and cipher: %+v", k)
	}
	if k := byName["Alice"].Keys[0]; k.Port != 0 || k.Method != "" {
		t.Fatalf("Alice's key uses the server's port and cipher: port %d method %q", k.Port, k.Method)
	}

	// The engine serves Bob's port with his cipher, as its own inbound.
	config, err := state.EngineConfig("off")
	if err != nil {
		t.Fatal(err)
	}
	var engine struct {
		Inbounds []struct {
			Type, Tag, Method string
			Port              int `json:"listen_port"`
			Users             []map[string]string
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &engine); err != nil {
		t.Fatal(err)
	}
	served := map[string]string{}
	for _, in := range engine.Inbounds {
		if in.Type == Shadowsocks {
			served[in.Tag] = fmt.Sprintf("%d/%s/%d", in.Port, in.Method, len(in.Users))
		}
	}
	// Main: Alice, Key 1, alice (2), Twin and the five new keys (Paused is turned off).
	want := map[string]string{Shadowsocks: fmt.Sprintf("%d/chacha20-ietf-poly1305/9", main), fmt.Sprintf("shadowsocks-%d", extra): fmt.Sprintf("%d/aes-256-gcm/1", extra)}
	if !mapsEqual(served, want) {
		t.Fatalf("shadowsocks inbounds %v, want %v", served, want)
	}
	if listening := state.Listening(); listening[fmt.Sprintf("shadowsocks-%d", extra)] != fmt.Sprintf("tcp+udp/%d", extra) {
		t.Fatalf("listening: %v", listening)
	}

	// The main port cannot later be moved onto an imported key's own port.
	state.Shadowsocks.Port = uint16(extra)
	if err := state.CheckPorts(); err == nil || !strings.Contains(err.Error(), "imported from Outline") {
		t.Fatalf("moving the main port onto Bob's: %v", err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestOutlineImportRefusals(t *testing.T) {
	free := func(string, uint16) bool { return true }
	fresh := func() *State {
		state, err := NewState(InitOptions{Hostname: "198.51.100.1", PortFree: free})
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	one := map[string]any{"name": "A", "password": "apass", "port": 40_000}

	// Only into a new server.
	state := fresh()
	state.Users = append(state.Users, &User{ID: "1", Name: "Existing"})
	serverJSON, keysJSON := outlineFiles("203.0.113.7", 40_000, nil, one)
	server, keys := decodeOutline(t, serverJSON, keysJSON)
	if _, err := state.importOutline(server, keys, free, time.Now()); err == nil || !strings.Contains(err.Error(), "already has clients") {
		t.Fatalf("a server with clients: %v", err)
	}
	// Not an empty Outline, not more keys than a server can hold.
	if _, err := fresh().importOutline(server, nil, free, time.Now()); err == nil {
		t.Fatal("no keys should be refused")
	}
	many := make([]outlineKey, MaxUsers+1)
	if _, err := fresh().importOutline(server, many, free, time.Now()); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("too many keys: %v", err)
	}
	// Every key below 1024: the server keeps its own port and everyone gets a new key.
	state = fresh()
	port := state.Shadowsocks.Port
	serverJSON, keysJSON = outlineFiles("not a host!", 443, nil, map[string]any{"name": "A", "password": "apass", "port": 443})
	server, keys = decodeOutline(t, serverJSON, keysJSON)
	report, err := state.importOutline(server, keys, free, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Port != port || report.Kept != 0 || len(report.NewKeys) != 1 || report.HostnameChanged || state.Hostname != "198.51.100.1" || len(report.Notes) != 1 {
		t.Fatalf("all keys below 1024: %+v", report)
	}
}

// The real thing: an import over the API, after which the ss:// keys Outline handed out carry
// traffic, on the main port and on an extra one; a dry run changes nothing.
func TestOutlineImportEndToEnd(t *testing.T) {
	web := webServer(t, "via outline key")
	testInternalPort = web
	t.Cleanup(func() { testInternalPort = 0 })
	server := newTestServer(t, nil)
	var before serverInfo
	server.must(t, http.StatusOK, "GET", "/server", nil, &before)

	main, extra := freeSharedPort(t), freeSharedPort(t)
	for extra == main {
		extra = freeSharedPort(t)
	}
	serverJSON, keysJSON := outlineFiles("127.0.0.1", main, nil,
		map[string]any{"name": "Phone", "password": "Zm9vYmFyYmF6cXV4MTIz", "port": main},
		map[string]any{"name": "Laptop", "password": "c2Vjb25kLXBhc3N3b3Jk", "port": main, "dataLimit": map[string]any{"bytes": 2e9}},
		map[string]any{"name": "Router", "password": "dGhpcmQtcGFzc3dvcmQ", "port": extra, "encryptionMethod": "aes-256-gcm"},
	)
	body := map[string]any{"server": serverJSON, "access_keys": keysJSON, "dry_run": true}

	var report outlineReport
	server.must(t, http.StatusOK, "POST", "/import/outline", body, &report)
	if !report.DryRun || report.Clients != 3 || report.Kept != 3 || report.Port != uint16(main) || !slices.Equal(report.ExtraPorts, []uint16{uint16(extra)}) {
		t.Fatalf("dry run report: %+v", report)
	}
	var after serverInfo
	server.must(t, http.StatusOK, "GET", "/server", nil, &after)
	if after.Users != 0 || after.Protocols[Shadowsocks].Port != before.Protocols[Shadowsocks].Port {
		t.Fatalf("a dry run changed the server: %+v", after)
	}

	body["dry_run"] = false
	server.must(t, http.StatusOK, "POST", "/import/outline", body, &report)
	if report.DryRun || report.Clients != 3 {
		t.Fatalf("report: %+v", report)
	}
	server.must(t, http.StatusOK, "GET", "/server", nil, &after)
	if after.Users != 3 || after.Protocols[Shadowsocks].Port != uint16(main) || !slices.Equal(after.ShadowsocksExtraPorts, []uint16{uint16(extra)}) {
		t.Fatalf("server after the import: %+v", after)
	}

	// Outline's own ss:// keys, unchanged.
	_, keys := decodeOutline(t, serverJSON, keysJSON)
	for _, k := range keys {
		method := k.Method
		if method == "" {
			method = outlineDefaultCipher
		}
		proxy := freeTCPPort(t)
		startClient(t, clientConfig(t, keyView{IssuedKey: IssuedKey{Protocol: Shadowsocks, AccessKey: outlineURL(method, k.Password, "127.0.0.1", k.Port)}}, proxy))
		got, err := fetch(proxy, "127.0.0.1:"+strconv.Itoa(int(web)), "outline.test", 10)
		if err != nil || got != "via outline key" {
			t.Fatalf("%s's Outline key: %q, %v", k.Name, got, err)
		}
	}

	// The traffic is counted for the right clients, and the data limit came along.
	var users []userView
	server.must(t, http.StatusOK, "GET", "/users", nil, &users)
	if len(users) != 3 || users[1].Name != "Laptop" || users[1].DataLimitBytes != 2_000_000_000 {
		t.Fatalf("users: %+v", users)
	}
	var live struct {
		Users []liveUser `json:"users"`
	}
	server.must(t, http.StatusOK, "GET", "/live", nil, &live)
	for _, u := range live.Users {
		if u.LastActive == 0 {
			t.Fatalf("%s's traffic was not seen: %+v", u.Name, live.Users)
		}
	}

	// A second import is refused: the server has clients now.
	if status := server.call(t, "POST", "/import/outline", body, nil); status != http.StatusBadRequest {
		t.Fatalf("second import: status %d", status)
	}
}

// A mesh that is turned off keeps its port through an import: turning it on again reuses it.
func TestOutlineImportKeepsTheMeshPortWhileTheMeshIsOff(t *testing.T) {
	free := func(string, uint16) bool { return true }
	state, err := NewState(InitOptions{Hostname: "198.51.100.1", PortFree: free})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.enableMesh("", "", free); err != nil {
		t.Fatal(err)
	}
	state.Mesh.Enabled = false
	port := int(state.Mesh.Port)
	serverJSON, keysJSON := outlineFiles("", port, nil, map[string]any{"name": "Mesh", "password": "meshpass", "port": port})
	server, keys := decodeOutline(t, serverJSON, keysJSON)
	report, err := state.importOutline(server, keys, free, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.NewKeys) != 1 || !strings.Contains(report.NewKeys[0].Reason, "the mesh") || int(state.Shadowsocks.Port) == port {
		t.Fatalf("an Outline key took the mesh's port: %+v, Shadowsocks on %d", report, state.Shadowsocks.Port)
	}
	state.Mesh.Enabled = true
	if err := state.CheckPorts(); err != nil {
		t.Fatalf("the mesh cannot be turned on again: %v", err)
	}
}
