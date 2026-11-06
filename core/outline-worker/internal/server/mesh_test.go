// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/mesh"
	"ghostlink.local/outline-worker/internal/meshproto"
)

// meshAgent talks to the coordinator the way ghostlink-mesh does: pinned TLS, JSON.
type meshAgent struct {
	t      *testing.T
	client *http.Client
	url    string
	secret string
	key    string
}

func newMeshAgent(t *testing.T, invite string) *meshAgent {
	t.Helper()
	inv, err := meshproto.DecodeInvite(invite)
	if err != nil {
		t.Fatal(err)
	}
	pin := inv.Pin
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !strings.EqualFold(hex.EncodeToString(sum[:]), pin) {
				t.Errorf("coordinator certificate does not match the invite's pin")
			}
			return nil
		},
	}}}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &meshAgent{t: t, client: client, url: inv.URL, key: base64.StdEncoding.EncodeToString(key)}
}

func (a *meshAgent) post(path string, body any, out any) int {
	a.t.Helper()
	data, _ := json.Marshal(body)
	request, _ := http.NewRequest(http.MethodPost, a.url+path, bytes.NewReader(data))
	if a.secret != "" {
		request.Header.Set("Authorization", "Bearer "+a.secret)
	}
	response, err := a.client.Do(request)
	if err != nil {
		a.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if out != nil && response.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			a.t.Fatalf("%s: %v: %s", path, err, raw)
		}
	}
	return response.StatusCode
}

func (a *meshAgent) join(token, name string, routes ...string) meshproto.JoinResponse {
	a.t.Helper()
	var out meshproto.JoinResponse
	if status := a.post("/v1/join", meshproto.JoinRequest{Protocol: meshproto.Version, Token: token, Name: name, PublicKey: a.key,
		ListenPort: 51820, Endpoints: []string{"203.0.113.9:51820"}, AdvertiseRoutes: routes, OS: "linux", Version: "test"}, &out); status != http.StatusOK {
		a.t.Fatalf("join %s: %d", name, status)
	}
	a.secret = out.Secret
	return out
}

func (a *meshAgent) sync(applied uint64, routes ...string) (meshproto.SyncResponse, int, time.Duration) {
	a.t.Helper()
	var out meshproto.SyncResponse
	start := time.Now()
	status := a.post("/v1/sync", meshproto.SyncRequest{Protocol: meshproto.Version, Version: "test", Applied: applied, ListenPort: 51820,
		Endpoints: []string{"203.0.113.9:51820"}, AdvertiseRoutes: routes, Peers: []meshproto.PeerStatus{}}, &out)
	return out, status, time.Since(start)
}

func TestMeshCoordinator(t *testing.T) {
	previousWait := meshWait
	meshWait = 1500 * time.Millisecond
	defer func() { meshWait = previousWait }()
	server := newTestServer(t, nil)
	meshServer := NewMeshServer(server.service)
	server.service.OnChange(func(previous, next *State) {
		if err := meshServer.Apply(); err != nil {
			t.Errorf("mesh apply: %v", err)
		}
	})
	t.Cleanup(meshServer.Close)

	if status := server.call(t, "POST", "/mesh/invites", map[string]any{}, nil); status != http.StatusBadRequest {
		t.Fatalf("invite before enabling: %d", status)
	}
	var info meshInfo
	server.must(t, http.StatusOK, "PATCH", "/mesh", map[string]any{"enabled": true}, &info)
	if !info.Enabled || info.Port == 0 || info.CIDR != mesh.DefaultCIDR || info.URL == "" {
		t.Fatalf("mesh info: %+v", info)
	}
	server.service.Read(func(s *State) {
		if ports := s.Listening(); ports["mesh"] != "tcp/"+strings.TrimPrefix(info.URL, "https://127.0.0.1:") {
			t.Errorf("listening: %v", ports)
		}
		data, _ := s.EngineConfig("off")
		var config struct {
			Route struct {
				Rules []struct {
					Port   []uint16 `json:"port"`
					Action string   `json:"action"`
				} `json:"rules"`
			} `json:"route"`
		}
		_ = json.Unmarshal(data, &config)
		blocked := false
		for _, rule := range config.Route.Rules {
			blocked = blocked || (rule.Action == "reject" && slices.Contains(rule.Port, info.Port))
		}
		if !blocked {
			t.Error("VPN users are not kept off the mesh port")
		}
	})

	var created inviteCreated
	server.must(t, http.StatusCreated, "POST", "/mesh/invites", map[string]any{"tags": []string{"web"}, "local": true}, &created)
	if !strings.HasPrefix(created.Command, "curl -fsSL "+MeshScript+" | sudo bash -s -- --join 'glmesh1:") {
		t.Fatalf("join command: %s", created.Command)
	}
	inv, _ := meshproto.DecodeInvite(created.Invite)
	pin := ""
	server.service.Read(func(s *State) { pin, _ = s.CertSHA256() })
	if inv.Pin != pin || !strings.HasPrefix(inv.URL, "https://127.0.0.1:") {
		t.Fatalf("invite: %+v", inv)
	}

	web := newMeshAgent(t, created.Invite)
	joined := web.join(inv.Token, "web-1", "10.20.0.0/24")
	if joined.Status != meshproto.StatusActive || joined.Address != "100.96.0.1" {
		t.Fatalf("join: %+v", joined)
	}
	// A used invite fails, and repeated failures are throttled.
	thief := newMeshAgent(t, created.Invite)
	if status := thief.post("/v1/join", meshproto.JoinRequest{Protocol: meshproto.Version, Token: inv.Token, Name: "thief", PublicKey: thief.key, ListenPort: 1}, nil); status != http.StatusForbidden {
		t.Fatalf("reused invite: %d", status)
	}

	first, status, took := web.sync(0)
	if status != http.StatusOK || first.Status != meshproto.StatusActive || first.Config == nil || took > time.Second {
		t.Fatalf("first sync: %d %+v after %v", status, first, took)
	}
	if first.Config.Name != "web-1" || first.Config.Address != "100.96.0.1/16" || !first.Config.Firewall.Open || len(first.Config.Peers) != 0 {
		t.Fatalf("first config: %+v", first.Config)
	}
	// Nothing new: the sync waits for the full period.
	same, _, took := web.sync(first.Config.Generation, "10.20.0.0/24")
	if same.Config.Generation != first.Config.Generation || took < meshWait-200*time.Millisecond {
		t.Fatalf("an unchanged sync returned after %v", took)
	}

	// A second node joining wakes the waiting sync of the first at once.
	var second inviteCreated
	server.must(t, http.StatusCreated, "POST", "/mesh/invites", map[string]any{"tags": []string{"db"}, "local": true}, &second)
	db := newMeshAgent(t, second.Invite)
	woke := make(chan time.Duration, 1)
	go func() {
		_, _, took := web.sync(first.Config.Generation, "10.20.0.0/24")
		woke <- took
	}()
	time.Sleep(200 * time.Millisecond)
	inv2, _ := meshproto.DecodeInvite(second.Invite)
	dbJoined := db.join(inv2.Token, "db-1")
	if took := <-woke; took > meshWait-300*time.Millisecond {
		t.Fatalf("the first node was not woken by the second joining (%v)", took)
	}
	withPeer, _, _ := web.sync(0, "10.20.0.0/24")
	if len(withPeer.Config.Peers) != 1 || withPeer.Config.Peers[0].Name != "db-1" || withPeer.Config.Peers[0].PublicKey != db.key {
		t.Fatalf("peers: %+v", withPeer.Config.Peers)
	}

	// Rules, routes and topology through the admin API.
	server.must(t, http.StatusOK, "PUT", "/mesh/rules", map[string]any{"rules": []mesh.Rule{{From: "tag:web", To: "tag:db", Protocol: "tcp", Ports: []string{"5432"}}}}, nil)
	if status := server.call(t, "PUT", "/mesh/rules", map[string]any{"rules": []mesh.Rule{{From: "web", To: "*", Protocol: "tcp"}}}, nil); status != http.StatusBadRequest {
		t.Fatalf("bad rule: %d", status)
	}
	dbConfig, _, _ := db.sync(0)
	if fw := dbConfig.Config.Firewall; fw.Open || len(fw.Allow) != 1 || fw.Allow[0].Sources[0] != "100.96.0.1/32" {
		t.Fatalf("db firewall: %+v", fw)
	}
	if status := server.call(t, "PATCH", "/mesh/nodes/"+joined.NodeID, map[string]any{"approved_routes": []string{"10.99.0.0/24"}}, nil); status != http.StatusBadRequest {
		t.Fatalf("approving a route the node does not offer: %d", status)
	}
	server.must(t, http.StatusOK, "PATCH", "/mesh/nodes/"+joined.NodeID, map[string]any{"approved_routes": []string{"10.20.0.0/24"}}, nil)
	dbConfig, _, _ = db.sync(0)
	if !slices.Equal(dbConfig.Config.Routes, []string{"10.20.0.0/24"}) {
		t.Fatalf("db routes: %+v", dbConfig.Config.Routes)
	}
	var topology mesh.Topology
	server.must(t, http.StatusOK, "GET", "/mesh/topology", nil, &topology)
	if len(topology.Nodes) != 2 || len(topology.Links) != 1 || !topology.Nodes[0].Online || topology.Nodes[0].SeenFrom != "127.0.0.1" {
		t.Fatalf("topology: %+v", topology)
	}

	// Removing a node ends its access; a bad secret is refused.
	server.must(t, http.StatusNoContent, "DELETE", "/mesh/nodes/"+dbJoined.NodeID, nil, nil)
	if _, status, _ := db.sync(0); status != http.StatusUnauthorized {
		t.Fatalf("a removed node synced: %d", status)
	}
	if after, _, _ := web.sync(0, "10.20.0.0/24"); len(after.Config.Peers) != 0 {
		t.Fatal("the removed node is still a peer")
	}
	// Turning the mesh off stops the agent API and tells nodes.
	server.must(t, http.StatusOK, "PATCH", "/mesh", map[string]any{"enabled": false}, nil)
	if _, err := web.client.Get(web.url + "/v1/sync"); err == nil {
		t.Fatal("the mesh port still answers after turning the mesh off")
	}
}

// The dashboard and the desktop app draw the mesh with the same file.
func TestMeshMapMatchesTheDesktopCopy(t *testing.T) {
	embedded, err := dashboardFiles.ReadFile("dashboard/mesh-map.js")
	if err != nil {
		t.Fatal(err)
	}
	index, _ := dashboardFiles.ReadFile("dashboard/index.html")
	for _, script := range []string{`src="mesh-map.js"`, `src="mesh.js"`} {
		if !bytes.Contains(index, []byte(script)) {
			t.Fatalf("dashboard index.html does not load %s", script)
		}
	}
	desktop, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "apps", "desktop", "ui", "mesh-map.js"))
	if os.IsNotExist(err) {
		t.Skip("desktop sources are not in this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(desktop, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(embedded, []byte("\r\n"), []byte("\n"))) {
		t.Fatal("internal/server/dashboard/mesh-map.js differs from apps/desktop/ui/mesh-map.js; copy the desktop file over")
	}
}
