// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// IPsec settings: identities the component accepts whatever the client's name, kept through a
// rename, and written to the component only when they change.
func TestIPsecIdentitiesAndSettingsFile(t *testing.T) {
	for name, want := range map[string]string{"📱 Phone": "Phone", "မောင် မောင်": "user", ".hidden": "hidden", "José García": "Jos-Garca", "-_-": "user"} {
		if got := identityLabel(name); got != want || !ipsecproto.ValidIdentity(strings.ToLower(got)+"-1@ghostlink") {
			t.Errorf("identityLabel(%q) = %q, want %q", name, got, want)
		}
	}
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	phone := server.user(t, map[string]any{"name": "📱 Phone"})
	eap := server.appleKey(t, phone, map[string]string{"protocol": "ikev2"})
	cert := server.appleKey(t, phone, map[string]string{"protocol": "ikev2", "auth": "certificate"})
	desired := server.desired(t) // validates as the agent does
	if !strings.HasPrefix(eap.Identity, "phone-") || !slices.Contains(desired.Allowed, eap.Identity) || !slices.Contains(desired.Allowed, cert.Identity) {
		t.Fatalf("identities %q %q, allowed %v", eap.Identity, cert.Identity, desired.Allowed)
	}

	// A rename keeps the identities, which installed profiles and the certificate carry.
	server.must(t, http.StatusOK, "PATCH", "/users/"+phone.ID, map[string]any{"name": "Alice iPhone"}, nil)
	var keys []keyView
	server.must(t, http.StatusOK, "GET", "/users/"+phone.ID+"/keys", nil, &keys)
	if len(keys) != 2 || keys[0].Identity != eap.Identity || keys[1].Identity != cert.Identity {
		t.Fatalf("identities after a rename: %+v", keys)
	}
	if allowed := server.desired(t).Allowed; !slices.Contains(allowed, eap.Identity) || !slices.Contains(allowed, cert.Identity) {
		t.Fatalf("allowed after a rename: %v", allowed)
	}
	// A key created after the rename takes the new name.
	if later := server.appleKey(t, phone, map[string]string{"protocol": "ikev2"}); !strings.HasPrefix(later.Identity, "alice-iphone-") {
		t.Fatalf("new key's identity %q", later.Identity)
	}

	// Usage accounting alone does not rewrite the component's settings; a real change does.
	generation := server.desired(t).Generation
	server.service.monitor.user("u" + phone.ID).pending.Add(1000)
	if err := server.service.Account(); err != nil {
		t.Fatal(err)
	}
	if server.desired(t).Generation != generation {
		t.Fatal("usage accounting rewrote the IPsec settings")
	}
	server.must(t, http.StatusOK, "PATCH", "/users/"+phone.ID, map[string]any{"enabled": false}, nil)
	if d := server.desired(t); d.Generation == generation || len(d.Allowed) != 0 {
		t.Fatalf("disabling the client did not reach the component: %v", d.Allowed)
	}

	// A hostname the component cannot use as the server's identity is refused.
	for _, host := range []string{"_vpn.example.com", strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.com"} {
		if status := server.call(t, "PATCH", "/server", map[string]any{"hostname": host}, nil); status != http.StatusBadRequest {
			t.Errorf("hostname %q: status %d", host, status)
		}
	}

	// The connection kit has no QR code for IKEv2/IPsec keys: they install with a profile.
	status, _, page := server.raw(t, "GET", "/users/"+phone.ID+"/kit", nil)
	if status != http.StatusOK || strings.Contains(page, "<svg") || !strings.Contains(page, ".mobileconfig") {
		t.Fatalf("kit for IKEv2 keys: %d, has QR code %v", status, strings.Contains(page, "<svg"))
	}
}

// writeIPsecStatus reports sessions from the agent at now.
func writeIPsecStatus(t *testing.T, s *testServer, now time.Time, sas, closed []ipsecproto.SA) {
	t.Helper()
	if sas == nil {
		sas = []ipsecproto.SA{}
	}
	data, _ := json.Marshal(ipsecproto.Status{Version: 1, UpdatedUnix: now.Unix(), Running: true, SAs: sas, Closed: closed})
	if err := os.WriteFile(filepath.Join(s.store.Dir(), IPsecDir, ipsecproto.StatusFile), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

// IKEv2/IPsec accounting: an ended session keeps nobody online, a listing that failed once is
// not counted twice, and sessions that were up before the server started are not charged
// again from their first counters.
func TestIPsecReportsAreCountedOnce(t *testing.T) {
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	tag := "u" + user.ID
	sa := func(child string, in, out uint64, established int64) ipsecproto.SA {
		return ipsecproto.SA{Name: "gl-ikev2-eap", UniqueID: "1", Version: 2, Identity: key.Identity, Remote: "198.51.100.20",
			Established: established, Children: []ipsecproto.Child{{UniqueID: child, BytesIn: in, BytesOut: out}}}
	}
	usage := func() uint64 {
		t.Helper()
		if err := server.service.Account(); err != nil {
			t.Fatal(err)
		}
		var got userView
		server.must(t, http.StatusOK, "GET", "/users/"+user.ID, nil, &got)
		return got.UsageBytes
	}
	lastSeen := func() int64 {
		users, _ := server.service.monitor.Live()
		return users[tag].LastActive
	}

	start := time.Now()
	writeIPsecStatus(t, server, start, []ipsecproto.SA{sa("1", 1000, 1000, 0)}, nil)
	server.service.recordIPsec(start)
	// The agent could not list the sessions once; the next report has the session again.
	writeIPsecStatus(t, server, start.Add(5*time.Second), nil, nil)
	server.service.recordIPsec(start.Add(5 * time.Second))
	writeIPsecStatus(t, server, start.Add(10*time.Second), []ipsecproto.SA{sa("1", 1100, 1000, 10)}, nil)
	server.service.recordIPsec(start.Add(10 * time.Second))
	if got := usage(); got != 2100 {
		t.Fatalf("usage %d after a failed listing, want 2100", got)
	}
	// The session ends; while the agent still lists it as closed, it keeps nobody online.
	writeIPsecStatus(t, server, start.Add(15*time.Second), nil, []ipsecproto.SA{sa("1", 1100, 1000, 15)})
	server.service.recordIPsec(start.Add(15 * time.Second))
	writeIPsecStatus(t, server, start.Add(50*time.Second), nil, []ipsecproto.SA{sa("1", 1100, 1000, 50)})
	server.service.recordIPsec(start.Add(50 * time.Second))
	if seen := lastSeen(); seen != start.Add(10*time.Second).Unix() {
		t.Fatalf("last seen %d, want %d (the last report with the session up)", seen, start.Add(10*time.Second).Unix())
	}

	// After a restart, a session that was up before it is a starting point, not new traffic.
	server.service.ipsecSeen, server.service.ipsecReported = map[string]ipsecCounters{}, false
	server.service.started = start.Add(55 * time.Second)
	writeIPsecStatus(t, server, start.Add(60*time.Second), []ipsecproto.SA{sa("2", 50_000, 50_000, 3600)}, nil)
	server.service.recordIPsec(start.Add(60 * time.Second))
	writeIPsecStatus(t, server, start.Add(65*time.Second), []ipsecproto.SA{sa("2", 50_100, 50_000, 3605)}, nil)
	server.service.recordIPsec(start.Add(65 * time.Second))
	if got := usage(); got != 2200 {
		t.Fatalf("usage %d after a restart, want 2200", got)
	}
}
