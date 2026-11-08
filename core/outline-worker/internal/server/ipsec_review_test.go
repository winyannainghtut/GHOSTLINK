// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// ipsecServer is a test server with IKEv2 and IPsec turned on.
func ipsecServer(t *testing.T) *testServer {
	t.Helper()
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{
		"ikev2": map[string]bool{"enabled": true}, "ipsec": map[string]bool{"enabled": true}}}, nil)
	return server
}

func (s *testServer) usage(t *testing.T, user userView) uint64 {
	t.Helper()
	if err := s.service.Account(); err != nil {
		t.Fatal(err)
	}
	var got userView
	s.must(t, http.StatusOK, "GET", "/users/"+user.ID, nil, &got)
	return got.UsageBytes
}

func TestIPsecDefaultIdentity(t *testing.T) {
	for _, c := range [][3]string{
		{"Alice", "7", "alice-7@ghostlink"},
		{"Alice & <Bob>", "9", "alice--bob-9@ghostlink"},
		{"Иван Петров", "7", "user-7@ghostlink"},
		{"田中 太郎", "7", "user-7@ghostlink"},
		{"မောင် မောင်", "7", "user-7@ghostlink"},
		{"👤 Alice", "7", "alice-7@ghostlink"},
		{"_bob", "3", "bob-3@ghostlink"},
		{".x", "3", "x-3@ghostlink"},
		{"-test", "3", "test-3@ghostlink"},
		{"[ Work ]", "3", "work--3@ghostlink"},
		{strings.Repeat("a", 60), "3", strings.Repeat("a", 40) + "-3@ghostlink"},
	} {
		got := defaultIdentity(c[0], c[1])
		if got != c[2] {
			t.Errorf("defaultIdentity(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
		if !ipsecproto.ValidIdentity(got) {
			t.Errorf("defaultIdentity(%q, %q) = %q, which the agent refuses", c[0], c[1], got)
		}
	}
}

// One user whose default identity the agent refused used to make the server write nothing at
// all, for everybody, with no sign in the API.
func TestIPsecAnyUserNameGivesAnIdentityTheAgentAccepts(t *testing.T) {
	server := ipsecServer(t)
	seen := map[string]bool{}
	for _, name := range []string{"Иван Петров", "田中 太郎", "မောင် မောင်", "👤 Alice", "_bob", ".x", "-test", "[ Work ]", "Alice"} {
		user := server.user(t, map[string]any{"name": name})
		for _, body := range []map[string]string{{"protocol": "ikev2"}, {"protocol": "ipsec", "auth": "psk"}} {
			key := server.appleKey(t, user, body)
			if !ipsecproto.ValidIdentity(key.Identity) || seen[strings.ToLower(key.Identity)] {
				t.Errorf("%q: identity %q is refused by the agent or not unique", name, key.Identity)
			}
			seen[strings.ToLower(key.Identity)] = true
			if desired := server.desired(t); !slices.Contains(desired.Allowed, key.Identity) {
				t.Fatalf("%q: the agent was not told about %s: %v", name, key.Identity, desired.Allowed)
			}
		}
	}
}

// A key the agent would refuse (only a hand-edited state has one) must not freeze the file.
func TestIPsecOneRefusedIdentityDoesNotStopTheAgentFromHearingAboutOthers(t *testing.T) {
	server := ipsecServer(t)
	bad := server.user(t, map[string]any{"name": "Bad"})
	good := server.user(t, map[string]any{"name": "Good"})
	badKey := server.appleKey(t, bad, map[string]string{"protocol": "ikev2"})
	server.must(t, http.StatusOK, "PATCH", "/users/"+bad.ID, map[string]any{"speed_limit_bps": 1000}, nil)
	if err := server.service.Change(func(s *State) error {
		s.User(bad.ID).Keys[0].LocalID = "-not an identity\n"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	goodKey := server.appleKey(t, good, map[string]string{"protocol": "ikev2"})
	desired := server.desired(t)
	if !slices.Contains(desired.Allowed, goodKey.Identity) || slices.Contains(desired.Allowed, badKey.Identity) {
		t.Fatalf("allowed: %v", desired.Allowed)
	}
	for _, limit := range desired.SpeedLimits {
		if limit.Name == "u"+bad.ID {
			t.Fatalf("a speed limit names the refused identity: %+v", limit)
		}
	}
}

// Renaming a user must not change the identity of keys already on their devices (a
// certificate key could not follow: its certificate names the identity).
func TestRenamingAUserKeepsTheirAppleIdentities(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Alice"})
	eap := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	cert := server.appleKey(t, user, map[string]string{"protocol": "ikev2", "auth": "certificate"})
	before := server.desired(t)
	server.must(t, http.StatusOK, "PATCH", "/users/"+user.ID, map[string]any{"name": "Alicia"}, nil)
	after := server.desired(t)
	for _, id := range []string{eap.Identity, cert.Identity} {
		if !slices.Contains(after.Allowed, id) {
			t.Errorf("%s is no longer allowed after the rename: %v", id, after.Allowed)
		}
	}
	if !slices.Equal(before.Allowed, after.Allowed) || len(after.IKEv2.EAP) != 1 || after.IKEv2.EAP[0].ID != eap.Identity {
		t.Errorf("identities changed with the name: %v -> %v", before.Allowed, after.Allowed)
	}
	status, _, body := server.raw(t, "GET", "/users/"+user.ID+"/keys/"+eap.ID+"/profile", nil)
	if status != http.StatusOK {
		t.Fatalf("profile: %d", status)
	}
	profile := readPlist(t, body)
	vpn := payloadOfType(t, profile, "com.apple.vpn.managed")["IKEv2"].(map[string]any)
	if vpn["LocalIdentifier"] != eap.Identity || vpn["AuthName"] != eap.Identity {
		t.Errorf("profile names %v, want %s", vpn["LocalIdentifier"], eap.Identity)
	}
	key := server.stateKey(user.ID, cert.ID)
	leaf, err := parseCertPEM(key.CertPEM)
	if err != nil || leaf.Subject.CommonName != cert.Identity || !slices.Contains(leaf.EmailAddresses, cert.Identity) {
		t.Errorf("the certificate no longer matches the key's identity %s: %v", cert.Identity, err)
	}
}

// Keys from before identities were stored get pinned when the server starts, and a certificate
// that names an identity the agent refused is replaced.
func TestIPsecPinIdentities(t *testing.T) {
	state, err := NewState(InitOptions{Hostname: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := state.ensureIPsecPKI(now, func(string, uint16) bool { return true }); err != nil {
		t.Fatal(err)
	}
	alice := &User{ID: "2", Name: "Alice", Enabled: true, Keys: []*Key{{ID: "5", Protocol: IKEv2, Auth: AuthEAP}}}
	ivan := &User{ID: "3", Name: "Иван", Enabled: true, Keys: []*Key{{ID: "6", Protocol: IKEv2, Auth: AuthCertificate, LocalID: "--6@ghostlink"}}}
	psk := &User{ID: "4", Name: "Carol", Enabled: true, Keys: []*Key{{ID: "7", Protocol: IPsec, Auth: AuthPSK, LocalID: "carol-phone@example.test"}, {ID: "8", Protocol: Shadowsocks}}}
	state.Users = []*User{alice, ivan, psk}
	// The way such a key looked before: a certificate for the refused identity, nothing stored.
	broken := ivan.Keys[0]
	if err := state.issueClientCert(ivan, broken, now); err != nil {
		t.Fatal(err)
	}
	oldSerial := broken.CertSerial
	broken.LocalID = ""

	if !state.pinIdentities(now) {
		t.Fatal("nothing was pinned")
	}
	if got := alice.Keys[0].LocalID; got != "alice-5@ghostlink" {
		t.Errorf("alice's key: %q", got)
	}
	if got := psk.Keys[0].LocalID; got != "carol-phone@example.test" || psk.Keys[1].LocalID != "" {
		t.Errorf("a custom identity or a non-Apple key changed: %q %q", got, psk.Keys[1].LocalID)
	}
	if broken.LocalID != "user-6@ghostlink" {
		t.Fatalf("the refused identity was kept: %q", broken.LocalID)
	}
	leaf, err := parseCertPEM(broken.CertPEM)
	if err != nil || leaf.Subject.CommonName != broken.LocalID || broken.CertSerial == oldSerial {
		t.Errorf("certificate not reissued for %s: %v (serial %d, was %d)", broken.LocalID, err, broken.CertSerial, oldSerial)
	}
	if !slices.ContainsFunc(state.IPsec.Revoked, func(r RevokedSerial) bool { return r.Serial == oldSerial }) {
		t.Error("the replaced certificate is not revoked")
	}
	if state.pinIdentities(now) {
		t.Error("pinning twice changed something")
	}
	alice.Name = "Alicia"
	if got := alice.Keys[0].localIdentity(alice); got != "alice-5@ghostlink" {
		t.Errorf("a rename changed a pinned identity: %q", got)
	}
}

// Initialize runs on every start of the server and pins identities in an old state file.
func TestIPsecInitializePinsIdentities(t *testing.T) {
	dir := t.TempDir()
	store, _, err := Initialize(dir, InitOptions{Hostname: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	store.State.Users = []*User{{ID: "2", Name: "Alice", Enabled: true, Keys: []*Key{{ID: "5", Protocol: IKEv2, Auth: AuthEAP}}}}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	again, _, err := Initialize(dir, InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := again.State.Users[0].Keys[0].LocalID; got != "alice-5@ghostlink" {
		t.Fatalf("pinned identity %q", got)
	}
	reloaded, err := Load(dir)
	if err != nil || reloaded.State.Users[0].Keys[0].LocalID != "alice-5@ghostlink" {
		t.Fatalf("the pinned identity was not saved: %v", err)
	}
}

// The counters are totals since each session began, and the sessions outlive the server: after
// a restart they only set the baseline.
func TestIPsecRestartDoesNotCountLiveSessionsAgain(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	report := func(in uint64) {
		fakeAgent(t, server, []ipsecproto.SA{{Name: "gl-ikev2-eap", UniqueID: "7", Version: 2, Identity: key.Identity,
			Remote: "198.51.100.20", Children: []ipsecproto.Child{{UniqueID: "1", BytesIn: in}}}})
		server.service.recordIPsec(time.Now())
	}
	const gigabytes = 20_000_000_000
	report(gigabytes)
	if got := server.usage(t, user); got != 0 {
		t.Fatalf("a session's whole total was counted at the first report: %d", got)
	}
	report(gigabytes + 100)
	if got := server.usage(t, user); got != 100 {
		t.Fatalf("usage = %d, want 100", got)
	}
	// The server restarts; the agent and the session carry on.
	server.service.ipsecSeen, server.service.ipsecLast = map[string]ipsecBaseline{}, time.Time{}
	report(gigabytes + 500)
	if got := server.usage(t, user); got != 100 {
		t.Fatalf("usage after a restart = %d, want 100: the session was counted again", got)
	}
	report(gigabytes + 700)
	if got := server.usage(t, user); got != 300 {
		t.Fatalf("usage = %d, want 300", got)
	}
}

// Enforcement ends a session: for a moment it is in neither list, and its final counters come
// as a closed child. They must be counted against what was counted already.
func TestIPsecSessionEndedByEnforcementIsCountedOnce(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	child := func(in uint64) []ipsecproto.Child { return []ipsecproto.Child{{UniqueID: "1", BytesIn: in}} }
	live := func(in uint64) {
		fakeAgent(t, server, []ipsecproto.SA{{Name: "gl-ikev2-eap", UniqueID: "7", Version: 2, Identity: key.Identity, Remote: "198.51.100.20", Children: child(in)}})
		server.service.recordIPsec(time.Now())
	}
	status := func(sas, closed []ipsecproto.SA) {
		data, _ := json.Marshal(ipsecproto.Status{Version: 1, UpdatedUnix: time.Now().Unix(), Running: true, SAs: sas, Closed: closed})
		_ = os.WriteFile(filepath.Join(server.store.Dir(), IPsecDir, ipsecproto.StatusFile), data, 0o640)
		server.service.recordIPsec(time.Now())
	}
	live(0)
	live(3000)
	if got := server.usage(t, user); got != 3000 {
		t.Fatalf("usage = %d, want 3000", got)
	}
	status([]ipsecproto.SA{}, nil) // terminated; the final counters have not arrived yet
	status([]ipsecproto.SA{}, []ipsecproto.SA{{Name: "gl-ikev2-eap", UniqueID: "7", Version: 2, Identity: key.Identity, Remote: "198.51.100.20", Children: child(3100)}})
	if got := server.usage(t, user); got != 3100 {
		t.Fatalf("usage = %d, want 3100: the session's total was counted twice", got)
	}
	// A listing that failed for one report leaves every session out of it.
	live(5000)
	status([]ipsecproto.SA{}, nil)
	live(5200)
	if got := server.usage(t, user); got != 3100+2100 {
		t.Fatalf("usage = %d, want %d: a failed listing counted the totals again", got, 3100+2100)
	}
}

// A closed session stays in the agent's report for a minute; reporting it again is not the client
// being there.
func TestClosedIPsecSessionsDoNotKeepAClientSeen(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	start := time.Now()
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	child := func(in uint64) []ipsecproto.Child {
		return []ipsecproto.Child{{UniqueID: "1", BytesIn: in, BytesOut: in}}
	}
	send := func(sas, closed []ipsecproto.SA, now time.Time) {
		data, _ := json.Marshal(ipsecproto.Status{Version: 1, UpdatedUnix: now.Unix(), Running: true, SAs: sas, Closed: closed})
		_ = os.WriteFile(filepath.Join(server.store.Dir(), IPsecDir, ipsecproto.StatusFile), data, 0o640)
		server.service.recordIPsec(now)
	}
	sa := func(in uint64) ipsecproto.SA {
		return ipsecproto.SA{Name: "gl-ikev2-eap", UniqueID: "7", Version: 2, Identity: key.Identity, Remote: "198.51.100.20", Children: child(in)}
	}
	lastSeen := func() int64 { return server.service.monitor.user("u" + user.ID).lastSeen.Load() }
	send([]ipsecproto.SA{sa(0)}, nil, at(0))
	send([]ipsecproto.SA{sa(100)}, nil, at(3))
	if lastSeen() != at(3).Unix() {
		t.Fatalf("a live session was not seen: %d", lastSeen())
	}
	send([]ipsecproto.SA{}, []ipsecproto.SA{sa(150)}, at(6)) // the last bytes
	last := lastSeen()
	for _, second := range []int{9, 12, 15, 18} {
		send([]ipsecproto.SA{}, []ipsecproto.SA{sa(150)}, at(second))
	}
	if lastSeen() != last {
		t.Fatalf("a closed session kept the client seen: %d, was %d", lastSeen(), last)
	}
	if got := server.usage(t, user); got != 300 {
		t.Fatalf("usage = %d, want 300", got)
	}
}

func TestIPsecSettingsAreWrittenOnlyWhenTheyChange(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Phone"})
	server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	before := server.desired(t).Generation

	// The usage accounting saves the state every 30 s while anyone has traffic. That is not a
	// change for the agent, which reloads strongSwan and its firewall for every new generation.
	server.service.monitor.AddExternal("u"+user.ID, IKEv2, 10, 10, "198.51.100.20", time.Now())
	if got := server.usage(t, user); got != 20 {
		t.Fatalf("usage = %d, want 20", got)
	}
	if after := server.desired(t).Generation; after != before {
		t.Fatalf("the usage accounting rewrote the agent's settings (generation %d, was %d)", after, before)
	}

	// A real change still arrives, and the daily refresh of the CRL always writes.
	server.must(t, http.StatusOK, "PATCH", "/users/"+user.ID, map[string]any{"speed_limit_bps": 500_000}, nil)
	changed := server.desired(t)
	if changed.Generation == before || len(changed.SpeedLimits) != 1 {
		t.Fatalf("a speed limit did not reach the agent: %+v", changed.SpeedLimits)
	}
	// (A day later, as the daily check runs it; the CRL carries its dates in whole seconds.)
	if err := server.service.WriteIPsecDesired(time.Now().Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if refreshed := server.desired(t); refreshed.Generation == changed.Generation || refreshed.CRL == changed.CRL {
		t.Fatal("a forced write did not refresh the generation and the CRL")
	}
	// Disabling the user withdraws the identity at once.
	server.must(t, http.StatusOK, "PATCH", "/users/"+user.ID, map[string]any{"enabled": false}, nil)
	if d := server.desired(t); len(d.Allowed) != 0 {
		t.Fatalf("disabled user still allowed: %v", d.Allowed)
	}
}

// Changes and writes at the same time: the file must end up holding the newest state, and no
// write may fail because another one is replacing the same files.
func TestIPsecSettingsWritesAreSerialized(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	var wg sync.WaitGroup
	failures := make(chan error, 64)
	for g := 0; g < 6; g++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 6; i++ {
				if err := server.service.WriteIPsecDesired(time.Now()); err != nil {
					failures <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 6; i++ {
				enabled := (g+i)%2 == 0
				if err := server.service.Change(func(s *State) error { s.User(user.ID).Enabled = enabled; return nil }); err != nil {
					failures <- err
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("concurrent write: %v", err)
	}
	var enabled bool
	server.service.Read(func(s *State) { enabled = s.User(user.ID).Enabled })
	if got := slices.Contains(server.desired(t).Allowed, key.Identity); got != enabled {
		t.Fatalf("the file says allowed=%v but the user is enabled=%v: an older write won", got, enabled)
	}
}

func TestProfileIdentifierNamesTheServerByItsCA(t *testing.T) {
	server := ipsecServer(t)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	identifier := func(server *testServer, user userView, key keyView) string {
		status, _, body := server.raw(t, "GET", "/users/"+user.ID+"/keys/"+key.ID+"/profile", nil)
		if status != http.StatusOK {
			t.Fatalf("profile: %d", status)
		}
		return readPlist(t, body)["PayloadIdentifier"].(string)
	}
	first := identifier(server, user, key)
	if !regexp.MustCompile(`^org\.ghostlink\.[0-9a-f]{12}\.` + key.ID + `$`).MatchString(first) {
		t.Fatalf("identifier %q", first)
	}
	// The name can change without the device holding a second copy of the profile.
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"name": "Another name"}, nil)
	if got := identifier(server, user, key); got != first {
		t.Fatalf("a server rename changed the identifier: %q -> %q", first, got)
	}
	// Another server with the same name and the same key ID must not replace this profile.
	other, err := NewState(InitOptions{Hostname: "127.0.0.1", Name: "Another name"})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.ensureIPsecPKI(time.Now(), func(string, uint16) bool { return true }); err != nil {
		t.Fatal(err)
	}
	owner := &User{ID: user.ID, Name: "Phone", Enabled: true}
	otherKey, err := other.NewKeyWith(owner, IKEv2, KeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	otherKey.ID = key.ID
	profile, err := other.AppleProfile(owner, otherKey, ProfileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := readPlist(t, profile)["PayloadIdentifier"].(string); got == first {
		t.Fatalf("two servers share the identifier %q", got)
	}
}

// The server certificate must name the new address when the server starts with one (the
// installer's --hostname and `setup --hostname` change it while the server is stopped).
func TestIPsecHostnameChangedWhileStoppedRenewsTheServerCertificate(t *testing.T) {
	dir := t.TempDir()
	store, _, err := Initialize(dir, InitOptions{Hostname: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.State.ensureIPsecPKI(time.Now(), portFree); err != nil {
		t.Fatal(err)
	}
	store.State.IPsec.IKEv2Enabled = true
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	renewed, _, err := Initialize(dir, InitOptions{Hostname: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseCertPEM(renewed.State.IPsec.ServerPEM)
	if err != nil || len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "203.0.113.9" || renewed.State.IPsec.ServerFor != "203.0.113.9" {
		t.Fatalf("the server certificate still names the old address: %v %v", cert.IPAddresses, err)
	}
}

// A state saved with a stale certificate (a server started by an older setup) is renewed at
// start, not a day later, and the agent is told straight away.
func TestIPsecStartRenewsAStaleServerCertificate(t *testing.T) {
	server := newTestServer(t, func(s *State) {
		if err := s.ensureIPsecPKI(time.Now(), portFree); err != nil {
			t.Fatal(err)
		}
		s.IPsec.IKEv2Enabled = true
		s.Hostname = "203.0.113.9"
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		var names string
		server.service.Read(func(s *State) { names = s.IPsec.ServerFor })
		if names == "203.0.113.9" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server certificate still names %q", names)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for {
		data, err := os.ReadFile(filepath.Join(server.store.Dir(), IPsecDir, ipsecproto.DesiredFile))
		var d ipsecproto.Desired
		if err == nil && json.Unmarshal(data, &d) == nil && d.ServerID == "203.0.113.9" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent was not told the new address: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
