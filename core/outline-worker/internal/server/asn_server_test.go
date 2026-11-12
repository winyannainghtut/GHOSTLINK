// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/asn"
)

// The ranges and AS numbers are the ones set aside for documentation (RFC 5737, RFC 3849 and
// RFC 5398): no real network is named in these tests.
const testASNList = "192.0.2.0\t192.0.2.255\t64496\tZZ\tEXAMPLE-ONE - Example Telecom One, Inc.\n" +
	"198.51.100.0\t198.51.100.255\t64498\tZZ\tEXAMPLE-THREE - Example Three\n" +
	"203.0.113.0\t203.0.113.255\t0\tNone\tNot routed\n" +
	"2001:db8::\t2001:db8::ffff\t64497\tZZ\tEXAMPLE-TWO - Example Mobile Two\n"

func gzipped(t *testing.T, text string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// asnSource is a stand-in for iptoasn.com on the local machine: what it answers can be changed,
// and an answer can be held back until the test lets it go.
type asnSource struct {
	mu     sync.Mutex
	status int
	body   []byte
	hold   chan struct{}
	hits   atomic.Int32
}

func serveASN(t *testing.T, body []byte) *asnSource {
	t.Helper()
	source := &asnSource{status: http.StatusOK, body: body}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source.hits.Add(1)
		source.mu.Lock()
		status, body, hold := source.status, source.body, source.hold
		source.mu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	oldURL, oldHTTP, oldMin, oldPoll := asnSourceURL, asnAllowHTTP, asnMinRanges, asnPoll
	asnSourceURL, asnAllowHTTP, asnMinRanges, asnPoll = httpServer.URL+"/ip2asn-combined.tsv.gz", true, 3, 10*time.Millisecond
	t.Cleanup(func() {
		httpServer.Close()
		asnSourceURL, asnAllowHTTP, asnMinRanges, asnPoll = oldURL, oldHTTP, oldMin, oldPoll
	})
	return source
}

func (s *asnSource) answer(status int, body []byte) {
	s.mu.Lock()
	s.status, s.body = status, body
	s.mu.Unlock()
}

func mustTable(t *testing.T) *asn.Table {
	t.Helper()
	table, err := asn.Parse(strings.NewReader(testASNList))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func (s *testServer) asnStatus(t *testing.T) asnStatus {
	t.Helper()
	var info serverInfo
	s.must(t, http.StatusOK, "GET", "/server", nil, &info)
	return info.ASN
}

// seenFrom makes the monitor record that user (an ID) connected from address.
func seenFrom(t *testing.T, server *testServer, user, address string) {
	t.Helper()
	server.service.monitor.AddExternal("u"+user, IKEv2, 10, 10, address, time.Now())
	server.service.Record(time.Now())
}

func (s *testServer) clients(t *testing.T) (map[string]clientView, asnStatus) {
	t.Helper()
	var out struct {
		Clients []clientView `json:"clients"`
		ASN     asnStatus    `json:"asn"`
	}
	s.must(t, http.StatusOK, "GET", "/clients", nil, &out)
	byIP := map[string]clientView{}
	for _, c := range out.Clients {
		byIP[c.IP] = c
	}
	return byIP, out.ASN
}

// Turned on, the lookup shows who runs each address; until then it shows nothing, and asks nobody.
func TestASNLookupIsOffUntilTurnedOn(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	server := newTestServer(t, nil)
	alice := server.user(t, map[string]any{"name": "Alice"})
	seenFrom(t, server, alice.ID, "192.0.2.10")

	byIP, status := server.clients(t)
	if status.Enabled || status.Ready || byIP["192.0.2.10"].ASN != 0 || byIP["192.0.2.10"].Operator != "" {
		t.Fatalf("a provider while the lookup is off: %+v %+v", byIP["192.0.2.10"], status)
	}
	if server.asnStatus(t).Enabled {
		t.Fatal("the lookup is on in a new server")
	}
	time.Sleep(100 * time.Millisecond)
	if source.hits.Load() != 0 {
		t.Fatalf("the list was downloaded %d time(s) while the lookup is off", source.hits.Load())
	}
	if _, err := os.Stat(server.store.Dir() + "/" + ASNFile); err == nil {
		t.Fatal("a list is saved while the lookup is off")
	}
}

func TestASNLookupShowsTheProviderOfAClient(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	server := newTestServer(t, nil)
	alice := server.user(t, map[string]any{"name": "Alice"})
	for _, address := range []string{"192.0.2.10", "2001:db8::5", "10.1.2.3", "203.0.113.9", "198.51.100.7"} {
		seenFrom(t, server, alice.ID, address)
	}

	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": true}, nil)
	waitFor(t, "the list", func() bool { return server.asnStatus(t).Ready })
	status := server.asnStatus(t)
	if !status.Enabled || status.Updating || status.Error != "" || status.Ranges != 3 || status.Source != ASNSource || status.UpdatedUnix == 0 {
		t.Fatalf("status after the download: %+v", status)
	}
	if source.hits.Load() != 1 {
		t.Fatalf("downloaded %d times", source.hits.Load())
	}

	byIP, listed := server.clients(t)
	if !listed.Ready {
		t.Fatalf("/clients does not say the lookup is ready: %+v", listed)
	}
	for address, want := range map[string]struct {
		number   uint32
		operator string
	}{
		"192.0.2.10":   {64496, "Example Telecom One, Inc."},
		"2001:db8::5":  {64497, "Example Mobile Two"},
		"198.51.100.7": {64498, "Example Three"},
		"10.1.2.3":     {}, // a private address is nobody's
		"203.0.113.9":  {}, // not routed
	} {
		got, ok := byIP[address]
		if !ok {
			t.Fatalf("%s is not listed", address)
		}
		if got.ASN != want.number || got.Operator != want.operator {
			t.Errorf("%s: AS%d %q, want AS%d %q", address, got.ASN, got.Operator, want.number, want.operator)
		}
	}
	// Saved for the next start, and counted among the server's data.
	if info, err := os.Stat(server.store.Dir() + "/" + ASNFile); err != nil || info.Size() == 0 {
		t.Fatalf("the list was not saved: %v", err)
	}
	if _, err := os.Stat(server.store.Dir() + "/" + ASNFile + ".pending"); err == nil {
		t.Fatal("the download left its temporary file")
	}
}

// What a server that is not iptoasn.com, or iptoasn.com on a bad day, may send: none of it is
// used, the error is said, and nothing is left on disk.
func TestASNBadListsAreRefused(t *testing.T) {
	good := gzipped(t, testASNList)
	for name, c := range map[string]struct {
		status int
		body   []byte
		want   string
	}{
		"rate limited":       {http.StatusTooManyRequests, []byte("slow down"), "429"},
		"server error":       {http.StatusInternalServerError, []byte("oops"), "500"},
		"html in place":      {http.StatusOK, gzipped(t, "<html>Please log in</html>\n"), "ip2asn format"},
		"not gzip at all":    {http.StatusOK, []byte("192.0.2.0\t192.0.2.255\t64496\tZZ\tX - Y\n"), "gzip"},
		"cut off":            {http.StatusOK, good[:len(good)/2], "refused"},
		"too few ranges":     {http.StatusOK, gzipped(t, "192.0.2.0\t192.0.2.255\t64496\tZZ\tX - Y\n"), "only 1 ranges"},
		"empty":              {http.StatusOK, nil, "refused"},
		"expands enormously": {http.StatusOK, gzipped(t, strings.Repeat("192.0.2.0\t192.0.2.255\t64496\tZZ\tX - Y\n", 50_000)), "expands to more than"},
	} {
		t.Run(name, func(t *testing.T) {
			source := serveASN(t, good)
			source.answer(c.status, c.body)
			if name == "expands enormously" {
				old := asnMaxExpanded
				asnMaxExpanded = 1 << 20
				t.Cleanup(func() { asnMaxExpanded = old })
			}
			server := newTestServer(t, nil)
			server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": true}, nil)
			waitFor(t, "the try to end", func() bool {
				s := server.asnStatus(t)
				return !s.Updating && s.Error != ""
			})
			status := server.asnStatus(t)
			if status.Ready || !strings.Contains(status.Error, c.want) {
				t.Fatalf("status %+v, want an error with %q and no list", status, c.want)
			}
			for _, file := range []string{ASNFile, ASNFile + ".pending"} {
				if _, err := os.Stat(server.store.Dir() + "/" + file); err == nil {
					t.Fatalf("%s was left on disk", file)
				}
			}
		})
	}
}

// A download that fails later does not take away the list that works.
func TestASNFailedUpdateKeepsTheListInUse(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	server := newTestServer(t, nil)
	alice := server.user(t, map[string]any{"name": "Alice"})
	seenFrom(t, server, alice.ID, "192.0.2.10")
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": true}, nil)
	waitFor(t, "the list", func() bool { return server.asnStatus(t).Ready })

	source.answer(http.StatusBadGateway, []byte("bad gateway"))
	var accepted asnStatus
	server.must(t, http.StatusAccepted, "POST", "/asn/update", nil, &accepted)
	waitFor(t, "the failed update", func() bool {
		s := server.asnStatus(t)
		return !s.Updating && s.Error != ""
	})
	status := server.asnStatus(t)
	if !status.Ready || !strings.Contains(status.Error, "502") {
		t.Fatalf("status after a failed update: %+v", status)
	}
	if byIP, _ := server.clients(t); byIP["192.0.2.10"].ASN != 64496 {
		t.Fatalf("the list in use was lost: %+v", byIP["192.0.2.10"])
	}

	// And the next good answer clears the error.
	source.answer(http.StatusOK, gzipped(t, strings.Replace(testASNList, "Example Telecom One, Inc.", "Renamed Telecom", 1)))
	server.must(t, http.StatusAccepted, "POST", "/asn/update", nil, nil)
	waitFor(t, "the new list", func() bool {
		s := server.asnStatus(t)
		return !s.Updating && s.Error == ""
	})
	if byIP, _ := server.clients(t); byIP["192.0.2.10"].Operator != "Renamed Telecom" {
		t.Fatalf("the new list is not in use: %+v", byIP["192.0.2.10"])
	}
}

func TestASNUpdateNeedsTheLookupOn(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	server := newTestServer(t, nil)
	server.must(t, http.StatusBadRequest, "POST", "/asn/update", nil, nil)
	if !strings.Contains(server.last, "turn it on first") {
		t.Fatalf("answer: %s", server.last)
	}
	if source.hits.Load() != 0 {
		t.Fatal("a download started while the lookup is off")
	}
}

// Turning it off deletes the list, and a download that was still running does not bring it back.
func TestASNTurnedOffDeletesTheListAndStopsADownloadInFlight(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	server := newTestServer(t, nil)
	alice := server.user(t, map[string]any{"name": "Alice"})
	seenFrom(t, server, alice.ID, "192.0.2.10")
	path := server.store.Dir() + "/" + ASNFile

	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": true}, nil)
	waitFor(t, "the list", func() bool { return server.asnStatus(t).Ready })
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": false}, nil)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the list was kept after the lookup was turned off")
	}
	if byIP, status := server.clients(t); status.Enabled || byIP["192.0.2.10"].ASN != 0 {
		t.Fatalf("a provider after turning it off: %+v %+v", byIP["192.0.2.10"], status)
	}

	// Turned on, and off again while the answer is on its way.
	source.mu.Lock()
	source.hold = make(chan struct{})
	hold := source.hold
	source.mu.Unlock()
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": true}, nil)
	waitFor(t, "the download to begin", func() bool { return source.hits.Load() == 2 })
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": false}, nil)
	close(hold)
	waitFor(t, "the download to end", func() bool {
		server.service.asn.mu.Lock()
		defer server.service.asn.mu.Unlock()
		return !server.service.asn.busy
	})
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a download that began before the lookup was turned off put its list back")
	}
	if _, found := server.service.asn.Lookup(netip.MustParseAddr("192.0.2.10")); found {
		t.Fatal("the list of a download that began before the lookup was turned off is in use")
	}
	if status := server.asnStatus(t); status.Enabled || status.Error != "" {
		t.Fatalf("status while off: %+v", status)
	}
}

// The saved list is read at start without asking anyone; one that cannot be read is removed so
// that the next try downloads a new one.
func TestASNLoadReadsTheSavedList(t *testing.T) {
	source := serveASN(t, nil)
	dir := t.TempDir()
	manager := newASNManager(dir)
	if err := manager.Load(); err != nil || manager.Status(true).Ready {
		t.Fatalf("nothing saved: %v %+v", err, manager.Status(true))
	}
	if err := os.WriteFile(manager.path(), gzipped(t, testASNList), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	status := manager.Status(true)
	if !status.Ready || status.Ranges != 3 || time.Since(time.Unix(status.UpdatedUnix, 0)) > time.Minute {
		t.Fatalf("status: %+v", status)
	}
	if info, found := manager.Lookup(netip.MustParseAddr("198.51.100.200")); !found || info.Number != 64498 {
		t.Fatalf("lookup: %+v %v", info, found)
	}

	damaged := newASNManager(t.TempDir())
	if err := os.WriteFile(damaged.path(), []byte("not a gzip file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := damaged.Load(); err == nil {
		t.Fatal("a damaged list was accepted")
	}
	if _, err := os.Stat(damaged.path()); err == nil {
		t.Fatal("a damaged list was kept")
	}
	if source.hits.Load() != 0 {
		t.Fatal("loading asked the network")
	}
}

// A list is downloaded again when there is none, or it is a month old, and not more often than
// every few hours after a failure.
func TestASNDue(t *testing.T) {
	now := time.Now()
	manager := newASNManager(t.TempDir())
	if !manager.Due(now) {
		t.Fatal("not due with no list")
	}
	if _, ok := manager.begin(now); !ok {
		t.Fatal("begin")
	}
	if manager.Due(now.Add(48 * time.Hour)) {
		t.Fatal("due while a download is running")
	}
	manager.finish(os.ErrDeadlineExceeded)
	if manager.Due(now.Add(time.Hour)) {
		t.Fatal("due an hour after a failure")
	}
	if !manager.Due(now.Add(asnRetryAfter + time.Minute)) {
		t.Fatal("not due long after a failure with no list")
	}
	manager.table.Store(mustTable(t))
	manager.updated = now
	if manager.Due(now.Add(7 * 24 * time.Hour)) {
		t.Fatal("due with a week-old list")
	}
	if !manager.Due(now.Add(asnRefreshAge + time.Hour)) {
		t.Fatal("not due with a list over a month old")
	}
}

func TestASNLowDiskRefusesTheDownload(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	diskCheck = func(string) (uint64, uint64, bool) { return 100_000_000, 30_000_000_000, true }
	t.Cleanup(func() { diskCheck = diskSpace })
	server := newTestServer(t, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"asn_lookup": true}, nil)
	waitFor(t, "the try to end", func() bool { s := server.asnStatus(t); return !s.Updating && s.Error != "" })
	if status := server.asnStatus(t); status.Ready || !strings.Contains(status.Error, "free disk space") {
		t.Fatalf("status: %+v", status)
	}
	if source.hits.Load() != 0 {
		t.Fatal("the list was downloaded onto a nearly full disk")
	}
}

// A redirect away from HTTPS is not followed: the list would travel in the clear and could be
// replaced on the way.
func TestASNRefusesARedirectToHTTP(t *testing.T) {
	oldAllow := asnAllowHTTP
	asnAllowHTTP = false
	t.Cleanup(func() { asnAllowHTTP = oldAllow })
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzipped(t, testASNList))
	}))
	t.Cleanup(insecure.Close)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, insecure.URL+"/list.gz", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	oldURL, oldClient := asnSourceURL, asnHTTPClient
	asnSourceURL = redirector.URL
	asnHTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: redirector.Client().Transport, CheckRedirect: oldClient.CheckRedirect}
	t.Cleanup(func() { asnSourceURL, asnHTTPClient = oldURL, oldClient })

	manager := newASNManager(t.TempDir())
	generation, _ := manager.begin(time.Now())
	err := manager.download(t.Context(), generation)
	if err == nil || !strings.Contains(err.Error(), "redirected away from HTTPS") {
		t.Fatalf("download followed a redirect to HTTP: %v", err)
	}
	if manager.Status(true).Ready {
		t.Fatal("a list from a redirect to HTTP is in use")
	}
}

// `ghostlink-server asn ...` and the provider columns of `clients`, on the real API listener.
func TestAdminASNCommands(t *testing.T) {
	source := serveASN(t, gzipped(t, testASNList))
	server := newTestServer(t, func(s *State) { s.API.Port = freeTCPPort(t) })
	alice := server.user(t, map[string]any{"name": "Alice"})
	seenFrom(t, server, alice.ID, "192.0.2.10")
	seenFrom(t, server, alice.ID, "10.9.9.9")
	run := adminCommands(t, server)
	mustRun := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	contains := func(out string, wants ...string) {
		t.Helper()
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Fatalf("output lacks %q:\n%s", want, out)
			}
		}
	}

	// Off: no provider columns, and the way to get them.
	contains(mustRun("asn", "status"), "off", "asn on")
	out := mustRun("clients")
	contains(out, "ADDRESS", "192.0.2.10", "sudo ghostlink-server asn on")
	if strings.Contains(out, "OPERATOR") {
		t.Fatalf("provider columns while off:\n%s", out)
	}
	contains(mustRun("settings"), "Provider lookup (AS and operator of client addresses): off")

	// On: the command waits for the list and says how it went.
	contains(mustRun("asn", "on"), "Provider lookup is on: 3 address ranges")
	out = mustRun("clients")
	contains(out, "AS", "OPERATOR", "AS64496", "Example Telecom One, Inc.", "10.9.9.9")
	if strings.Contains(out, "asn on") {
		t.Fatalf("the hint is shown with the lookup on:\n%s", out)
	}
	contains(mustRun("settings"), "Provider lookup: on, 3 address ranges from iptoasn.com")
	contains(mustRun("--json", "clients"), `"asn": 64496`, `"operator": "Example Telecom One, Inc."`)
	contains(mustRun("--json", "asn", "status"), `"enabled": true`, `"ready": true`)

	// Update downloads again; a failing source is an error, and the list in use stays.
	contains(mustRun("asn", "update"), "Provider lookup is on")
	if source.hits.Load() != 2 {
		t.Fatalf("downloads: %d, want 2", source.hits.Load())
	}
	source.answer(http.StatusInternalServerError, []byte("no"))
	if out, err := run("asn", "update"); err == nil || !strings.Contains(err.Error(), "could not be downloaded") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("a failing source: %v\n%s", err, out)
	}
	contains(mustRun("clients"), "AS64496")
	contains(mustRun("settings"), "The last update failed")

	// Off deletes the list.
	contains(mustRun("asn", "off"), "off", "deleted")
	contains(mustRun("settings"), "Provider lookup (AS and operator of client addresses): off")
	if _, err := os.Stat(server.store.Dir() + "/" + ASNFile); err == nil {
		t.Fatal("the list is still on disk")
	}
	for _, args := range [][]string{{"asn"}, {"asn", "maybe"}, {"asn", "on", "now"}} {
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), "usage: asn") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if out, err := run("asn", "update"); err == nil || !strings.Contains(err.Error(), "turn it on first") {
		t.Fatalf("update while off: %v\n%s", err, out)
	}
}
