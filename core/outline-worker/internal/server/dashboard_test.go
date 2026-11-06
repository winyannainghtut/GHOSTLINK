// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

type dashboardHarness struct {
	server    *testServer
	dashboard *Dashboard
	token     string
}

func newDashboardHarness(t *testing.T) *dashboardHarness {
	t.Helper()
	server := newTestServer(t, func(s *State) {
		s.Dashboard = DashboardConfig{Port: freeTCPPort(t), Token: "test-token-1234567890"}
	})
	dashboard := NewDashboard(server.service, NewAPI(server.service, "test"))
	// Public mode would listen on every address; tests keep it on loopback.
	dashboard.listen = func(network, address string) (net.Listener, error) {
		if strings.HasPrefix(address, ":") {
			address = "127.0.0.1" + address
		}
		return net.Listen(network, address)
	}
	if err := dashboard.Apply(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dashboard.Close)
	server.service.OnChange(func(previous, next *State) {
		if previous.Dashboard != next.Dashboard {
			if err := dashboard.Apply(); err != nil {
				t.Errorf("apply: %v", err)
			}
		}
	})
	return &dashboardHarness{server, dashboard, "test-token-1234567890"}
}

func (h *dashboardHarness) url(path string) string {
	h.dashboard.mu.Lock()
	defer h.dashboard.mu.Unlock()
	scheme := "http"
	if h.dashboard.running.Public {
		scheme = "https"
	}
	return fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, h.dashboard.running.Port, path)
}

var insecure = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

func (h *dashboardHarness) send(t *testing.T, method, path string, body any, cookie *http.Cookie, header bool, host string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request, _ := http.NewRequest(method, h.url(path), reader)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if header {
		request.Header.Set(csrfHeader, "1")
	}
	if host != "" {
		request.Host = host
	}
	response, err := insecure.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func (h *dashboardHarness) login(t *testing.T, token string) (*http.Cookie, int) {
	t.Helper()
	response := h.send(t, "POST", "/login", map[string]string{"token": token}, nil, false, "")
	for _, c := range response.Cookies() {
		if c.Name == sessionCookie {
			return c, response.StatusCode
		}
	}
	return nil, response.StatusCode
}

func TestDashboardSignInAndProtections(t *testing.T) {
	h := newDashboardHarness(t)
	page := h.send(t, "GET", "/", nil, nil, false, "")
	body, _ := io.ReadAll(page.Body)
	if page.StatusCode != 200 || !strings.Contains(string(body), "Ghostlink server") || !strings.Contains(page.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("index: %d %s", page.StatusCode, page.Header)
	}
	if got := h.send(t, "GET", "/api/server", nil, nil, true, "").StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("no session: %d", got)
	}
	if _, status := h.login(t, "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", status)
	}
	cookie, status := h.login(t, h.token)
	if status != http.StatusNoContent || cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure {
		t.Fatalf("login: %d %+v", status, cookie)
	}
	if got := h.send(t, "GET", "/api/server", nil, cookie, false, "").StatusCode; got != http.StatusForbidden {
		t.Fatalf("missing CSRF header: %d", got)
	}
	if got := h.send(t, "GET", "/api/server", nil, cookie, true, "evil.example:1234").StatusCode; got != http.StatusForbidden {
		t.Fatalf("foreign Host: %d", got)
	}
	server := h.send(t, "GET", "/api/server", nil, cookie, true, "")
	var info serverInfo
	if err := json.NewDecoder(server.Body).Decode(&info); err != nil || info.DashboardPort == 0 || info.DashboardPublic {
		t.Fatalf("api through the dashboard: %v %+v", err, info)
	}
	user := h.server.user(t, map[string]any{"name": "Kit"})
	h.server.key(t, user, AmneziaWG)
	kit := h.send(t, "GET", "/api/users/"+user.ID+"/kit", nil, cookie, true, "")
	if kit.StatusCode != 200 || !strings.HasPrefix(kit.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("kit: %d %s", kit.StatusCode, kit.Header.Get("Content-Type"))
	}

	// The dashboard has its own port: never 443, below 1024 or another service's port.
	for _, port := range []any{443, 80, info.APIPort, info.Protocols[VLESS].Port} {
		if got := h.server.call(t, "PATCH", "/server", map[string]any{"dashboard_port": port}, nil); got != http.StatusBadRequest {
			t.Fatalf("dashboard port %v accepted: %d", port, got)
		}
	}
	moved := freeTCPPort(t)
	old := info.DashboardPort
	h.server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"dashboard_port": moved}, nil)
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", old), time.Second); err == nil {
		conn.Close()
		t.Fatal("the old dashboard port still answers")
	}
	if got := h.send(t, "GET", "/api/server", nil, cookie, true, "").StatusCode; got != 200 {
		t.Fatalf("dashboard on the new port: %d", got)
	}

	// A new token signs everyone out.
	h.server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"reset_dashboard_token": true}, nil)
	if got := h.send(t, "GET", "/api/server", nil, cookie, true, "").StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("old session after reset: %d", got)
	}

	// Public mode serves TLS 1.3 with the pinned certificate and marks the cookie Secure.
	h.server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"dashboard_public": true}, nil)
	var token string
	h.server.service.Read(func(s *State) { token = s.Dashboard.Token })
	h.token = token
	publicCookie, status := h.login(t, token)
	if status != http.StatusNoContent || !publicCookie.Secure {
		t.Fatalf("public login: %d %+v", status, publicCookie)
	}
	response := h.send(t, "GET", "/api/server", nil, publicCookie, true, "")
	pin, _ := h.server.store.State.CertSHA256()
	sum := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	if response.TLS.Version != tls.VersionTLS13 || !strings.EqualFold(hex.EncodeToString(sum[:]), pin) {
		t.Fatal("public dashboard is not TLS 1.3 with the pinned certificate")
	}
	h.server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"dashboard_public": false}, nil)
	if got := h.send(t, "GET", "/", nil, nil, false, "").StatusCode; got != 200 {
		t.Fatalf("back to private: %d", got)
	}
}

func TestDashboardLoginThrottling(t *testing.T) {
	h := newDashboardHarness(t)
	for i := 0; i < 20; i++ {
		h.login(t, "guess")
	}
	if _, status := h.login(t, h.token); status != http.StatusTooManyRequests {
		t.Fatalf("after 20 wrong tokens even the right one must wait: %d", status)
	}
}

// The dashboard is built from ui/ (npm run build:dashboard) into the embedded directory. The
// build must be complete, flat (the server serves only top-level names) and CSP-safe: no inline
// scripts or styles, nothing loaded from elsewhere.
func TestDashboardBuildIsCompleteAndCSPSafe(t *testing.T) {
	index, err := dashboardFiles.ReadFile("dashboard/index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:src|href)="\./([^"]+)"`).FindAllStringSubmatch(string(index), -1)
	var scripts, styles int
	for _, ref := range refs {
		name := ref[1]
		if strings.Contains(name, "/") {
			t.Fatalf("%s is not a top-level file", name)
		}
		data, err := dashboardFiles.ReadFile("dashboard/" + name)
		if err != nil {
			t.Fatalf("index.html refers to %s, which is not embedded", name)
		}
		switch {
		case strings.HasSuffix(name, ".js"):
			scripts++
			if bytes.Contains(data, []byte("eval(")) {
				t.Fatalf("%s uses eval, which the CSP refuses", name)
			}
		case strings.HasSuffix(name, ".css"):
			styles++
			for _, u := range regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(string(data), -1) {
				target := strings.Trim(u[1], `"'`)
				if strings.HasPrefix(target, "#") {
					continue
				}
				if !strings.HasPrefix(target, "./") {
					t.Fatalf("%s loads %s from outside the dashboard", name, target)
				}
				if _, err := dashboardFiles.ReadFile("dashboard/" + strings.TrimPrefix(target, "./")); err != nil {
					t.Fatalf("%s refers to %s, which is not embedded", name, target)
				}
			}
		}
	}
	if scripts != 1 || styles != 1 {
		t.Fatalf("index.html should load one script and one stylesheet, found %d and %d", scripts, styles)
	}
	if regexp.MustCompile(`<script(?:\s+[^>]*)?>[^<]+</script>|\sstyle=|<style`).Match(index) {
		t.Fatal("index.html has inline script or style")
	}
	entries, _ := dashboardFiles.ReadDir("dashboard")
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("dashboard/%s is a directory; the server serves only top-level files", entry.Name())
		}
	}
}
