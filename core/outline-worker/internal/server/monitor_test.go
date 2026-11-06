// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bufio"
	"bytes"
	"fmt"
	"image"
	"image/color"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/makiuchi-d/gozxing"
	gozxingqr "github.com/makiuchi-d/gozxing/qrcode"
)

func TestMain(m *testing.M) {
	// Loopback only: no firewall prompts on development machines.
	listenAddress, apiListenHost = "127.0.0.1", "127.0.0.1"
	os.Exit(m.Run())
}

func labelBytesOf(items []labelBytes, label string) uint64 {
	for _, item := range items {
		if item.Label == label {
			return item.Bytes
		}
	}
	return 0
}

// openTunnel keeps a CONNECT tunnel open through a client proxy so the server sees an open
// connection.
func openTunnel(t *testing.T, proxyPort uint16, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("tunnel: %v", err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: plain.test\r\n\r\n")
	return conn
}

// Real clients through the server: live rates and connections, traffic types, protocols,
// opt-in sites, client addresses (including WireGuard endpoints from UAPI) and persistence.
func TestMonitoringEndToEnd(t *testing.T) {
	web := webServer(t, strings.Repeat("x", 200_000))
	testInternalPort = web
	t.Cleanup(func() { testInternalPort = 0 })
	server := newTestServer(t, nil)
	alice := server.user(t, map[string]any{"name": "Alice"})
	bob := server.user(t, map[string]any{"name": "Bob"})
	ssKey := server.key(t, alice, Shadowsocks)
	wgKey := server.key(t, bob, WireGuard)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"site_stats": true}, nil)
	aliceProxy, bobProxy := freeTCPPort(t), freeTCPPort(t)
	startClient(t, clientConfig(t, ssKey, aliceProxy))
	startClient(t, clientConfig(t, wgKey, bobProxy))
	monitor := server.service.monitor

	monitor.Sample(time.Now())
	if body, err := fetch(aliceProxy, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(web))), "www.youtube.com", 4); err != nil || len(body) != 200_000 {
		t.Fatalf("alice fetch: %v", err)
	}
	monitor.Sample(time.Now())
	wgTarget := net.JoinHostPort(parseConf(t, wgKey.Config)["DNS"], strconv.Itoa(int(web)))
	if _, err := fetch(bobProxy, wgTarget, "plain.test", 6); err != nil {
		t.Fatalf("bob fetch: %v", err)
	}

	var live struct {
		Users []liveUser `json:"users"`
	}
	server.must(t, http.StatusOK, "GET", "/live", nil, &live)
	if live.Users[0].Name != "Alice" || live.Users[0].DownBps < 100_000 || !live.Users[0].Online {
		t.Fatalf("alice's live rate was not measured: %+v", live.Users)
	}

	held := openTunnel(t, aliceProxy, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(web))))
	waitFor(t, "an open connection", func() bool {
		server.must(t, http.StatusOK, "GET", "/live", nil, &live)
		return live.Users[0].Active >= 1
	})
	held.Close()
	waitFor(t, "the connection to close", func() bool {
		server.must(t, http.StatusOK, "GET", "/live", nil, &live)
		return live.Users[0].Active == 0
	})

	var stats StatsResult
	server.must(t, http.StatusOK, "GET", "/stats?range=24h&user="+alice.ID, nil, &stats)
	if labelBytesOf(stats.Types, "Web (HTTP)") < 200_000 || labelBytesOf(stats.Protocols, Shadowsocks) < 200_000 {
		t.Fatalf("alice's breakdown: types=%+v protocols=%+v", stats.Types, stats.Protocols)
	}
	if labelBytesOf(stats.Sites, "YouTube") < 200_000 {
		t.Fatalf("site stats on, but YouTube was not counted: %+v", stats.Sites)
	}
	if len(stats.Series) == 0 || stats.Series[0].Down < 200_000 {
		t.Fatalf("hourly series: %+v", stats.Series)
	}
	server.must(t, http.StatusOK, "GET", "/stats?range=7d&user="+bob.ID, nil, &stats)
	if labelBytesOf(stats.Protocols, WireGuard) == 0 {
		t.Fatalf("bob's WireGuard traffic missing: %+v", stats.Protocols)
	}

	var clients struct {
		Clients []clientView `json:"clients"`
	}
	server.must(t, http.StatusOK, "GET", "/clients", nil, &clients)
	seen := map[string]string{}
	for _, c := range clients.Clients {
		seen[c.Name] = c.Protocol + " " + c.IP
	}
	if seen["Alice"] != "shadowsocks 127.0.0.1" || seen["Bob"] != "wireguard 127.0.0.1" {
		t.Fatalf("client addresses: %+v", clients.Clients)
	}

	// Saved history is reloaded by a new monitor.
	server.service.SaveHistory(time.Now())
	reloaded := NewMonitor()
	if err := reloaded.LoadHistory(filepath.Join(server.store.Dir(), HistoryFile)); err != nil {
		t.Fatal(err)
	}
	persisted, err := reloaded.Stats(server.store.State, "24h", "u"+alice.ID, time.Now())
	if err != nil || labelBytesOf(persisted.Sites, "YouTube") == 0 {
		t.Fatalf("history did not persist: %+v %v", persisted, err)
	}

	// Turning site statistics off deletes them.
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"site_stats": false}, nil)
	server.must(t, http.StatusOK, "GET", "/stats?range=24h&user="+alice.ID, nil, &stats)
	if len(stats.Sites) != 0 {
		t.Fatalf("sites remained after turning them off: %+v", stats.Sites)
	}
	reloaded.readHistory(func(h *History) {}) // loaded copy is independent
	monitor.readHistory(func(h *History) {
		for _, day := range h.Daily["u"+alice.ID] {
			if len(day.Sites) != 0 {
				t.Fatal("site totals still stored")
			}
		}
	})
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestUserNamesAreUnique(t *testing.T) {
	server := newTestServer(t, nil)
	server.user(t, map[string]any{"name": "Alice"})
	if got := server.call(t, "POST", "/users", map[string]any{"name": "alice"}, nil); got != http.StatusBadRequest {
		t.Fatalf("duplicate name: status %d", got)
	}
	bob := server.user(t, map[string]any{"name": "Bob"})
	if got := server.call(t, "PATCH", "/users/"+bob.ID, map[string]any{"name": "ALICE"}, nil); got != http.StatusBadRequest {
		t.Fatalf("rename onto another user's name: status %d", got)
	}
	server.must(t, http.StatusOK, "PATCH", "/users/"+bob.ID, map[string]any{"name": "Bob"}, nil)
}

func TestHistoryRotation(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	settings := MonitorSettings{HistoryDays: 30, SiteDays: 10}
	h := newHistory()
	for day := 0; day < 40; day++ {
		at := now.Add(-time.Duration(day) * 24 * time.Hour)
		h.addTraffic("u1", at, 100, 200)
		h.addDetail("u1", at, "type", "Web (HTTPS)", 300)
		h.addDetail("u1", at, "site", "YouTube", 300)
	}
	h.addClient("u1", "203.0.113.1", Shadowsocks, now.Add(-40*24*time.Hour).Unix(), now.Add(-35*24*time.Hour).Unix())
	h.addClient("u1", "203.0.113.2", Shadowsocks, now.Unix(), now.Unix())
	if _, err := h.encode(now, settings, 1<<30); err != nil {
		t.Fatal(err)
	}
	days := h.Daily["u1"]
	if len(days) != 30 {
		t.Fatalf("kept %d days, want 30 (30-day retention)", len(days))
	}
	for _, d := range days {
		if d.T < now.Add(-10*24*time.Hour).Truncate(24*time.Hour).Unix() && len(d.Sites) != 0 {
			t.Fatal("site totals outlived their retention")
		}
	}
	if len(h.Hourly["u1"]) > hourlyDays+1 || len(h.Clients["u1"]) != 1 {
		t.Fatalf("hourly %d, clients %+v", len(h.Hourly["u1"]), h.Clients["u1"])
	}

	// Over the size cap: sites go first, then breakdowns, then hourly, then daily totals.
	full, _ := h.encode(now, settings, 1<<30)
	trimmed, err := h.encode(now, settings, len(full)-200)
	if err != nil || len(trimmed) > len(full)-200 {
		t.Fatalf("not trimmed under the cap: %d", len(trimmed))
	}
	sites, breakdowns := 0, 0
	for _, d := range h.Daily["u1"] {
		sites += len(d.Sites)
		breakdowns += len(d.Types)
	}
	if breakdowns == 0 || len(h.Daily["u1"]) != 30 {
		t.Fatal("trimmed more valuable data before site totals")
	}
	tiny, _ := h.encode(now, settings, 400)
	if len(tiny) > 400 {
		t.Fatalf("a tiny cap was not honored: %d bytes", len(tiny))
	}
	_ = sites
}

func TestLowDiskPausesDetail(t *testing.T) {
	m := NewMonitor()
	free := uint64(10 << 30)
	diskCheck = func(string) (uint64, uint64, bool) { return free, 100 << 30, true }
	t.Cleanup(func() { diskCheck = diskSpace })
	if paused, _ := m.CheckDisk("x"); paused {
		t.Fatal("paused with plenty of space")
	}
	free = 100 << 20
	if paused, changed := m.CheckDisk("x"); !paused || !changed {
		t.Fatal("did not pause when nearly full")
	}
	m.counters(adapterContext("u1", "tls"))
	m.mu.Lock()
	details := len(m.detail)
	m.mu.Unlock()
	if details != 0 {
		t.Fatal("detail was recorded while paused")
	}
	free = 10 << 30
	if paused, changed := m.CheckDisk("x"); paused || !changed {
		t.Fatal("did not resume when space returned")
	}
}

// decode reads a QR bitmap back with an independent decoder.
func decodeQR(t *testing.T, black func(x, y int) bool, size int) string {
	t.Helper()
	const scale = 6
	img := image.NewGray(image.Rect(0, 0, size*scale, size*scale))
	for y := 0; y < size*scale; y++ {
		for x := 0; x < size*scale; x++ {
			if black(x/scale, y/scale) {
				img.SetGray(x, y, color.Gray{0})
			} else {
				img.SetGray(x, y, color.Gray{255})
			}
		}
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	result, err := gozxingqr.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		t.Fatalf("QR code does not decode: %v", err)
	}
	return result.GetText()
}

func TestQRCodesDecodeToTheKey(t *testing.T) {
	state, err := NewState(InitOptions{Hostname: "203.0.113.7", PortFree: func(string, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	user := &User{ID: "1", Name: "Eve", Enabled: true}
	for _, protocol := range Protocols {
		key, err := state.NewKey(user, protocol)
		if err != nil {
			t.Fatal(err)
		}
		user.Keys = append(user.Keys, key)
		issued, _ := state.Render(user, key)
		content, _ := qrContent(issued, "auto")

		svg, err := QRSVG(content)
		if err != nil {
			t.Fatalf("%s: %v", protocol, err)
		}
		size, _ := strconv.Atoi(regexp.MustCompile(`viewBox="0 0 (\d+) `).FindStringSubmatch(svg)[1])
		dark := map[[2]int]bool{}
		for _, m := range regexp.MustCompile(`M(\d+) (\d+)h(\d+)`).FindAllStringSubmatch(svg, -1) {
			x, _ := strconv.Atoi(m[1])
			y, _ := strconv.Atoi(m[2])
			w, _ := strconv.Atoi(m[3])
			for i := 0; i < w; i++ {
				dark[[2]int{x + i, y}] = true
			}
		}
		if got := decodeQR(t, func(x, y int) bool { return dark[[2]int{x, y}] }, size); got != content {
			t.Fatalf("%s SVG decodes to %q", protocol, got)
		}

		text, err := QRText(content)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(text, ""), "\n"), "\n")
		width := len([]rune(lines[0]))
		cells := map[[2]int]bool{}
		for row, line := range lines {
			for x, r := range []rune(line) {
				cells[[2]int{x, 2 * row}] = r == '█' || r == '▀'
				cells[[2]int{x, 2*row + 1}] = r == '█' || r == '▄'
			}
		}
		if got := decodeQR(t, func(x, y int) bool { return cells[[2]int{x, y}] }, width); got != content {
			t.Fatalf("%s terminal QR decodes to %q", protocol, got)
		}
	}
	page, err := state.Kit(user)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range user.Keys {
		issued, _ := state.Render(user, key)
		if !strings.Contains(page, htmlEscape(issued.AccessKey)) || strings.Count(page, "<svg") != len(user.Keys) {
			t.Fatalf("kit misses the %s key or a QR code", key.Protocol)
		}
	}
	if !strings.Contains(page, "Keep this page private") || strings.Contains(page, "<script") {
		t.Fatal("kit text or safety")
	}
}

func htmlEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&#34;")
		case '\'':
			b.WriteString("&#39;")
		case '+':
			b.WriteString("&#43;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type adapterMetadata = adapter.InboundContext

func adapterContext(user, protocol string) adapterMetadata {
	var metadata adapterMetadata
	metadata.User, metadata.Protocol, metadata.Inbound = user, protocol, Shadowsocks
	return metadata
}
