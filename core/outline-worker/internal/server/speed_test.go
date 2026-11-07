// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// bulkServer answers every request with size bytes.
func bulkServer(t *testing.T, size int) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	payload := strings.Repeat("g", size)
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		io.WriteString(w, payload)
	}))
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// Speed limits with real clients: a capped client downloads at its cap, through Shadowsocks
// and through WireGuard (whose connections come from the server's userspace stack); others
// are not slowed; the server default and "no limit" apply live, without an engine reload.
func TestSpeedLimitsEndToEnd(t *testing.T) {
	const size = 3_000_000
	bulk := bulkServer(t, size)
	testInternalPort = bulk
	t.Cleanup(func() { testInternalPort = 0 })
	server := newTestServer(t, nil)

	capped := server.user(t, map[string]any{"name": "Capped", "speed_limit_bps": 1_000_000})
	if capped.SpeedLimitBps != 1_000_000 || capped.EffectiveSpeedLimitBps != 1_000_000 {
		t.Fatalf("capped view: %+v", capped)
	}
	free := server.user(t, map[string]any{"name": "Free"})
	cappedSS, cappedWG, freeSS := server.key(t, capped, Shadowsocks), server.key(t, capped, WireGuard), server.key(t, free, Shadowsocks)
	proxies := map[*keyView]uint16{}
	for _, key := range []*keyView{&cappedSS, &cappedWG, &freeSS} {
		proxies[key] = freeTCPPort(t)
		startClient(t, clientConfig(t, *key, proxies[key]))
	}
	download := func(key *keyView) time.Duration {
		t.Helper()
		host := "127.0.0.1"
		if key.Protocol == WireGuard {
			host = parseConf(t, key.Config)["DNS"]
		}
		start := time.Now()
		body, err := fetch(proxies[key], net.JoinHostPort(host, strconv.Itoa(int(bulk))), "bulk.test", 4)
		if err != nil || len(body) != size {
			t.Fatalf("%s download: %d bytes, %v", key.Protocol, len(body), err)
		}
		return time.Since(start)
	}
	// 3 MB at 1 MB/s, less the 250 KB burst: about 2.75 s.
	atCap := func(name string, took time.Duration, rate float64) {
		t.Helper()
		want := (size - burstFor(int64(rate))) / rate
		if s := took.Seconds(); s < want*0.8 || s > want*1.6 {
			t.Fatalf("%s took %.2f s; at the cap it should take about %.2f s", name, s, want)
		}
	}
	reloads := server.service.engine.Reloads()

	atCap("capped Shadowsocks", download(&cappedSS), 1_000_000)
	atCap("capped WireGuard", download(&cappedWG), 1_000_000)
	if took := download(&freeSS); took > 1500*time.Millisecond {
		t.Fatalf("an unlimited client took %v for 3 MB", took)
	}

	// The server default caps everyone without a limit of their own, at once.
	var info serverInfo
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"default_speed_limit_bps": 2_000_000}, nil)
	server.must(t, http.StatusOK, "GET", "/server", nil, &info)
	if info.DefaultSpeedLimitBps != 2_000_000 {
		t.Fatalf("default not reported: %d", info.DefaultSpeedLimitBps)
	}
	atCap("Free under the 2 MB/s default", download(&freeSS), 2_000_000)
	atCap("Capped keeps its own 1 MB/s", download(&cappedSS), 1_000_000)

	// "No limit" overrides the default.
	var view userView
	server.must(t, http.StatusOK, "PATCH", "/users/"+free.ID, map[string]any{"speed_limit_bps": -1}, &view)
	if view.SpeedLimitBps != -1 || view.EffectiveSpeedLimitBps != 0 {
		t.Fatalf("no-limit view: %+v", view)
	}
	if took := download(&freeSS); took > 1500*time.Millisecond {
		t.Fatalf("a client with no limit took %v for 3 MB", took)
	}
	if got := server.service.engine.Reloads(); got != reloads {
		t.Fatalf("speed limit changes reloaded the engine (%d -> %d reloads)", reloads, got)
	}

	// Out-of-range values are refused.
	for _, bad := range []map[string]any{{"speed_limit_bps": -2}, {"speed_limit_bps": 2_000_000_000}} {
		if status := server.call(t, "PATCH", "/users/"+free.ID, bad, nil); status != http.StatusBadRequest {
			t.Fatalf("%v: status %d", bad, status)
		}
	}
	if status := server.call(t, "PATCH", "/server", map[string]any{"default_speed_limit_bps": 2_000_000_000}, nil); status != http.StatusBadRequest {
		t.Fatalf("too large default: status %d", status)
	}
}
