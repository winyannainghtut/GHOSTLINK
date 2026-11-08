// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"net/netip"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/awg"
)

// A client counts as online only while it sends: a connection it left open, and the small
// writes remote services keep making to it, do not keep it online after it has gone.
func TestOnlineFollowsWhatTheClientSends(t *testing.T) {
	m := NewMonitor()
	u := m.user("u1")
	start := time.Unix(1_800_000_000, 0)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	m.Sample(at(0))

	u.active.Add(1)
	u.down.Add(1_000)
	m.Sample(at(1))
	if seen := u.lastSeen.Load(); seen != 0 {
		t.Fatalf("an open connection and a small write to the client counted as the client: %d", seen)
	}
	u.down.Add(liveDownload)
	m.Sample(at(2))
	if seen := u.lastSeen.Load(); seen != at(2).Unix() {
		t.Fatalf("a bulk download to the client did not count: %d", seen)
	}
	u.up.Add(1)
	m.Sample(at(3))
	if seen := u.lastSeen.Load(); seen != at(3).Unix() {
		t.Fatalf("an upload did not count: %d", seen)
	}

	seen := at(3).Unix()
	if !isOnline(seen, seen+onlineSeconds) || isOnline(seen, seen+onlineSeconds+1) || isOnline(0, seen) {
		t.Fatal("online must mean seen within the last minute")
	}
	users, _ := m.Live()
	if users["u1"].LastActive != seen || users["u1"].Active != 1 {
		t.Fatalf("live state: %+v", users["u1"])
	}
}

// WireGuard/AmneziaWG clients are seen through their peer's receive counter, which their 25 s
// keepalive moves even when they are idle, and through handshakes.
func TestPeersSeenThroughTheirReceiveCounter(t *testing.T) {
	m := NewMonitor()
	start := time.Unix(1_800_000_000, 0)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	endpoint := netip.MustParseAddrPort("198.51.100.20:40000")
	peer := PeerReport{User: "u2", Protocol: WireGuard, Key: "key", Status: awg.PeerStatus{RxBytes: 100, Endpoint: endpoint}}
	seen := func() int64 { return m.user("u2").lastSeen.Load() }

	m.PeersSeen([]PeerReport{peer}, at(0))
	if seen() != 0 {
		t.Fatal("a counter seen for the first time gives no time; it must not count")
	}
	m.PeersSeen([]PeerReport{peer}, at(5))
	if seen() != 0 {
		t.Fatal("an unchanged counter counted as the client sending")
	}
	peer.Status.RxBytes = 132
	m.PeersSeen([]PeerReport{peer}, at(10))
	if seen() != at(10).Unix() {
		t.Fatalf("a keepalive did not count: %d", seen())
	}
	peer.Status.RxBytes = 0 // the engine reloaded and its counters started again
	m.PeersSeen([]PeerReport{peer}, at(15))
	if seen() != at(10).Unix() {
		t.Fatalf("a counter that went back counted: %d", seen())
	}
	peer.Status.LastHandshake = at(12)
	m.PeersSeen([]PeerReport{peer}, at(20))
	if seen() != at(12).Unix() {
		t.Fatalf("a handshake did not count at its own time: %d", seen())
	}
	if clients := m.clients["u2"]; clients["198.51.100.20"].Protocol != WireGuard {
		t.Fatalf("the peer's real address was not recorded: %+v", clients)
	}
	// Peers that are gone are forgotten, so a key issued again starts from scratch.
	m.PeersSeen(nil, at(25))
	if len(m.peerRx) != 0 {
		t.Fatalf("stale peer counters kept: %v", m.peerRx)
	}
}
