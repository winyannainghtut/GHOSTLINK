// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// withHostAddresses makes the host's interfaces carry addrs for one test.
func withHostAddresses(t *testing.T, addrs ...string) {
	t.Helper()
	saved := hostAddresses
	hostAddresses = func() []netip.Addr {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	t.Cleanup(func() { hostAddresses = saved })
}

func guardState(t *testing.T) *State {
	t.Helper()
	state, err := NewState(InitOptions{Hostname: "vpn.example.com", PortFree: func(string, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	state.Dashboard.Port = 20_001
	state.Rules = Rules{BlockedIPs: []string{"198.51.100.0/24"}, BlockedPorts: []string{"6881-6889"}, BlockSMTP: true, BlockBitTorrent: true}
	state.Users = []*User{
		{ID: "1", Name: "Alice", Enabled: true, Rules: Rules{BlockedIPs: []string{"203.0.113.7/32"}, BlockedPorts: []string{"5000"}}},
		{ID: "2", Name: "Carol", Enabled: true, ExemptFromGlobalRules: true},
	}
	return state
}

// Every UDP packet that leaves a session for another destination meets the rules a session to
// that destination would: sing-box routes a UDP session by its first packet only.
func TestUDPGuardRefusesWhatTheRulesRefuse(t *testing.T) {
	withHostAddresses(t, "192.0.2.10", "2001:db8::10", "10.0.0.5", "127.0.0.1")
	state := guardState(t)
	g := newUDPGuard(state)
	utp := make([]byte, 20)
	utp[0] = 4<<4 | 1 // a uTP SYN, version 1, no extensions
	api, dashboard := fmt.Sprint(state.API.Port), fmt.Sprint(state.Dashboard.Port)
	cases := []struct {
		user, destination string
		packet            []byte
		want              bool
	}{
		{"u1", "203.0.113.50:443", nil, true},
		{"u1", "127.0.0.53:53", nil, false},
		{"u1", "203.0.113.50:53", nil, false}, // another resolver: DNS goes to the server's
		{"u1", "127.0.0.1:8080", nil, false},
		{"u1", "10.1.2.3:9000", nil, false},
		{"u1", "169.254.169.254:80", nil, false},
		{"u1", "100.64.0.1:9000", nil, false},
		{"u1", "[::1]:9000", nil, false},
		{"u1", "[fd00::1]:9000", nil, false},
		{"u1", "[::ffff:127.0.0.1]:9000", nil, false},
		{"u1", "[64:ff9b::7f00:1]:9000", nil, false},
		{"u1", "192.0.2.10:22", nil, false}, // the host's own public addresses
		{"u1", "[2001:db8::10]:5432", nil, false},
		{"u1", "203.0.113.50:" + api, nil, false},
		{"u1", "203.0.113.50:" + dashboard, nil, false},
		{"u1", "203.0.113.7:443", nil, false}, // Alice's own rules
		{"u1", "203.0.113.50:5000", nil, false},
		{"u2", "203.0.113.7:443", nil, true},   // are not Carol's
		{"u1", "198.51.100.9:443", nil, false}, // the rules for everyone
		{"u1", "203.0.113.50:6885", nil, false},
		{"u1", "203.0.113.50:25", nil, false},
		{"u1", "203.0.113.50:50000", utp, false},
		{"u2", "198.51.100.9:443", nil, true}, // Carol is exempt from them
		{"u2", "203.0.113.50:50000", utp, true},
		{"u2", "127.0.0.1:9000", nil, false},  // but not from the internal blocks
		{"u1", "example.com:443", nil, false}, // a name cannot be checked here
		{"", "198.51.100.9:443", nil, false},  // no user: the rules for everyone
	}
	for _, tc := range cases {
		if got := g.allows(tc.user, M.ParseSocksaddr(tc.destination), tc.packet); got != tc.want {
			t.Errorf("%s to %s: allowed %v, want %v", tc.user, tc.destination, got, tc.want)
		}
	}
}

// The host's own public addresses and the dashboard port are blocked like the API port: with
// host networking a connection to them arrives over loopback, past host firewall allowlists.
func TestEngineBlocksEveryAddressOfTheHost(t *testing.T) {
	withHostAddresses(t, "192.0.2.10", "2001:db8::10", "10.0.0.5", "fe80::1", "127.0.0.1")
	state := guardState(t)
	data, err := state.EngineConfig("off")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Route struct {
			Rules []struct {
				IPCIDR []string `json:"ip_cidr"`
				Port   []uint16 `json:"port"`
				Action string   `json:"action"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var own []string
	ports := false
	for _, rule := range config.Route.Rules {
		if rule.Action == "reject" && slices.Contains(rule.IPCIDR, "192.0.2.10/32") {
			own = rule.IPCIDR
		}
		ports = ports || rule.Action == "reject" && slices.Contains(rule.Port, state.API.Port) && slices.Contains(rule.Port, state.Dashboard.Port)
	}
	if strings.Join(own, ",") != "192.0.2.10/32,2001:db8::10/128" {
		t.Fatalf("the host's own addresses are not blocked as they should be: %v", own)
	}
	if !ports {
		t.Fatal("the API and dashboard ports are not blocked on every address")
	}
	// The hostname, when it is an address, stays blocked whatever the interfaces say.
	state.Hostname = "203.0.113.9"
	if addrs := state.serverAddresses(); !slices.Contains(addrs, netip.MustParseAddr("203.0.113.9")) || len(addrs) != 3 {
		t.Fatalf("server addresses: %v", addrs)
	}
}

// handshakeInbound is a client's UDP session that wants to hear when its outbound opened, as
// the WireGuard stack does (it releases the session's first packet then).
type handshakeInbound struct {
	framingInbound
	succeeded bool
}

func (h *handshakeInbound) HandshakeSuccess() error {
	h.succeeded = true
	return nil
}

// The policing wrapper lets sing reach the session inside for handshake reports and timeouts,
// while its reads stay its own.
func TestPolicedPacketConnPassesLookupsButNotReads(t *testing.T) {
	m := NewMonitor()
	inbound := &handshakeInbound{}
	conn := m.RoutedPacketConnection(context.Background(), inbound, adapter.InboundContext{User: "u1", Inbound: WireGuard}, nil, nil)
	if err := N.ReportPacketConnHandshakeSuccess(conn, nil); err != nil || !inbound.succeeded {
		t.Fatalf("the handshake report did not reach the session: %v", err)
	}
	if reader, _ := N.UnwrapCountPacketReader(conn, nil); reader == N.PacketReader(inbound) {
		t.Fatal("the copy loop would read past the policing wrapper")
	} else if _, ok := reader.(*policedPacketConn); !ok {
		t.Fatalf("reads stop at %T, not at the policing wrapper", reader)
	}
}

// sendTo sends one datagram on the association to another destination than the first one.
func (s *socksUDP) sendTo(t *testing.T, addr netip.Addr, port uint16, payload []byte) {
	t.Helper()
	ip := addr.As4()
	header := []byte{0, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := s.relay.Write(append(header, payload...)); err != nil {
		t.Fatal(err)
	}
}

// A UDP session through the real server, routed to an allowed service, cannot then send its
// packets to a service the rules block: here another port on the server's own loopback.
func TestUDPSessionsCannotSwitchToBlockedDestinations(t *testing.T) {
	allowed, hidden := udpEcho(t), udpEcho(t)
	testInternalPort = allowed
	t.Cleanup(func() { testInternalPort = 0 })
	server := newTestServer(t, nil)
	for _, protocol := range []string{Shadowsocks, WireGuard} {
		t.Run(protocol, func(t *testing.T) {
			user := server.user(t, map[string]any{"name": "UDP " + protocol})
			key := server.key(t, user, protocol)
			proxy := freeTCPPort(t)
			startClient(t, clientConfig(t, key, proxy))
			// WireGuard clients reach the server's loopback through its tunnel address.
			target := netip.MustParseAddr("127.0.0.1")
			if protocol == WireGuard {
				target = netip.MustParseAddr(parseConf(t, key.Config)["DNS"])
			}
			udp := openSocksUDP(t, proxy, allowed)
			first, other := []byte("routed destination"), []byte("blocked destination")
			got := 0
			for attempt := 0; attempt < 10 && got == 0; attempt++ {
				udp.sendTo(t, target, allowed, first)
				got = udp.receive(t, first, 500*time.Millisecond)
			}
			if got == 0 {
				t.Fatal("the routed destination did not answer")
			}
			for range 5 {
				udp.sendTo(t, target, hidden, other)
			}
			if got := udp.receive(t, other, time.Second); got != 0 {
				t.Fatalf("%d packets reached a loopback service through a session routed elsewhere", got)
			}
			udp.sendTo(t, target, allowed, first)
			if got := udp.receive(t, first, time.Second); got != 1 {
				t.Fatalf("the routed destination stopped answering (%d)", got)
			}
		})
	}
}
