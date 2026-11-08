// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package awg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	upconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	updevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/wireguard"
	boxjson "github.com/sagernet/sing/common/json"
	"golang.org/x/crypto/curve25519"
)

type keyPair struct{ private, public string }

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public)}
}

func hexKey(t *testing.T, b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func freePort(t *testing.T, network string) uint16 {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func testContext() context.Context {
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	endpoints := endpoint.NewRegistry()
	Register(endpoints)
	wireguard.RegisterEndpoint(endpoints)
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	return box.Context(context.Background(), in, out, endpoints, dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry())
}

func startBox(t *testing.T, config string) *box.Box {
	t.Helper()
	ctx := testContext()
	options, err := boxjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatalf("parse box config: %v\n%s", err, config)
	}
	options.Log = &option.LogOptions{Disabled: true}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("create box: %v", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatalf("start box: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func fetch(proxyPort uint16, target string) (string, error) {
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: 6 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		response, err := client.Get(target)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		return string(body), err
	}
	return "", lastErr
}

// upstreamServer runs an unmodified amneziawg-go device on a userspace netstack, listening on
// UDP and serving HTTP at 10.77.0.1 inside the tunnel.
func upstreamServer(t *testing.T, server, client keyPair, port uint16, obfuscation map[string]string) {
	t.Helper()
	tunDevice, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1376)
	if err != nil {
		t.Fatal(err)
	}
	upstream := updevice.NewDevice(tunDevice, upconn.NewStdNetBind(), updevice.NewLogger(updevice.LogLevelSilent, ""))
	var config strings.Builder
	fmt.Fprintf(&config, "private_key=%s\nlisten_port=%d", hexKey(t, server.private), port)
	for _, name := range obfuscationOrder {
		if value, ok := obfuscation[name]; ok {
			fmt.Fprintf(&config, "\n%s=%s", name, value)
		}
	}
	fmt.Fprintf(&config, "\npublic_key=%s\nallowed_ip=10.77.0.2/32", hexKey(t, client.public))
	if err := upstream.IpcSet(config.String()); err != nil {
		t.Fatalf("configure upstream peer: %v", err)
	}
	if err := upstream.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(upstream.Close)
	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "hello through amneziawg")
	}))
}

func obfuscationJSON(obfuscation map[string]string) string {
	if len(obfuscation) == 0 {
		return ""
	}
	encoded, _ := boxjson.Marshal(obfuscation)
	return `,"obfuscation":` + string(encoded)
}

func clientConfig(proxyPort, serverPort uint16, client, server keyPair, obfuscation map[string]string) string {
	return fmt.Sprintf(`{
	  "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
	  "endpoints":[{"type":"amneziawg","tag":"awg","address":["10.77.0.2/32"],"private_key":%q,
	    "peers":[{"address":"127.0.0.1","port":%d,"public_key":%q,"allowed_ips":["0.0.0.0/0"],"persistent_keepalive":"15"}]%s}],
	  "route":{"final":"awg"}
	}`, proxyPort, client.private, serverPort, server.public, obfuscationJSON(obfuscation))
}

var (
	legacyParameters = map[string]string{
		"jc": "3", "jmin": "10", "jmax": "30", "s1": "15", "s2": "18",
		"h1": "1234567", "h2": "2345678", "h3": "3456789", "h4": "4567890",
	}
	awg2Parameters = map[string]string{
		"jc": "4", "jmin": "10", "jmax": "50", "s1": "24", "s2": "28", "s3": "16", "s4": "12",
		"h1": "100000-199999", "h2": "200000-299999", "h3": "300000-399999", "h4": "400000-499999",
		"i1":                    "<b 0x0102030405><r 12><t>",
		"header_protection_key": strings.Repeat("ab", 32),
	}
)

func TestClientInteroperatesWithUpstreamAmneziaWG(t *testing.T) {
	for name, parameters := range map[string]map[string]string{
		"legacy AWG": legacyParameters, "AWG 2.0": awg2Parameters, "plain WireGuard": nil,
	} {
		t.Run(name, func(t *testing.T) {
			server, client := newKeyPair(t), newKeyPair(t)
			serverPort, proxyPort := freePort(t, "udp"), freePort(t, "tcp")
			upstreamServer(t, server, client, serverPort, parameters)
			startBox(t, clientConfig(proxyPort, serverPort, client, server, parameters))
			body, err := fetch(proxyPort, "http://10.77.0.1/")
			if err != nil || body != "hello through amneziawg" {
				t.Fatalf("no traffic through %s: body=%q err=%v", name, body, err)
			}
		})
	}
}

func TestMismatchedObfuscationIsRejected(t *testing.T) {
	server, client := newKeyPair(t), newKeyPair(t)
	serverPort, proxyPort := freePort(t, "udp"), freePort(t, "tcp")
	upstreamServer(t, server, client, serverPort, legacyParameters)
	wrong := map[string]string{}
	for k, v := range legacyParameters {
		wrong[k] = v
	}
	wrong["h1"] = "7654321"
	startBox(t, clientConfig(proxyPort, serverPort, client, server, wrong))
	if body, err := fetch(proxyPort, "http://10.77.0.1/"); err == nil {
		t.Fatalf("handshake with mismatched magic headers must fail, got %q", body)
	}
}

// Server role: our endpoint listens with zero obfuscation and a stock WireGuard client (the
// sing-box native endpoint on wireguard-go) reaches an HTTP server behind it.
func TestServerAcceptsStockWireGuardClient(t *testing.T) {
	server, client := newKeyPair(t), newKeyPair(t)
	serverPort, proxyPort := freePort(t, "udp"), freePort(t, "tcp")
	web, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "served behind ghostlink")
	}))
	startBox(t, fmt.Sprintf(`{
	  "endpoints":[{"type":"amneziawg","tag":"srv","address":["10.88.0.1/24"],"private_key":%q,"listen_port":%d,
	    "peers":[{"user":"alice","public_key":%q,"allowed_ips":["10.88.0.2/32"]}]}],
	  "outbounds":[{"type":"direct","tag":"direct"}],
	  "route":{"final":"direct"}
	}`, server.private, serverPort, client.public))
	startBox(t, fmt.Sprintf(`{
	  "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
	  "endpoints":[{"type":"wireguard","tag":"wg","address":["10.88.0.2/32"],"private_key":%q,
	    "peers":[{"address":"127.0.0.1","port":%d,"public_key":%q,"allowed_ips":["0.0.0.0/0"]}]}],
	  "route":{"final":"wg"}
	}`, proxyPort, client.private, serverPort, server.public))
	// Loopback never leaves the client's userspace stack, so address the server's tunnel IP;
	// the server maps its own tunnel addresses to its loopback.
	webPort := web.Addr().(*net.TCPAddr).Port
	body, err := fetch(proxyPort, fmt.Sprintf("http://10.88.0.1:%d/", webPort))
	if err != nil || body != "served behind ghostlink" {
		t.Fatalf("stock WireGuard client could not use the server: body=%q err=%v", body, err)
	}
}

func localWeb(t *testing.T, reply string) int {
	t.Helper()
	web, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { web.Close() })
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, reply) }))
	return web.Addr().(*net.TCPAddr).Port
}

func serverConfig(server keyPair, port uint16, rules string, peers []string, obfuscation map[string]string) string {
	return fmt.Sprintf(`{
	  "endpoints":[{"type":"amneziawg","tag":"srv","address":["10.88.0.1/24"],"private_key":%q,"listen_port":%d,
	    "peers":[%s]%s}],
	  "outbounds":[{"type":"direct","tag":"direct"}],
	  "route":{"rules":[%s],"final":"direct"}
	}`, server.private, port, strings.Join(peers, ","), obfuscationJSON(obfuscation), rules)
}

func peerJSON(user string, keys keyPair, address string) string {
	return fmt.Sprintf(`{"user":%q,"public_key":%q,"allowed_ips":[%q]}`, user, keys.public, address)
}

// An unmodified amneziawg-go client with AWG 2.0 parameters reaches the server.
func TestServerAcceptsUpstreamAmneziaWGClient(t *testing.T) {
	server, client := newKeyPair(t), newKeyPair(t)
	serverPort := freePort(t, "udp")
	webPort := localWeb(t, "awg server ok")
	startBox(t, serverConfig(server, serverPort, "", []string{peerJSON("alice", client, "10.88.0.2/32")}, awg2Parameters))
	tunDevice, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.88.0.2")}, nil, 1376)
	if err != nil {
		t.Fatal(err)
	}
	upstream := updevice.NewDevice(tunDevice, upconn.NewStdNetBind(), updevice.NewLogger(updevice.LogLevelSilent, ""))
	var config strings.Builder
	fmt.Fprintf(&config, "private_key=%s", hexKey(t, client.private))
	for _, name := range obfuscationOrder {
		if value, ok := awg2Parameters[name]; ok {
			fmt.Fprintf(&config, "\n%s=%s", name, value)
		}
	}
	fmt.Fprintf(&config, "\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1", hexKey(t, server.public), serverPort)
	if err := upstream.IpcSet(config.String()); err != nil {
		t.Fatal(err)
	}
	if err := upstream.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(upstream.Close)
	client2 := &http.Client{Transport: &http.Transport{DialContext: tnet.DialContext, DisableKeepAlives: true}, Timeout: 6 * time.Second}
	var body []byte
	for attempt := 0; attempt < 3; attempt++ {
		response, err := client2.Get(fmt.Sprintf("http://10.88.0.1:%d/", webPort))
		if err != nil {
			continue
		}
		body, _ = io.ReadAll(response.Body)
		response.Body.Close()
		break
	}
	if string(body) != "awg server ok" {
		t.Fatalf("upstream AmneziaWG client could not use the server: %q", body)
	}
}

// Each peer's traffic carries its user name, so auth_user rules apply per user.
func TestServerRulesMatchPeerUser(t *testing.T) {
	for _, tc := range []struct {
		blocked string
		allowed bool
	}{{"alice", false}, {"bob", true}} {
		t.Run("block "+tc.blocked, func(t *testing.T) {
			server, alice := newKeyPair(t), newKeyPair(t)
			serverPort, proxyPort := freePort(t, "udp"), freePort(t, "tcp")
			webPort := localWeb(t, "per-user ok")
			rules := fmt.Sprintf(`{"auth_user":[%q],"action":"reject"}`, tc.blocked)
			startBox(t, serverConfig(server, serverPort, rules, []string{peerJSON("alice", alice, "10.88.0.2/32")}, nil))
			startBox(t, fmt.Sprintf(`{
			  "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
			  "endpoints":[{"type":"wireguard","tag":"wg","address":["10.88.0.2/32"],"private_key":%q,
			    "peers":[{"address":"127.0.0.1","port":%d,"public_key":%q,"allowed_ips":["0.0.0.0/0"]}]}],
			  "route":{"final":"wg"}
			}`, proxyPort, alice.private, serverPort, server.public))
			body, err := fetch(proxyPort, fmt.Sprintf("http://10.88.0.1:%d/", webPort))
			if tc.allowed && body != "per-user ok" {
				t.Fatalf("alice should pass a rule for %s: body=%q err=%v", tc.blocked, body, err)
			}
			if !tc.allowed && body == "per-user ok" {
				t.Fatal("alice's traffic passed a rule that blocks alice")
			}
		})
	}
}

// upstreamClient runs an unmodified, unobfuscated amneziawg-go client with the tunnel address
// 10.88.0.2 against a server endpoint on serverPort.
func upstreamClient(t *testing.T, server, client keyPair, serverPort uint16) *netstack.Net {
	t.Helper()
	tunDevice, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.88.0.2")}, nil, 1376)
	if err != nil {
		t.Fatal(err)
	}
	upstream := updevice.NewDevice(tunDevice, upconn.NewStdNetBind(), updevice.NewLogger(updevice.LogLevelSilent, ""))
	config := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1",
		hexKey(t, client.private), hexKey(t, server.public), serverPort)
	if err := upstream.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	if err := upstream.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(upstream.Close)
	return tnet
}

// udpEcho answers each datagram sent to it on 127.0.0.1 with "echo " and the datagram.
func udpEcho(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			conn.WriteTo(append([]byte("echo "), buffer[:n]...), from)
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// udpExchange sends a datagram from socket to the server's tunnel address on port and returns the
// reply that comes back from there, or false if none arrives within about attempts seconds.
func udpExchange(socket net.PacketConn, port uint16, attempts int) (string, bool) {
	target := &net.UDPAddr{IP: net.IPv4(10, 88, 0, 1), Port: int(port)}
	buffer := make([]byte, 2048)
	for attempt := 0; attempt < attempts; attempt++ {
		if _, err := socket.WriteTo([]byte(fmt.Sprint("to ", port)), target); err != nil {
			return "", false
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			socket.SetReadDeadline(deadline)
			n, from, err := socket.ReadFrom(buffer)
			if err != nil {
				continue
			}
			// Ignore a late reply to an earlier exchange on the same socket.
			if address, ok := from.(*net.UDPAddr); ok && address.Port == int(port) {
				return string(buffer[:n]), true
			}
		}
	}
	return "", false
}

// The route rules see every UDP destination, not only the first one a socket sends to. Otherwise
// a client could send one allowed datagram and then reach blocked destinations, the server's
// internal ranges included, from the same socket.
func TestServerJudgesEveryUDPDestination(t *testing.T) {
	server, client := newKeyPair(t), newKeyPair(t)
	serverPort := freePort(t, "udp")
	allowed, blocked, other := udpEcho(t), udpEcho(t), udpEcho(t)
	rules := fmt.Sprintf(`{"port":[%d],"action":"reject"}`, blocked)
	startBox(t, serverConfig(server, serverPort, rules, []string{peerJSON("alice", client, "10.88.0.2/32")}, nil))
	tnet := upstreamClient(t, server, client, serverPort)
	socket, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.88.0.2"), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if reply, ok := udpExchange(socket, allowed, 6); reply != fmt.Sprint("echo to ", allowed) {
		t.Fatalf("no UDP through the server: %q %v", reply, ok)
	}
	if reply, ok := udpExchange(socket, blocked, 2); ok {
		t.Fatalf("a datagram to a blocked port passed after an allowed one from the same socket: %q", reply)
	}
	if reply, ok := udpExchange(socket, other, 3); reply != fmt.Sprint("echo to ", other) {
		t.Fatalf("a second allowed destination from the same socket got no answer: %q %v", reply, ok)
	}
}

func TestUAPIInjectionIsRejected(t *testing.T) {
	keys := newKeyPair(t)
	for _, bad := range []map[string]string{
		{"jc": "3\nlisten_port=1"},
		{"jc": "3=4"},
		{"fwmark": "1"},
		{"replace_peers": "true"},
	} {
		options := Options{PrivateKey: keys.private, Obfuscation: bad}
		if _, err := options.deviceConfig(); err == nil {
			t.Fatalf("accepted unsafe obfuscation %v", bad)
		}
	}
}

func TestParsePeers(t *testing.T) {
	state := "private_key=00\nlisten_port=1\npublic_key=" + strings.Repeat("ab", 32) +
		"\nendpoint=[::ffff:203.0.113.9]:51820\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=10\ntx_bytes=20\n" +
		"public_key=" + strings.Repeat("cd", 32) + "\nlast_handshake_time_sec=0\nrx_bytes=0\ntx_bytes=0\n"
	peers := parsePeers(state)
	first := peers[base64.StdEncoding.EncodeToString(mustHex(t, strings.Repeat("ab", 32)))]
	if first.RxBytes != 10 || first.TxBytes != 20 || first.Endpoint.String() != "203.0.113.9:51820" || first.LastHandshake.Unix() != 1700000000 {
		t.Fatalf("parsed %+v", first)
	}
	second := peers[base64.StdEncoding.EncodeToString(mustHex(t, strings.Repeat("cd", 32)))]
	if second.Endpoint.IsValid() || !second.LastHandshake.IsZero() {
		t.Fatalf("a peer without traffic must have no endpoint or handshake: %+v", second)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
