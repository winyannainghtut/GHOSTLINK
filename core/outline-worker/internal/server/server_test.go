// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/wireguard"
	boxjson "github.com/sagernet/sing/common/json"

	"ghostlink.local/outline-worker/internal/awg"
)

// --- client side: unmodified sing-box clients built only from the keys the API returns ---

func clientContext() context.Context {
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)
	out := outbound.NewRegistry()
	shadowsocks.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	direct.RegisterOutbound(out)
	endpoints := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpoints)
	awg.Register(endpoints)
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	return box.Context(context.Background(), in, out, endpoints, dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry())
}

func startClient(t *testing.T, config string) {
	t.Helper()
	ctx := clientContext()
	options, err := boxjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatalf("client config: %v\n%s", err, config)
	}
	options.Log = &option.LogOptions{Disabled: true}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func parseConf(t *testing.T, conf string) map[string]string {
	t.Helper()
	values := map[string]string{}
	for _, line := range strings.Split(conf, "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return values
}

// clientConfig turns an issued key into a sing-box client with a local HTTP proxy.
func clientConfig(t *testing.T, key keyView, proxyPort uint16) string {
	t.Helper()
	inbound := fmt.Sprintf(`"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}]`, proxyPort)
	switch key.Protocol {
	case Shadowsocks:
		link, err := url.Parse(key.AccessKey)
		if err != nil || link.Scheme != "ss" || link.Query().Get("outline") != "1" {
			t.Fatalf("bad ss:// key: %v", err)
		}
		credential, err := base64.RawURLEncoding.DecodeString(link.User.Username())
		if err != nil {
			t.Fatal(err)
		}
		method, password, _ := strings.Cut(string(credential), ":")
		return fmt.Sprintf(`{%s,"outbounds":[{"type":"shadowsocks","tag":"proxy","server":%q,"server_port":%s,"method":%q,"password":%q}],"route":{"final":"proxy"}}`,
			inbound, link.Hostname(), link.Port(), method, password)
	case VLESS:
		link, err := url.Parse(key.AccessKey)
		if err != nil || link.Scheme != "vless" {
			t.Fatalf("bad vless:// key: %v", err)
		}
		q := link.Query()
		if q.Get("security") != "reality" || q.Get("type") != "tcp" || q.Get("encryption") != "none" {
			t.Fatalf("unexpected vless parameters: %v", q)
		}
		return fmt.Sprintf(`{%s,"outbounds":[{"type":"vless","tag":"proxy","server":%q,"server_port":%s,"uuid":%q,"flow":%q,
		  "tls":{"enabled":true,"server_name":%q,"utls":{"enabled":true,"fingerprint":%q},"reality":{"enabled":true,"public_key":%q,"short_id":%q}}}],"route":{"final":"proxy"}}`,
			inbound, link.Hostname(), link.Port(), link.User.Username(), q.Get("flow"), q.Get("sni"), q.Get("fp"), q.Get("pbk"), q.Get("sid"))
	case WireGuard, AmneziaWG:
		conf := parseConf(t, key.Config)
		host, port, err := net.SplitHostPort(conf["Endpoint"])
		if err != nil {
			t.Fatal(err)
		}
		obfuscation := map[string]string{}
		for _, name := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1"} {
			if value, ok := conf[name]; ok {
				obfuscation[strings.ToLower(name)] = value
			}
		}
		if (key.Protocol == AmneziaWG) != (len(obfuscation) > 0) {
			t.Fatalf("%s config has obfuscation=%v", key.Protocol, obfuscation)
		}
		kind, extra := "wireguard", ""
		if key.Protocol == AmneziaWG {
			raw, _ := json.Marshal(obfuscation)
			kind, extra = "amneziawg", `,"obfuscation":`+string(raw)
		}
		return fmt.Sprintf(`{%s,"endpoints":[{"type":%q,"tag":"proxy","address":[%q],"private_key":%q,"mtu":%s,
		  "peers":[{"address":%q,"port":%s,"public_key":%q,"pre_shared_key":%q,"allowed_ips":["0.0.0.0/0"]}]%s}],"route":{"final":"proxy"}}`,
			inbound, kind, conf["Address"], conf["PrivateKey"], conf["MTU"], host, port, conf["PublicKey"], conf["PresharedKey"], extra)
	}
	t.Fatalf("unknown protocol %q", key.Protocol)
	return ""
}

// fetch opens a CONNECT tunnel to the target address and sends a request naming host, as a
// browser does: the server sees an IP destination and learns the site name by sniffing.
func fetch(proxyPort uint16, target, host string, attempts int) (string, error) {
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		body, err := fetchOnce(proxyPort, target, host)
		if err == nil {
			return body, nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return "", lastErr
}

func fetchOnce(proxyPort uint16, target, host string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	established, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "", err
	}
	if established.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy answered %d", established.StatusCode)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", response.StatusCode)
	}
	return string(body), nil
}

func webServer(t *testing.T, reply string) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, reply) }))
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// realityTarget is a local TLS 1.3 site for REALITY to borrow its handshake from.
func realityTarget(t *testing.T) uint16 {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "reality.test"},
		DNSNames: []string{"reality.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	decoy := &http.Server{ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "decoy") })}
	go decoy.Serve(listener)
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// --- server side ---

type testServer struct {
	service *Service
	store   *Store
	api     *httptest.Server
	base    string
}

func newTestServer(t *testing.T, mutate func(*State)) *testServer {
	t.Helper()
	state, err := NewState(InitOptions{Hostname: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(state)
	}
	store := &Store{dir: t.TempDir(), State: state}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	monitor := NewMonitor()
	logLevel := "off"
	if os.Getenv("GHOSTLINK_TEST_SERVER_LOG") != "" {
		logLevel = "debug"
	}
	service := NewService(store, NewEngine(monitor, logLevel), monitor)
	if err := service.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { service.Close() })
	api := httptest.NewServer(NewAPI(service, "test"))
	t.Cleanup(api.Close)
	return &testServer{service, store, api, api.URL + "/" + state.API.Secret}
}

func (s *testServer) call(t *testing.T, method, path string, body, out any) int {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request, _ := http.NewRequest(method, s.base+path, reader)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if out != nil && response.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, data)
		}
	}
	return response.StatusCode
}

func (s *testServer) must(t *testing.T, status int, method, path string, body, out any) {
	t.Helper()
	if got := s.call(t, method, path, body, out); got != status {
		t.Fatalf("%s %s: status %d, want %d", method, path, got, status)
	}
}

func (s *testServer) user(t *testing.T, body map[string]any) userView {
	t.Helper()
	var user userView
	s.must(t, http.StatusCreated, "POST", "/users", body, &user)
	return user
}

func (s *testServer) key(t *testing.T, user userView, protocol string) keyView {
	t.Helper()
	var key keyView
	s.must(t, http.StatusCreated, "POST", "/users/"+user.ID+"/keys", map[string]string{"protocol": protocol}, &key)
	return key
}

// The whole server: keys from the API, unmodified clients, per-user and global rules, the
// always-on internal blocks, usage, data limits, disabling and key removal.
func TestServerEndToEnd(t *testing.T) {
	web := webServer(t, "ok")
	hidden := webServer(t, "host service")
	testInternalPort = web
	t.Cleanup(func() { testInternalPort = 0 })
	target := realityTarget(t)
	server := newTestServer(t, func(s *State) {
		s.VLESS.Handshake, s.VLESS.HandshakeServer, s.VLESS.HandshakePort = "reality.test", "127.0.0.1", target
	})

	alice := server.user(t, map[string]any{"name": "Alice", "rules": map[string]any{"blocked_domains": []string{"alice-blocked.test"}}})
	bob := server.user(t, map[string]any{"name": "Bob"})
	carol := server.user(t, map[string]any{"name": "Carol", "exempt_from_global_rules": true})
	var rules Rules
	server.must(t, http.StatusOK, "PUT", "/rules", map[string]any{"blocked_domains": []string{"*.Global-Blocked.test"}, "block_smtp": true}, &rules)
	if len(rules.BlockedDomains) != 1 || rules.BlockedDomains[0] != "global-blocked.test" {
		t.Fatalf("rules were not normalized: %+v", rules)
	}
	aliceKeys := map[string]keyView{}
	for _, protocol := range Protocols {
		aliceKeys[protocol] = server.key(t, alice, protocol)
	}
	bobKey := server.key(t, bob, Shadowsocks)
	carolKey := server.key(t, carol, Shadowsocks)

	// WireGuard clients keep loopback inside their own stack, so they address the server's
	// tunnel IP, which the server maps to its loopback.
	destination := func(key keyView, port uint16) string {
		host := "127.0.0.1"
		if key.Protocol == WireGuard || key.Protocol == AmneziaWG {
			host = parseConf(t, key.Config)["DNS"] // the server's tunnel address
		}
		return net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	works := func(t *testing.T, proxy uint16, key keyView, host string) {
		t.Helper()
		if body, err := fetch(proxy, destination(key, web), host, 4); body != "ok" {
			t.Fatalf("%s for %s should work: body=%q err=%v", key.Protocol, host, body, err)
		}
	}
	blocked := func(t *testing.T, proxy uint16, key keyView, host string, port uint16) {
		t.Helper()
		if body, err := fetch(proxy, destination(key, port), host, 1); err == nil {
			t.Fatalf("%s for %s:%d should be blocked, got %q", key.Protocol, host, port, body)
		}
	}

	for _, protocol := range Protocols {
		key := aliceKeys[protocol]
		t.Run("alice/"+protocol, func(t *testing.T) {
			proxy := freeTCPPort(t)
			startClient(t, clientConfig(t, key, proxy))
			works(t, proxy, key, "plain.test")
			blocked(t, proxy, key, "alice-blocked.test", web)
			blocked(t, proxy, key, "www.global-blocked.test", web)
			blocked(t, proxy, key, "plain.test", hidden)
		})
	}
	bobProxy, carolProxy := freeTCPPort(t), freeTCPPort(t)
	startClient(t, clientConfig(t, bobKey, bobProxy))
	startClient(t, clientConfig(t, carolKey, carolProxy))
	t.Run("rules are per user", func(t *testing.T) {
		works(t, bobProxy, bobKey, "alice-blocked.test")
		blocked(t, bobProxy, bobKey, "global-blocked.test", web)
	})
	t.Run("exempt user skips global rules but not internal blocks", func(t *testing.T) {
		works(t, carolProxy, carolKey, "global-blocked.test")
		blocked(t, carolProxy, carolKey, "plain.test", hidden)
	})

	var metrics struct {
		Users []userUsage `json:"users"`
	}
	server.must(t, http.StatusOK, "GET", "/metrics", nil, &metrics)
	if metrics.Users[0].ID != alice.ID || metrics.Users[0].UsageBytes == 0 {
		t.Fatalf("alice's traffic was not counted: %+v", metrics.Users)
	}

	ssKey, aliceProxy := aliceKeys[Shadowsocks], freeTCPPort(t)
	startClient(t, clientConfig(t, ssKey, aliceProxy))
	t.Run("data limit", func(t *testing.T) {
		var updated userView
		server.must(t, http.StatusOK, "PATCH", "/users/"+alice.ID, map[string]any{"data_limit_bytes": 1}, &updated)
		if !updated.OverLimit {
			t.Fatalf("alice should be over her limit: %+v", updated)
		}
		blocked(t, aliceProxy, ssKey, "plain.test", web)
		server.must(t, http.StatusOK, "PATCH", "/users/"+alice.ID, map[string]any{"data_limit_bytes": 0, "reset_usage": true}, &updated)
		works(t, aliceProxy, ssKey, "plain.test")
	})
	t.Run("disabled user", func(t *testing.T) {
		server.must(t, http.StatusOK, "PATCH", "/users/"+bob.ID, map[string]any{"enabled": false}, nil)
		blocked(t, bobProxy, bobKey, "plain.test", web)
	})
	t.Run("removed key", func(t *testing.T) {
		server.must(t, http.StatusNoContent, "DELETE", "/users/"+carol.ID+"/keys/"+carolKey.ID, nil, nil)
		blocked(t, carolProxy, carolKey, "plain.test", web)
	})

	loaded, err := Load(server.store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.State.Users) != 3 || loaded.State.User(bob.ID).Enabled || len(loaded.State.User(carol.ID).Keys) != 0 {
		t.Fatalf("changes were not saved")
	}
}

func TestAPIRefusesBadRequests(t *testing.T) {
	server := newTestServer(t, nil)
	user := server.user(t, map[string]any{"name": "Dave"})
	cases := []struct {
		method, path string
		body         any
		status       int
	}{
		{"POST", "/users", map[string]any{"name": "x", "is_admin": true}, http.StatusBadRequest},
		{"POST", "/users", map[string]any{}, http.StatusBadRequest},
		{"POST", "/users", map[string]any{"name": "bad\x00name"}, http.StatusBadRequest},
		{"PUT", "/rules", map[string]any{"blocked_ips": []string{"not-an-ip"}}, http.StatusBadRequest},
		{"PUT", "/rules", map[string]any{"blocked_ports": []string{"70000"}}, http.StatusBadRequest},
		{"PUT", "/rules", map[string]any{"blocked_domains": []string{"bad domain"}}, http.StatusBadRequest},
		{"POST", "/users/" + user.ID + "/keys", map[string]any{"protocol": "openvpn"}, http.StatusBadRequest},
		{"GET", "/users/999", nil, http.StatusNotFound},
		{"DELETE", "/users/" + user.ID + "/keys/999", nil, http.StatusNotFound},
		{"PATCH", "/server", map[string]any{"hostname": "-bad-"}, http.StatusBadRequest},
		{"PATCH", "/server", map[string]any{"vless_handshake": "10.0.0.1"}, http.StatusBadRequest},
		{"DELETE", "/server", nil, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		if got := server.call(t, tc.method, tc.path, tc.body, nil); got != tc.status {
			t.Errorf("%s %s %v: status %d, want %d", tc.method, tc.path, tc.body, got, tc.status)
		}
	}

	// A port clash is refused and changes nothing.
	var info serverInfo
	server.must(t, http.StatusOK, "GET", "/server", nil, &info)
	clash := map[string]any{"protocols": map[string]any{VLESS: map[string]any{"port": info.APIPort}}}
	if got := server.call(t, "PATCH", "/server", clash, nil); got != http.StatusBadRequest {
		t.Fatalf("port clash: status %d", got)
	}
	var after serverInfo
	server.must(t, http.StatusOK, "GET", "/server", nil, &after)
	if after.Protocols[VLESS].Port != info.Protocols[VLESS].Port {
		t.Fatal("a refused change was applied")
	}

	// Keys cannot be issued for a protocol that is turned off.
	off := map[string]any{"protocols": map[string]any{WireGuard: map[string]any{"enabled": false}}}
	server.must(t, http.StatusOK, "PATCH", "/server", off, nil)
	if got := server.call(t, "POST", "/users/"+user.ID+"/keys", map[string]any{"protocol": WireGuard}, nil); got != http.StatusBadRequest {
		t.Fatalf("key for a disabled protocol: status %d", got)
	}
}

func TestAPISecretPath(t *testing.T) {
	server := newTestServer(t, nil)
	get := func(path string) int {
		response, err := http.Get(server.api.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if status := get("/" + server.store.State.API.Secret + "/server"); status != http.StatusOK {
		t.Fatalf("correct secret: %d", status)
	}
	for _, path := range []string{"/server", "/", "/" + server.store.State.API.Secret[1:] + "/server", "/" + server.store.State.API.Secret + "x/server"} {
		if status := get(path); status != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404", path, status)
		}
	}
	for i := 0; i < 20; i++ {
		get("/guess")
	}
	if status := get("/" + server.store.State.API.Secret + "/server"); status != http.StatusTooManyRequests {
		t.Fatalf("after repeated guesses: status %d, want 429", status)
	}
}

// The real listener: TLS 1.3 only, and the certificate matches the management key's pin.
func TestAPIListenerIsPinnedTLS13(t *testing.T) {
	server := newTestServer(t, func(s *State) { s.API.Port = freeTCPPort(t) })
	api := NewAPI(server.service, "test")
	httpServer, listener, err := api.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go httpServer.ServeTLS(listener, "", "")
	t.Cleanup(func() { httpServer.Close() })
	state := server.store.State
	pin, err := state.CertSHA256()
	if err != nil {
		t.Fatal(err)
	}
	key := state.ManagementKey(pin)
	pinned := func(want string) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // replaced by the pin check below, as in the Ghostlink app
			VerifyConnection: func(cs tls.ConnectionState) error {
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
					return fmt.Errorf("certificate does not match the pin")
				}
				return nil
			},
		}}}
	}
	response, err := pinned(key.CertSHA256).Get(key.APIURL + "/server")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("status %d, TLS %x", response.StatusCode, response.TLS.Version)
	}
	if _, err := pinned(strings.Repeat("0", 64)).Get(key.APIURL + "/server"); err == nil {
		t.Fatal("a wrong pin was accepted")
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}}}
	if _, err := old.Get(key.APIURL + "/server"); err == nil {
		t.Fatal("TLS 1.2 was accepted")
	}
}

func TestInitializeCreatesOnceAndPrintsKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, created, err := Initialize(dir, InitOptions{Hostname: "vpn.example.com"})
	if err != nil || !created {
		t.Fatalf("first init: created=%v err=%v", created, err)
	}
	if err := Check(store.State); err != nil {
		t.Fatalf("fresh configuration is invalid: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ManagementKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	var key ManagementKey
	if err := json.Unmarshal(data, &key); err != nil {
		t.Fatal(err)
	}
	pin, _ := store.State.CertSHA256()
	wantURL := fmt.Sprintf("https://vpn.example.com:%d/%s", store.State.API.Port, store.State.API.Secret)
	if key.APIURL != wantURL || key.CertSHA256 != pin || len(pin) != 64 || len(store.State.API.Secret) < 22 {
		t.Fatalf("management key %+v", key)
	}
	ports := map[uint16]bool{}
	for _, port := range []uint16{store.State.API.Port, store.State.Shadowsocks.Port, store.State.VLESS.Port, store.State.WireGuard.Port, store.State.AmneziaWG.Port} {
		if port < 10_000 || ports[port] {
			t.Fatalf("ports are not distinct high ports: %+v", store.State)
		}
		ports[port] = true
	}
	if !store.State.Rules.BlockSMTP {
		t.Fatal("outgoing mail should be blocked by default")
	}

	again, created, err := Initialize(dir, InitOptions{Hostname: "203.0.113.7"})
	if err != nil || created {
		t.Fatalf("second init: created=%v err=%v", created, err)
	}
	if again.State.API.Secret != store.State.API.Secret || again.State.Hostname != "203.0.113.7" {
		t.Fatal("re-running init must keep the server and only update the hostname")
	}
	if _, _, err := Initialize(filepath.Join(t.TempDir(), "x"), InitOptions{DetectHostname: func() (string, error) { return "", fmt.Errorf("offline") }}); err == nil {
		t.Fatal("init without an address should fail")
	}
}

// Amnezia keys are in the exporter's format and contain no SSH credentials.
func TestAmneziaKeys(t *testing.T) {
	state, err := NewState(InitOptions{Hostname: "203.0.113.7", PortFree: func(string, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	user := &User{ID: "1", Name: "Eve", Enabled: true}
	for protocol, container := range map[string]string{AmneziaWG: "amnezia-awg2", WireGuard: "amnezia-wireguard"} {
		key, err := state.NewKey(user, protocol)
		if err != nil {
			t.Fatal(err)
		}
		user.Keys = append(user.Keys, key)
		rendered, err := state.Render(user, key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rendered.AccessKey, "vpn://"))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := zlib.NewReader(bytes.NewReader(raw[4:]))
		if err != nil {
			t.Fatal(err)
		}
		document, _ := io.ReadAll(reader)
		if binary.BigEndian.Uint32(raw[:4]) != uint32(len(document)) {
			t.Fatal("length prefix does not match")
		}
		var parsed struct {
			Containers []map[string]json.RawMessage `json:"containers"`
			Default    string                       `json:"defaultContainer"`
			UserName   *string                      `json:"userName"`
			Password   *string                      `json:"password"`
		}
		if err := json.Unmarshal(document, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.UserName != nil || parsed.Password != nil || parsed.Default != container {
			t.Fatalf("%s: unexpected key document %s", protocol, document)
		}
		var section struct {
			LastConfig string `json:"last_config"`
		}
		sub := "wireguard"
		if protocol == AmneziaWG {
			sub = "awg"
		}
		json.Unmarshal(parsed.Containers[0][sub], &section)
		var last map[string]any
		json.Unmarshal([]byte(section.LastConfig), &last)
		if last["config"] != rendered.Config || last["client_ip"] != key.Address {
			t.Fatalf("%s: last_config does not carry the client config", protocol)
		}
		if protocol == AmneziaWG && last["H1"] != state.AmneziaWG.Params.H1 {
			t.Fatal("AmneziaWG parameters missing from the key")
		}
	}
	if user.Keys[0].Address == user.Keys[1].Address && state.AmneziaWG.Subnet == state.WireGuard.Subnet {
		t.Fatal("tunnel addresses collide")
	}
}

func TestAWGParametersAreValid(t *testing.T) {
	for i := 0; i < 200; i++ {
		p := newAWGParams()
		if p.S1+56 == p.S2 || p.Jmin >= p.Jmax || p.Jc < 1 {
			t.Fatalf("invalid parameters %+v", p)
		}
		type span struct{ lo, hi uint64 }
		var spans []span
		for _, h := range []string{p.H1, p.H2, p.H3, p.H4} {
			lo, hi, _ := strings.Cut(h, "-")
			a, _ := strconv.ParseUint(lo, 10, 32)
			b, err := strconv.ParseUint(hi, 10, 32)
			if err != nil || a < 5 || b <= a {
				t.Fatalf("bad header range %q", h)
			}
			for _, s := range spans {
				if a <= s.hi && s.lo <= b {
					t.Fatalf("header ranges overlap: %+v", p)
				}
			}
			spans = append(spans, span{a, b})
		}
	}
}

func TestRuleNormalization(t *testing.T) {
	rules, err := Rules{
		BlockedDomains: []string{"Example.COM", "*.example.com", ".example.com."},
		BlockedIPs:     []string{"192.0.2.1", "198.51.100.7/24"},
		BlockedPorts:   []string{"25", "6881-6889", "25"},
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rules.BlockedDomains, ",") != "example.com" ||
		strings.Join(rules.BlockedIPs, ",") != "192.0.2.1/32,198.51.100.0/24" ||
		strings.Join(rules.BlockedPorts, ",") != "25,6881-6889" {
		t.Fatalf("normalized: %+v", rules)
	}
	for _, bad := range []Rules{
		{BlockedDomains: []string{"192.0.2.1"}},
		{BlockedPorts: []string{"0"}},
		{BlockedPorts: []string{"9-3"}},
		{BlockedDomains: make([]string, maxRuleEntries+1)},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
