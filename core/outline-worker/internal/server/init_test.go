// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// "ghostlink-server setup --hostname" runs init with the new address. Like "set --hostname", it
// must reissue the IKEv2/IPsec server certificate, or Apple devices would refuse the server.
func TestInitializeNewHostnameRenewsIPsecCertificate(t *testing.T) {
	free := func(string, uint16) bool { return true }
	dir := filepath.Join(t.TempDir(), "state")
	store, _, err := Initialize(dir, InitOptions{Hostname: "203.0.113.7", PortFree: free})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.State.ensureIPsecPKI(time.Now(), free); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Initialize(dir, InitOptions{Hostname: "vpn.example.com", PortFree: free}); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ipsec := loaded.State.IPsec
	if ipsec.ServerFor != "vpn.example.com" {
		t.Fatalf("server certificate issued for %q after the new hostname", ipsec.ServerFor)
	}
	ca, err := parseCertPEM(ipsec.CAPEM)
	if err != nil {
		t.Fatal(err)
	}
	server, err := parseCertPEM(ipsec.ServerPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: "vpn.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server certificate for the new hostname: %v", err)
	}

	// A server that never turned IKEv2/IPsec on gets no CA from a new hostname.
	other := filepath.Join(t.TempDir(), "state")
	if _, _, err := Initialize(other, InitOptions{Hostname: "203.0.113.8", PortFree: free}); err != nil {
		t.Fatal(err)
	}
	again, _, err := Initialize(other, InitOptions{Hostname: "vpn2.example.com", PortFree: free})
	if err != nil || again.State.IPsec.CAPEM != "" || again.State.Hostname != "vpn2.example.com" {
		t.Fatalf("init without IKEv2/IPsec: %v, CA %t, hostname %q", err, again.State.IPsec.CAPEM != "", again.State.Hostname)
	}
}

// A new server runs only Shadowsocks. The other protocols have their keys and their own ports
// already, so turning one on later needs only its switch, but nothing listens for them.
func TestNewServersRunOnlyShadowsocks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, created, err := Initialize(dir, InitOptions{Hostname: "203.0.113.7", PortFree: func(string, uint16) bool { return true }})
	if err != nil || !created {
		t.Fatalf("init: created %v, %v", created, err)
	}
	s := store.State
	if !s.Shadowsocks.Enabled || s.VLESS.Enabled || s.WireGuard.Enabled || s.AmneziaWG.Enabled || s.IPsec.IKEv2Enabled || s.IPsec.IPsecEnabled {
		t.Fatalf("protocols on a new server: shadowsocks %v, vless %v, wireguard %v, amneziawg %v, ikev2 %v, ipsec %v",
			s.Shadowsocks.Enabled, s.VLESS.Enabled, s.WireGuard.Enabled, s.AmneziaWG.Enabled, s.IPsec.IKEv2Enabled, s.IPsec.IPsecEnabled)
	}
	if s.VLESS.PrivateKey == "" || s.VLESS.ShortID == "" || s.WireGuard.PrivateKey == "" || s.AmneziaWG.PrivateKey == "" || s.AmneziaWG.Params.H1 == "" {
		t.Fatal("a protocol that is off has no keys to be turned on with")
	}
	seen := map[uint16]bool{}
	for _, port := range []uint16{s.API.Port, s.Dashboard.Port, s.Shadowsocks.Port, s.VLESS.Port, s.WireGuard.Port, s.AmneziaWG.Port} {
		if port < 10_000 || seen[port] {
			t.Fatalf("ports are not distinct high ports: %d after %v", port, seen)
		}
		seen[port] = true
	}
	if listening := s.Listening(); len(listening) != 3 || listening["api"] == "" || listening["dashboard"] == "" || listening[Shadowsocks] == "" {
		t.Fatalf("a new server listens on %v", listening)
	}
	// The ports of the protocols that are off are kept for them, and the engine accepts the state.
	if err := s.checkReservedPorts(); err != nil {
		t.Fatal(err)
	}
	if err := Check(s); err != nil {
		t.Fatal(err)
	}
}

// An upgrade keeps the protocols each server has on: servers created by older versions have all
// four on, unless their administrator turned some off.
func TestInitKeepsTheProtocolsOfAnExistingServer(t *testing.T) {
	free := func(string, uint16) bool { return true }
	dir := filepath.Join(t.TempDir(), "state")
	state, err := NewState(InitOptions{Hostname: "203.0.113.7", PortFree: free})
	if err != nil {
		t.Fatal(err)
	}
	allProtocolsOn(state)
	state.WireGuard.Enabled = false // turned off by its administrator
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&Store{dir: dir, State: state}).Save(); err != nil {
		t.Fatal(err)
	}
	// serve and setup run init at every start; it gives this server, older than the dashboard, a
	// dashboard port and saves the state.
	if _, created, err := Initialize(dir, InitOptions{PortFree: free}); err != nil || created {
		t.Fatalf("init on an existing server: created %v, %v", created, err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := loaded.State
	if !s.Shadowsocks.Enabled || !s.VLESS.Enabled || s.WireGuard.Enabled || !s.AmneziaWG.Enabled || s.Dashboard.Port == 0 {
		t.Fatalf("after the upgrade: shadowsocks %v, vless %v, wireguard %v, amneziawg %v, dashboard port %d",
			s.Shadowsocks.Enabled, s.VLESS.Enabled, s.WireGuard.Enabled, s.AmneziaWG.Enabled, s.Dashboard.Port)
	}
}
