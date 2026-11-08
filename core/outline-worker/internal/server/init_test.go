// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto/x509"
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
