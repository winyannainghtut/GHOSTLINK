// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package ipsecagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

func pemOf(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

// fixture is a complete, valid desired state with all four methods.
func fixture(t *testing.T) ipsecproto.Desired {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "vpn.example.test"},
		DNSNames: []string{"vpn.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, ca, &serverKey.PublicKey, caKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	d := ipsecproto.Desired{
		Version: ipsecproto.Version, Generation: 7,
		CA: pemOf("CERTIFICATE", caDER), Server: pemOf("CERTIFICATE", serverDER), ServerKey: pemOf("PRIVATE KEY", keyDER), CRL: pemOf("X509 CRL", crlDER),
		ServerID: "vpn.example.test",
		IKEv2: &ipsecproto.IKEv2{Pool: "10.79.0.0/20", Gateway: "10.79.0.1", Certificates: true,
			EAP: []ipsecproto.NTLMSecret{{ID: "alice-2@ghostlink", NTHash: "8846f7eaee8fb117ad06bdd830b7586c"}}},
		IKEv1: &ipsecproto.IKEv1{Pool: "10.80.0.0/20", Gateway: "10.80.0.1", Group: "ghostlink", PSK: strings.Repeat("k", 43),
			XAuth: []ipsecproto.XAuthSecret{{ID: "bob-3@ghostlink", Password: "xauth-password"}}, Certificates: true},
		Firewall: ipsecproto.Firewall{Internal: []string{"10.0.0.0/8", "fc00::/7"}, Blocked: []string{"203.0.113.0/24", "2001:db8::/32"},
			Ports: []string{"6881-6889", "8080"}, BlockSMTP: true, ServerIP: "198.51.100.1", DNSPort: 40123},
		Allowed: []string{"alice-2@ghostlink", "bob-3@ghostlink"},
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return d
}

func TestRenderSwanctl(t *testing.T) {
	d := fixture(t)
	files, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	conf := files["swanctl.conf"]
	for _, want := range []string{
		ConnIKEv2Cert + " {", ConnIKEv2EAP + " {", ConnIKEv1Cert + " {", ConnIKEv1PSK + " {",
		"auth = eap-mschapv2", "auth = xauth-generic", "aggressive = yes", "id = keyid:ghostlink",
		"addrs = 10.79.0.2-10.79.15.254", "addrs = 10.80.0.2-10.80.15.254", "dns = 10.79.0.1",
		"secret = 0x8846f7eaee8fb117ad06bdd830b7586c", "encap = yes", "proposals = " + ikev2Proposals,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("swanctl.conf lacks %q", want)
		}
	}
	if strings.Contains(conf, "xauth-password") || strings.Contains(conf, d.IKEv1.PSK) {
		t.Error("secrets are written in plain text instead of 0s base64")
	}
	if strings.Count(conf, "{") != strings.Count(conf, "}") {
		t.Error("unbalanced sections")
	}
	for _, name := range []string{"x509ca/ghostlink-ca.pem", "x509/server.pem", "pkcs8/server.pem", "x509crl/ghostlink.crl"} {
		if files[name] == "" {
			t.Errorf("missing %s", name)
		}
	}

	// Without a PSK there is no Aggressive Mode connection and no group secret.
	d.IKEv1.PSK, d.IKEv1.Group = "", ""
	files, _ = Render(d)
	if strings.Contains(files["swanctl.conf"], ConnIKEv1PSK) || strings.Contains(files["swanctl.conf"], "ike-group") {
		t.Error("PSK connection rendered without a PSK")
	}
	if StrongswanConf(false) == StrongswanConf(true) || strings.Contains(StrongswanConf(false), "aggressive_mode_psk") {
		t.Error("aggressive mode is allowed without a PSK")
	}

	// Nothing enabled: an empty configuration that unloads everything.
	files, _ = Render(ipsecproto.Desired{Version: 1})
	if strings.Contains(files["swanctl.conf"], "gl-") || len(files) != 1 {
		t.Errorf("empty desired state rendered %v", files)
	}
}

func TestFirewallRules(t *testing.T) {
	rules := Rules(fixture(t))
	filter, nat, mangle := rules["filter"], rules["nat"], rules["mangle"]
	for _, want := range []string{
		"-A GHOSTLINK-IPSEC-FWD -s 10.79.0.0/20 -j GHOSTLINK-IPSEC-OUT",
		"-A GHOSTLINK-IPSEC-OUT -m policy --dir in --pol none -j DROP",
		"-A GHOSTLINK-IPSEC-OUT -d 10.0.0.0/8 -j DROP",
		"-A GHOSTLINK-IPSEC-OUT -d 198.51.100.1/32 -j DROP",
		"-A GHOSTLINK-IPSEC-OUT -d 203.0.113.0/24 -j REJECT",
		"-A GHOSTLINK-IPSEC-OUT -p udp --dport 6881:6889 -j REJECT",
		"-A GHOSTLINK-IPSEC-OUT -p tcp --dport 25 -j REJECT",
		"-A GHOSTLINK-IPSEC-IN -s 10.80.0.0/20 -d 10.80.0.1/32 -p udp --dport 40123 -m policy --dir in --pol ipsec -j ACCEPT",
		"-A GHOSTLINK-IPSEC-IN -s 10.80.0.0/20 -j DROP",
	} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter lacks %q", want)
		}
	}
	if strings.Contains(filter, "fc00::") || strings.Contains(filter, "2001:db8") {
		t.Error("IPv6 ranges leaked into iptables rules")
	}
	if !strings.HasSuffix(filter, "-A GHOSTLINK-IPSEC-OUT -j ACCEPT\nCOMMIT\n") {
		t.Error("the final accept must come after every block")
	}
	for _, want := range []string{
		"-A GHOSTLINK-IPSEC-PRE -s 10.79.0.0/20 -p udp --dport 53 -m policy --dir in --pol ipsec -j DNAT --to-destination 10.79.0.1:40123",
		"-A GHOSTLINK-IPSEC-POST -s 10.80.0.0/20 -m policy --dir out --pol none -j MASQUERADE",
	} {
		if !strings.Contains(nat, want) {
			t.Errorf("nat lacks %q", want)
		}
	}
	if !strings.Contains(mangle, "TCPMSS --set-mss 1360") || !strings.HasPrefix(mangle, "*mangle\n:GHOSTLINK-IPSEC-MSS - [0:0]\n") {
		t.Errorf("mangle: %s", mangle)
	}
}

func TestPoolRange(t *testing.T) {
	for _, c := range [][3]string{
		{"10.79.0.0/20", "10.79.0.1", "10.79.0.2-10.79.15.254"},
		{"10.80.0.0/24", "10.80.0.1", "10.80.0.2-10.80.0.254"},
	} {
		if got, err := poolRange(c[0], c[1]); err != nil || got != c[2] {
			t.Errorf("poolRange(%s) = %s %v, want %s", c[0], got, err, c[2])
		}
	}
	if _, err := poolRange("10.79.0.0/20", "10.1.0.1"); err == nil {
		t.Error("a gateway outside the pool was accepted")
	}
}

func TestValidateRefusesUnsafeSettings(t *testing.T) {
	for name, mutate := range map[string]func(*ipsecproto.Desired){
		"identity with newline": func(d *ipsecproto.Desired) { d.Allowed = append(d.Allowed, "a\n}") },
		"identity with brace":   func(d *ipsecproto.Desired) { d.IKEv2.EAP[0].ID = "x} secrets {" },
		"identity as @ form":    func(d *ipsecproto.Desired) { d.IKEv1.XAuth[0].ID = "@#00ff" },
		"short hash":            func(d *ipsecproto.Desired) { d.IKEv2.EAP[0].NTHash = "abcd" },
		"password with newline": func(d *ipsecproto.Desired) { d.IKEv1.XAuth[0].Password = "a\nb" },
		"short psk":             func(d *ipsecproto.Desired) { d.IKEv1.PSK = "short" },
		"pool too big":          func(d *ipsecproto.Desired) { d.IKEv2.Pool = "10.0.0.0/8" },
		"gateway not first":     func(d *ipsecproto.Desired) { d.IKEv2.Gateway = "10.79.0.9" },
		"bad cidr":              func(d *ipsecproto.Desired) { d.Firewall.Blocked = []string{"1.2.3.4/33"} },
		"cidr injection":        func(d *ipsecproto.Desired) { d.Firewall.Internal = []string{"10.0.0.0/8 -j ACCEPT"} },
		"bad port":              func(d *ipsecproto.Desired) { d.Firewall.Ports = []string{"25 -j ACCEPT"} },
		"low dns port":          func(d *ipsecproto.Desired) { d.Firewall.DNSPort = 53 },
		"server key not pem":    func(d *ipsecproto.Desired) { d.ServerKey = "secret" },
		"ca is not a ca":        func(d *ipsecproto.Desired) { d.CA = d.Server },
		"unknown version":       func(d *ipsecproto.Desired) { d.Version = 2 },
		"server id with spaces": func(d *ipsecproto.Desired) { d.ServerID = "a b" },
	} {
		d := fixture(t)
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseSAsAndEnforcement(t *testing.T) {
	sa := func(state, version, eap, xauth, remote string, children map[string][2]string) *vici.Message {
		m := vici.NewMessage()
		_ = m.Set("uniqueid", "5")
		_ = m.Set("version", version)
		_ = m.Set("state", state)
		_ = m.Set("remote-host", "198.51.100.20")
		_ = m.Set("remote-id", remote)
		if eap != "" {
			_ = m.Set("remote-eap-id", eap)
		}
		if xauth != "" {
			_ = m.Set("remote-xauth-id", xauth)
		}
		_ = m.Set("established", "42")
		_ = m.Set("remote-vips", []string{"10.79.0.2"})
		list := vici.NewMessage()
		for name, bytes := range children {
			c := vici.NewMessage()
			_ = c.Set("uniqueid", name)
			_ = c.Set("bytes-in", bytes[0])
			_ = c.Set("bytes-out", bytes[1])
			_ = list.Set("gl-"+name, c)
		}
		_ = m.Set("child-sas", list)
		return m
	}
	event := func(name string, m *vici.Message) *vici.Message {
		e := vici.NewMessage()
		_ = e.Set(name, m)
		return e
	}
	sas := ParseSAs([]*vici.Message{
		event(ConnIKEv2EAP, sa("ESTABLISHED", "2", "Alice-2@ghostlink", "", "alice-2@ghostlink", map[string][2]string{"9": {"100", "200"}})),
		event(ConnIKEv1PSK, sa("ESTABLISHED", "1", "", "bob-3@ghostlink", "ghostlink", nil)),
		event(ConnIKEv1PSK, sa("CONNECTING", "1", "", "", "ghostlink", nil)),
	})
	if len(sas) != 2 {
		t.Fatalf("parsed %d SAs, want the 2 established ones", len(sas))
	}
	if sas[0].Identity != "Alice-2@ghostlink" || sas[0].Version != 2 || sas[0].VirtualIP != "10.79.0.2" ||
		len(sas[0].Children) != 1 || sas[0].Children[0].BytesIn != 100 || sas[0].Children[0].BytesOut != 200 || sas[0].Established != 42 {
		t.Fatalf("IKEv2 SA: %+v", sas[0])
	}
	if sas[1].Identity != "bob-3@ghostlink" {
		t.Fatalf("an IPsec PSK user is identified by XAuth, got %q", sas[1].Identity)
	}
	// Down and rekey events report the CHILD_SAs that ended; up events report nothing.
	down := event(ConnIKEv2EAP, sa("ESTABLISHED", "2", "alice-2@ghostlink", "", "alice-2@ghostlink", map[string][2]string{"9": {"500", "700"}}))
	_ = down.Set("up", "no")
	if closed := ClosedChildren(down); len(closed) != 1 || closed[0].Children[0].BytesOut != 700 || closed[0].Identity != "alice-2@ghostlink" {
		t.Fatalf("child-updown: %+v", closed)
	}
	upEvent := event(ConnIKEv2EAP, sa("ESTABLISHED", "2", "alice-2@ghostlink", "", "alice-2@ghostlink", map[string][2]string{"9": {"1", "1"}}))
	_ = upEvent.Set("up", "yes")
	if closed := ClosedChildren(upEvent); len(closed) != 0 {
		t.Fatalf("an up event reported closed children: %+v", closed)
	}
	rekeyed := sa("ESTABLISHED", "2", "alice-2@ghostlink", "", "alice-2@ghostlink", nil)
	old, fresh, pair, list := vici.NewMessage(), vici.NewMessage(), vici.NewMessage(), vici.NewMessage()
	_ = old.Set("uniqueid", "9")
	_ = old.Set("bytes-in", "800")
	_ = old.Set("bytes-out", "900")
	_ = fresh.Set("uniqueid", "10")
	_ = pair.Set("old", old)
	_ = pair.Set("new", fresh)
	_ = list.Set("gl-ikev2-9", pair)
	_ = rekeyed.Set("child-sas", list)
	if closed := ClosedChildren(event(ConnIKEv2EAP, rekeyed)); len(closed) != 1 || closed[0].Children[0].UniqueID != "9" || closed[0].Children[0].BytesIn != 800 {
		t.Fatalf("child-rekey: %+v", closed)
	}
	conns := map[string]bool{ConnIKEv2EAP: true, ConnIKEv1PSK: true}
	if ended := Disallowed(sas, map[string]bool{"alice-2@ghostlink": true, "bob-3@ghostlink": true}, conns); len(ended) != 0 {
		t.Fatalf("allowed SAs ended: %v", ended)
	}
	if ended := Disallowed(sas, map[string]bool{"alice-2@ghostlink": true}, conns); len(ended) != 1 {
		t.Fatalf("removed identity kept: %v", ended)
	}
	if ended := Disallowed(sas, map[string]bool{"alice-2@ghostlink": true, "bob-3@ghostlink": true}, map[string]bool{ConnIKEv2EAP: true}); len(ended) != 1 {
		t.Fatalf("SA of an unloaded connection kept: %v", ended)
	}
}
