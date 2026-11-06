// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"software.sslmate.com/src/go-pkcs12"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// --- a strict reader for the XML property lists Apple profiles use ---

func readPlist(t *testing.T, data string) map[string]any {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(data))
	var root any
	for {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("plist: %v", err)
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local != "plist" {
				t.Fatalf("plist: root element %q", start.Name.Local)
			}
			root = readValue(t, decoder, nextStart(t, decoder))
			break
		}
	}
	dict, ok := root.(map[string]any)
	if !ok {
		t.Fatalf("plist root is %T", root)
	}
	return dict
}

func nextStart(t *testing.T, d *xml.Decoder) xml.StartElement {
	t.Helper()
	for {
		token, err := d.Token()
		if err != nil {
			t.Fatalf("plist: %v", err)
		}
		switch v := token.(type) {
		case xml.StartElement:
			return v
		case xml.EndElement:
			return xml.StartElement{} // end of a container
		}
	}
}

func text(t *testing.T, d *xml.Decoder) string {
	t.Helper()
	var b strings.Builder
	for {
		token, err := d.Token()
		if err != nil {
			t.Fatalf("plist: %v", err)
		}
		switch v := token.(type) {
		case xml.CharData:
			b.Write(v)
		case xml.EndElement:
			return b.String()
		case xml.StartElement:
			t.Fatalf("plist: unexpected <%s> in a scalar", v.Name.Local)
		}
	}
}

func readValue(t *testing.T, d *xml.Decoder, start xml.StartElement) any {
	t.Helper()
	switch start.Name.Local {
	case "dict":
		out := map[string]any{}
		for {
			key := nextStart(t, d)
			if key.Name.Local == "" {
				return out
			}
			if key.Name.Local != "key" {
				t.Fatalf("plist: <%s> where a key belongs", key.Name.Local)
			}
			name := text(t, d)
			if _, dup := out[name]; dup {
				t.Fatalf("plist: duplicate key %q", name)
			}
			out[name] = readValue(t, d, nextStart(t, d))
		}
	case "array":
		out := []any{}
		for {
			item := nextStart(t, d)
			if item.Name.Local == "" {
				return out
			}
			out = append(out, readValue(t, d, item))
		}
	case "string":
		return text(t, d)
	case "integer":
		n, err := strconv.ParseInt(text(t, d), 10, 64)
		if err != nil {
			t.Fatalf("plist integer: %v", err)
		}
		return n
	case "data":
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text(t, d)), ""))
		if err != nil {
			t.Fatalf("plist data: %v", err)
		}
		return raw
	case "true", "false":
		_ = d.Skip()
		return start.Name.Local == "true"
	}
	t.Fatalf("plist: unknown element <%s>", start.Name.Local)
	return nil
}

// --- harness ---

// fakeAgent reports a running IPsec component, as the agent's status file would.
func fakeAgent(t *testing.T, s *testServer, sas []ipsecproto.SA) {
	t.Helper()
	dir := filepath.Join(s.store.Dir(), IPsecDir)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if sas == nil {
		sas = []ipsecproto.SA{}
	}
	data, _ := json.Marshal(ipsecproto.Status{Version: 1, UpdatedUnix: time.Now().Unix(), Running: true, SAs: sas, Plugins: []string{"vici"}})
	if err := os.WriteFile(filepath.Join(dir, ipsecproto.StatusFile), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func (s *testServer) raw(t *testing.T, method, path string, body any) (int, string, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	request, _ := http.NewRequest(method, s.base+path, reader)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header.Get("Content-Type"), string(data)
}

func (s *testServer) appleKey(t *testing.T, user userView, body map[string]string) keyView {
	t.Helper()
	var key keyView
	s.must(t, http.StatusCreated, "POST", "/users/"+user.ID+"/keys", body, &key)
	return key
}

func (s *testServer) desired(t *testing.T) ipsecproto.Desired {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.store.Dir(), IPsecDir, ipsecproto.DesiredFile))
	if err != nil {
		t.Fatal(err)
	}
	var d ipsecproto.Desired
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("desired state does not validate: %v", err)
	}
	return d
}

func (s *testServer) stateKey(user, key string) *Key {
	var found *Key
	s.service.Read(func(st *State) {
		for _, k := range st.User(user).Keys {
			if k.ID == key {
				copied := *k
				found = &copied
			}
		}
	})
	return found
}

func payloadOfType(t *testing.T, profile map[string]any, kind string) map[string]any {
	t.Helper()
	for _, p := range profile["PayloadContent"].([]any) {
		if p := p.(map[string]any); p["PayloadType"] == kind {
			return p
		}
	}
	return nil
}

func crlEntries(t *testing.T, s *testServer) map[int64]int {
	t.Helper()
	block, _ := pem.Decode([]byte(s.desired(t).CRL))
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var ca *x509.Certificate
	s.service.Read(func(st *State) { ca, _ = parseCertPEM(st.IPsec.CAPEM) })
	if err := list.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	out := map[int64]int{}
	for _, e := range list.RevokedCertificateEntries {
		out[e.SerialNumber.Int64()] = e.ReasonCode
	}
	return out
}

// --- tests ---

func TestNTHashVectors(t *testing.T) {
	for password, want := range map[string]string{
		"password":   "8846f7eaee8fb117ad06bdd830b7586c",
		"clientPass": "44ebba8d5312b8d611474411f56989ae", // RFC 2759, section 9.2
	} {
		if got := ntHash(password); got != want {
			t.Errorf("ntHash(%q) = %s, want %s", password, got, want)
		}
	}
}

func TestKeyOptionValidation(t *testing.T) {
	for _, c := range []struct {
		protocol string
		options  KeyOptions
		ok       bool
		auth     string
	}{
		{IKEv2, KeyOptions{}, true, AuthEAP},
		{IPsec, KeyOptions{}, true, AuthCertificate},
		{IKEv2, KeyOptions{Auth: AuthPSK}, false, ""},
		{IPsec, KeyOptions{Auth: AuthEAP}, false, ""},
		{IPsec, KeyOptions{Auth: AuthPSK}, true, AuthPSK},
		{IKEv2, KeyOptions{RemoteID: "vpn.example.test", LocalID: "phone@example.test", ServerAddress: "203.0.113.7"}, true, AuthEAP},
		{IKEv2, KeyOptions{RemoteID: "203.0.113.7"}, true, AuthEAP},
		{IKEv2, KeyOptions{LocalID: "203.0.113.7"}, false, ""},
		{IKEv2, KeyOptions{LocalID: "@special"}, false, ""},
		{IKEv2, KeyOptions{LocalID: "a\n}"}, false, ""},
		{IKEv2, KeyOptions{LocalID: "a b"}, false, ""},
		{IKEv2, KeyOptions{ServerAddress: "bad host!"}, false, ""},
		{IPsec, KeyOptions{RemoteID: "vpn.example.test"}, false, ""},
		{Shadowsocks, KeyOptions{Auth: AuthEAP}, false, ""},
		{Shadowsocks, KeyOptions{}, true, ""},
	} {
		got, err := c.options.validate(c.protocol)
		if (err == nil) != c.ok {
			t.Errorf("%s %+v: err = %v, want ok=%v", c.protocol, c.options, err, c.ok)
		}
		if err == nil && got.Auth != c.auth {
			t.Errorf("%s %+v: auth %q, want %q", c.protocol, c.options, got.Auth, c.auth)
		}
	}
}

// Apple profiles for all four methods, the component check, desired state for the agent,
// certificate holds and revocation.
func TestAppleProfilesAndAgentState(t *testing.T) {
	server := newTestServer(t, func(s *State) { s.Name = `Lab <&"'> server` })
	var errBody map[string]string
	status, _, body := server.raw(t, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}})
	_ = json.Unmarshal([]byte(body), &errBody)
	if status != http.StatusBadRequest || !strings.Contains(body, "ipsec enable") {
		t.Fatalf("enabling IKEv2 without the component: %d %s", status, body)
	}
	user := server.user(t, map[string]any{"name": "Alice & <Bob>"})
	if status, _, _ := server.raw(t, "POST", "/users/"+user.ID+"/keys", map[string]string{"protocol": "ikev2"}); status != http.StatusBadRequest {
		t.Fatalf("IKEv2 key while turned off: %d", status)
	}

	fakeAgent(t, server, nil)
	var info serverInfo
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{
		"ikev2": map[string]bool{"enabled": true}, "ipsec": map[string]bool{"enabled": true}}}, &info)
	if !info.Protocols[IKEv2].Enabled || !info.Protocols[IPsec].Enabled || !info.IPsecComponent.Running {
		t.Fatalf("server info after enabling: %+v", info)
	}
	if status, _, _ := server.raw(t, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]any{"port": 1500}}}); status != http.StatusBadRequest {
		t.Fatalf("IKEv2 port change: %d", status)
	}
	var config map[string]any
	server.service.Read(func(s *State) {
		data, _ := s.EngineConfig("off")
		_ = json.Unmarshal(data, &config)
		if ports := s.Listening(); ports["ipsec-ike"] != "udp/500" || ports["ipsec-natt"] != "udp/4500" || ports[ipsecDNSTag] == "" {
			t.Errorf("listening: %v", ports)
		}
	})
	if !strings.Contains(fmt.Sprint(config["inbounds"]), ipsecDNSTag) {
		t.Fatalf("no IPsec DNS inbound: %v", config["inbounds"])
	}

	eap := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	cert := server.appleKey(t, user, map[string]string{"protocol": "ikev2", "auth": "certificate",
		"remote_identifier": "vpn.example.test", "local_identifier": "alice-phone@example.test", "server_address": "vpn.example.test"})
	ipsecCert := server.appleKey(t, user, map[string]string{"protocol": "ipsec"})
	psk := server.appleKey(t, user, map[string]string{"protocol": "ipsec", "auth": "psk"})
	if eap.Auth != AuthEAP || cert.Auth != AuthCertificate || ipsecCert.Auth != AuthCertificate || psk.Auth != AuthPSK {
		t.Fatalf("auth methods: %s %s %s %s", eap.Auth, cert.Auth, ipsecCert.Auth, psk.Auth)
	}
	if psk.Warning == "" || eap.Warning != "" || eap.AccessKey != "" || cert.RemoteID != "vpn.example.test" || cert.Address != "vpn.example.test" {
		t.Fatalf("issued keys: %+v %+v", psk, cert)
	}
	if status, _, _ := server.raw(t, "POST", "/users/"+user.ID+"/keys", map[string]string{"protocol": "ikev2", "local_identifier": "Alice-Phone@example.test"}); status != http.StatusBadRequest {
		t.Fatalf("duplicate local identifier: %d", status)
	}
	if status, _, _ := server.raw(t, "GET", "/users/"+user.ID+"/keys/"+eap.ID+"/qr", nil); status != http.StatusBadRequest {
		t.Fatalf("QR for an IKEv2 key: %d", status)
	}

	var ca, serverCert *x509.Certificate
	var psKey string
	var group string
	server.service.Read(func(s *State) {
		ca, _ = parseCertPEM(s.IPsec.CAPEM)
		serverCert, _ = parseCertPEM(s.IPsec.ServerPEM)
		psKey, group = s.IPsec.PSK, s.IPsec.GroupName
	})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"127.0.0.1", "vpn.example.test"} {
		if _, err := serverCert.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("server certificate for %s: %v", name, err)
		}
	}
	if !slices.ContainsFunc(serverCert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool { return oid.Equal(ikeIntermediate) }) {
		t.Error("server certificate lacks the IKE intermediate EKU macOS needs")
	}

	profileOf := func(key keyView, query string) map[string]any {
		t.Helper()
		status, contentType, body := server.raw(t, "GET", "/users/"+user.ID+"/keys/"+key.ID+"/profile"+query, nil)
		if status != http.StatusOK || contentType != "application/x-apple-aspen-config" {
			t.Fatalf("profile %s: %d %s %s", key.ID, status, contentType, body)
		}
		if !strings.Contains(body, "Lab &lt;&amp;&#34;&#39;&gt; server") && !strings.Contains(body, "Lab &lt;&amp;&quot;&apos;&gt; server") {
			t.Fatalf("server name is not escaped in the profile")
		}
		profile := readPlist(t, body)
		if profile["PayloadType"] != "Configuration" || !strings.Contains(profile["PayloadDisplayName"].(string), `Lab <&"'> server`) {
			t.Fatalf("profile header: %v", profile["PayloadDisplayName"])
		}
		seen := map[string]bool{profile["PayloadUUID"].(string): true}
		for _, p := range profile["PayloadContent"].([]any) {
			uuid := p.(map[string]any)["PayloadUUID"].(string)
			if seen[uuid] {
				t.Fatalf("duplicate PayloadUUID %s", uuid)
			}
			seen[uuid] = true
		}
		root := payloadOfType(t, profile, "com.apple.security.root")
		if root == nil || !bytes.Equal(root["PayloadContent"].([]byte), ca.Raw) {
			t.Fatal("profile does not carry the IPsec CA")
		}
		return profile
	}
	vpnSettings := func(profile map[string]any, kind string) map[string]any {
		t.Helper()
		vpn := payloadOfType(t, profile, "com.apple.vpn.managed")
		if vpn == nil || vpn["VPNType"] != kind {
			t.Fatalf("VPN payload: %v", vpn)
		}
		return vpn[kind].(map[string]any)
	}
	identityOf := func(profile map[string]any, settings map[string]any, wantPassword bool) *x509.Certificate {
		t.Helper()
		p12 := payloadOfType(t, profile, "com.apple.security.pkcs12")
		if p12 == nil || settings["PayloadCertificateUUID"] != p12["PayloadUUID"] {
			t.Fatalf("certificate payload is missing or not referenced")
		}
		password, has := p12["Password"].(string)
		if has != wantPassword {
			t.Fatalf("pkcs12 password embedded = %v, want %v", has, wantPassword)
		}
		if !has {
			return nil
		}
		_, leaf, chain, err := pkcs12.DecodeChain(p12["PayloadContent"].([]byte), password)
		if err != nil {
			t.Fatalf("pkcs12: %v", err)
		}
		if len(chain) != 1 || !chain[0].Equal(ca) {
			t.Fatal("pkcs12 does not include the CA")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("client certificate: %v", err)
		}
		return leaf
	}

	// IKEv2 with username and password (EAP-MSCHAPv2).
	profile := profileOf(eap, "")
	settings := vpnSettings(profile, "IKEv2")
	eapKey := server.stateKey(user.ID, eap.ID)
	if settings["AuthenticationMethod"] != "None" || settings["ExtendedAuthEnabled"] != int64(1) ||
		settings["AuthName"] != eap.Identity || settings["AuthPassword"] != eapKey.Secret ||
		settings["RemoteIdentifier"] != "127.0.0.1" || settings["LocalIdentifier"] != eap.Identity ||
		settings["RemoteAddress"] != "127.0.0.1" || payloadOfType(t, profile, "com.apple.security.pkcs12") != nil {
		t.Fatalf("IKEv2 EAP settings: %v", settings)
	}
	if again := profileOf(eap, ""); again["PayloadUUID"] != profile["PayloadUUID"] {
		t.Fatal("profile UUIDs are not stable, so reinstalling would duplicate the VPN")
	}

	// IKEv2 with a certificate and custom identifiers.
	profile = profileOf(cert, "?on_demand=1")
	settings = vpnSettings(profile, "IKEv2")
	leaf := identityOf(profile, settings, true)
	if settings["AuthenticationMethod"] != "Certificate" || settings["RemoteIdentifier"] != "vpn.example.test" ||
		settings["LocalIdentifier"] != "alice-phone@example.test" || settings["RemoteAddress"] != "vpn.example.test" ||
		settings["OnDemandEnabled"] != int64(1) || settings["ServerCertificateIssuerCommonName"] != ca.Subject.CommonName {
		t.Fatalf("IKEv2 certificate settings: %v", settings)
	}
	if !slices.Contains(leaf.EmailAddresses, "alice-phone@example.test") {
		t.Fatalf("client certificate identities: %v", leaf.EmailAddresses)
	}
	identityOf(profileOf(cert, "?prompt_password=1"), vpnSettings(profileOf(cert, "?prompt_password=1"), "IKEv2"), false)

	// IPsec (IKEv1) with a certificate and XAuth.
	profile = profileOf(ipsecCert, "")
	settings = vpnSettings(profile, "IPSec")
	identityOf(profile, settings, true)
	if settings["AuthenticationMethod"] != "Certificate" || settings["XAuthEnabled"] != int64(1) || settings["XAuthName"] != ipsecCert.Identity {
		t.Fatalf("IPsec certificate settings: %v", settings)
	}

	// IPsec with the group's pre-shared key and XAuth.
	profile = profileOf(psk, "")
	settings = vpnSettings(profile, "IPSec")
	if settings["AuthenticationMethod"] != "SharedSecret" || !bytes.Equal(settings["SharedSecret"].([]byte), []byte(psKey)) ||
		settings["LocalIdentifier"] != group || settings["LocalIdentifierType"] != "KeyID" ||
		settings["XAuthPassword"] != server.stateKey(user.ID, psk.ID).Secret {
		t.Fatalf("IPsec PSK settings: %v", settings)
	}

	// The kit explains profiles instead of showing a key.
	if status, _, kit := server.raw(t, "GET", "/users/"+user.ID+"/kit", nil); status != http.StatusOK || !strings.Contains(kit, ".mobileconfig") {
		t.Fatalf("kit: %d", status)
	}

	// What the agent gets: NT hashes, never EAP passwords; every identity; the PSK.
	raw, _ := os.ReadFile(filepath.Join(server.store.Dir(), IPsecDir, ipsecproto.DesiredFile))
	if strings.Contains(string(raw), eapKey.Secret) {
		t.Fatal("the agent's settings contain an EAP password")
	}
	desired := server.desired(t)
	if desired.IKEv2 == nil || desired.IKEv1 == nil || len(desired.IKEv2.EAP) != 1 || desired.IKEv2.EAP[0].NTHash != ntHash(eapKey.Secret) ||
		!desired.IKEv2.Certificates || desired.IKEv1.PSK != psKey || desired.IKEv1.Group != group || len(desired.IKEv1.XAuth) != 2 {
		t.Fatalf("desired state: %+v %+v", desired.IKEv2, desired.IKEv1)
	}
	for _, id := range []string{eap.Identity, "alice-phone@example.test", ipsecCert.Identity, psk.Identity} {
		if !slices.Contains(desired.Allowed, id) {
			t.Fatalf("%s is not allowed: %v", id, desired.Allowed)
		}
	}
	if desired.Firewall.DNSPort == 0 || len(desired.Firewall.Internal) == 0 || desired.Firewall.ServerIP != "127.0.0.1" {
		t.Fatalf("firewall: %+v", desired.Firewall)
	}

	// Disabling the user drops every identity and holds the certificates.
	certSerial := server.stateKey(user.ID, cert.ID).CertSerial
	server.must(t, http.StatusOK, "PATCH", "/users/"+user.ID, map[string]any{"enabled": false}, nil)
	if d := server.desired(t); len(d.Allowed) != 0 || len(d.IKEv2.EAP) != 0 || len(d.IKEv1.XAuth) != 0 {
		t.Fatalf("disabled user still allowed: %v", d.Allowed)
	}
	if reason, held := crlEntries(t, server)[certSerial]; !held || reason != crlHold {
		t.Fatalf("certificate of a disabled user is not on hold: %v", crlEntries(t, server))
	}
	server.must(t, http.StatusOK, "PATCH", "/users/"+user.ID, map[string]any{"enabled": true}, nil)
	if _, held := crlEntries(t, server)[certSerial]; held {
		t.Fatal("hold not lifted after enabling the user")
	}

	// Removing the key revokes its certificate for good.
	server.must(t, http.StatusNoContent, "DELETE", "/users/"+user.ID+"/keys/"+cert.ID, nil, nil)
	if reason, revoked := crlEntries(t, server)[certSerial]; !revoked || reason != 0 {
		t.Fatalf("removed key's certificate is not revoked: %v", crlEntries(t, server))
	}
	if slices.Contains(server.desired(t).Allowed, "alice-phone@example.test") {
		t.Fatal("removed key is still allowed")
	}

	// Rotating the PSK changes it for the agent.
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"rotate_ipsec_psk": true}, nil)
	if d := server.desired(t); d.IKEv1.PSK == psKey || len(d.IKEv1.PSK) < 32 {
		t.Fatal("PSK was not rotated")
	}
}

// The agent's per-SA byte counters become user traffic, and rekeys are not double counted.
func TestIPsecTrafficAccounting(t *testing.T) {
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	user := server.user(t, map[string]any{"name": "Phone", "data_limit_bytes": 5000})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	report := func(in, out uint64, child string) {
		fakeAgent(t, server, []ipsecproto.SA{{Name: "gl-ikev2-eap", UniqueID: "7", Version: 2, Identity: strings.ToUpper(key.Identity),
			Remote: "198.51.100.20", Children: []ipsecproto.Child{{UniqueID: child, BytesIn: in, BytesOut: out}}}})
		server.service.recordIPsec(time.Now())
	}
	report(1000, 2000, "1")
	report(1500, 2500, "1") // +500 up, +500 down
	report(100, 0, "2")     // a rekeyed child starts from zero
	if err := server.service.Account(); err != nil {
		t.Fatal(err)
	}
	var got userView
	server.must(t, http.StatusOK, "GET", "/users/"+user.ID, nil, &got)
	if got.UsageBytes != 4100 {
		t.Fatalf("usage = %d, want 4100", got.UsageBytes)
	}
	var clients struct{ Clients []clientView }
	server.must(t, http.StatusOK, "GET", "/clients?user="+user.ID, nil, &clients)
	if len(clients.Clients) == 0 || clients.Clients[0].IP != "198.51.100.20" || clients.Clients[0].Protocol != IKEv2 {
		t.Fatalf("client log: %+v", clients)
	}
	// A session that ends between reports is counted from its final counters, once.
	closed := func(child string, in uint64) {
		data, _ := json.Marshal(ipsecproto.Status{Version: 1, UpdatedUnix: time.Now().Unix(), Running: true, SAs: []ipsecproto.SA{},
			Closed: []ipsecproto.SA{{Name: "gl-ikev2-eap", UniqueID: "8", Version: 2, Identity: key.Identity, Remote: "198.51.100.20",
				Children: []ipsecproto.Child{{UniqueID: child, BytesIn: in}}}}})
		_ = os.WriteFile(filepath.Join(server.store.Dir(), IPsecDir, ipsecproto.StatusFile), data, 0o640)
		server.service.recordIPsec(time.Now())
	}
	closed("2", 150) // child 2 was last seen at 100: +50
	closed("2", 150) // the same closed child again: +0
	closed("9", 30)  // never seen live: +30
	if err := server.service.Account(); err != nil {
		t.Fatal(err)
	}
	server.must(t, http.StatusOK, "GET", "/users/"+user.ID, nil, &got)
	if got.UsageBytes != 4180 {
		t.Fatalf("usage after closed sessions = %d, want 4180", got.UsageBytes)
	}
	report(1000, 0, "10") // +1000: over the 5000 byte limit
	if err := server.service.Account(); err != nil {
		t.Fatal(err)
	}
	if d := server.desired(t); len(d.Allowed) != 0 {
		t.Fatalf("over-limit user is still allowed: %v", d.Allowed)
	}

	// A stale status means the component is not running.
	dir := filepath.Join(server.store.Dir(), IPsecDir)
	data, _ := json.Marshal(ipsecproto.Status{Version: 1, UpdatedUnix: time.Now().Add(-time.Minute).Unix(), Running: true})
	_ = os.WriteFile(filepath.Join(dir, ipsecproto.StatusFile), data, 0o640)
	if _, running := server.service.IPsecStatus(time.Now()); running {
		t.Fatal("a minute-old status counts as running")
	}
}

// The IPsec DNS listener answers only the pools, through the server's DNS rules.
func TestIPsecDNSListener(t *testing.T) {
	previous := ipsecDNSSources
	ipsecDNSSources = append(append([]string{}, previous...), "127.0.0.1/32")
	defer func() { ipsecDNSSources = previous }()
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PUT", "/rules", map[string]any{"blocked_domains": []string{"blocked.example"}}, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	var port uint16
	server.service.Read(func(s *State) { port = s.IPsec.DNSPort })

	query := func() (dnsmessage.RCode, error) {
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, RecursionDesired: true})
		_ = builder.StartQuestions()
		_ = builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("www.blocked.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		packet, _ := builder.Finish()
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := conn.Write(packet); err != nil {
			return 0, err
		}
		reply := make([]byte, 1500)
		n, err := conn.Read(reply)
		if err != nil {
			return 0, err
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(reply[:n])
		return header.RCode, err
	}
	var code dnsmessage.RCode
	var err error
	for i := 0; i < 10; i++ {
		if code, err = query(); err == nil {
			break
		}
	}
	if err != nil || code != dnsmessage.RCodeNameError {
		t.Fatalf("blocked name through the IPsec DNS: %v %v", code, err)
	}

	// Other sources get nothing (a rule change reloads the engine without loopback).
	ipsecDNSSources = previous
	server.must(t, http.StatusOK, "PUT", "/rules", map[string]any{"blocked_domains": []string{"blocked.example", "other.example"}}, nil)
	if code, err := query(); err == nil {
		t.Fatalf("a source outside the pools got a DNS answer (%v)", code)
	}
}
