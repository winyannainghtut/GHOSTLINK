// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package ipsecagent applies the Ghostlink server's IPsec configuration to strongSwan and the
// host firewall. It runs as root in its own container; everything it applies comes from a
// validated ipsecproto.Desired, and the algorithms are fixed here.
package ipsecagent

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// Connection names; status and enforcement use them to tell the four methods apart.
const (
	ConnIKEv2Cert = "gl-ikev2-cert"
	ConnIKEv2EAP  = "gl-ikev2-eap"
	ConnIKEv1Cert = "gl-ikev1-cert"
	ConnIKEv1PSK  = "gl-ikev1-psk"
)

// Proposals match what Ghostlink's Apple profiles ask for (AES-256-GCM, SHA2-256, DH 19 for
// IKEv2), with fallbacks Apple devices offer when a profile is edited.
const (
	ikev2Proposals = "aes256gcm16-prfsha256-ecp256,aes256-sha256-ecp256,aes256-sha256-modp2048"
	ikev2ESP       = "aes256gcm16-ecp256,aes256gcm16,aes256-sha256-ecp256,aes256-sha256"
	ikev1Proposals = "aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048"
	ikev1ESP       = "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1"
)

// Files are the swanctl directory's contents, by path relative to it.
type Files map[string]string

// conf writes strongSwan's nested "name { key = value }" syntax. Every value is either fixed
// here or checked by Desired.Validate (identities, ranges, hex and base64), so none needs quoting.
type conf struct {
	b     strings.Builder
	depth int
}

func (c *conf) open(name string) {
	c.b.WriteString(strings.Repeat("  ", c.depth) + name + " {\n")
	c.depth++
}

func (c *conf) close() {
	c.depth--
	c.b.WriteString(strings.Repeat("  ", c.depth) + "}\n")
}

func (c *conf) set(key, value string) {
	c.b.WriteString(strings.Repeat("  ", c.depth) + key + " = " + value + "\n")
}

// poolRange is the pool without its network, gateway and broadcast addresses.
func poolRange(pool, gateway string) (string, error) {
	prefix, err := netip.ParsePrefix(pool)
	if err != nil {
		return "", err
	}
	gw, err := netip.ParseAddr(gateway)
	if err != nil {
		return "", err
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || !prefix.Contains(gw) {
		return "", fmt.Errorf("gateway %s is not in pool %s", gateway, pool)
	}
	// Validate keeps the gateway first in the pool, so leases start after it.
	first := prefix.Addr().Next()
	if first == gw {
		first = gw.Next()
	}
	raw := prefix.Addr().As4()
	n := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3]) | (uint32(1)<<(32-prefix.Bits()) - 1)
	last := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}).Prev()
	return first.String() + "-" + last.String(), nil
}

func secret(text string) string { return "0s" + base64.StdEncoding.EncodeToString([]byte(text)) }

// Render builds swanctl.conf and the credential files for a validated Desired.
func Render(d ipsecproto.Desired) (Files, error) {
	files := Files{}
	var c conf
	c.b.WriteString("# Written by ghostlink-ipsec-agent from the Ghostlink server's settings; do not edit.\n")
	c.open("connections")
	child := func(name, esp string, ikev1 bool) {
		c.open("children")
		c.open(name)
		c.set("local_ts", "0.0.0.0/0")
		c.set("esp_proposals", esp)
		c.set("dpd_action", "clear")
		if ikev1 {
			// Apple's IKEv1 client rekeys itself; a rekey started here would need a new XAuth.
			c.set("rekey_time", "0s")
		}
		c.close()
		c.close()
	}
	common := func(version, pool, proposals string) {
		c.set("version", version)
		c.set("proposals", proposals)
		c.set("pools", pool)
		c.set("send_cert", "always")
		// Always UDP-encapsulate (port 4500), so firewalls only need UDP 500 and 4500.
		c.set("encap", "yes")
		c.set("dpd_delay", "30s")
	}
	local := func(auth, id string) {
		c.open("local")
		c.set("auth", auth)
		if auth == "pubkey" {
			c.set("certs", "server.pem")
		}
		if id != "" {
			c.set("id", id)
		}
		c.close()
	}
	if v := d.IKEv2; v != nil {
		// The requested remote identifier is answered when the certificate carries it.
		c.open(ConnIKEv2Cert)
		common("2", "gl-ikev2", ikev2Proposals)
		c.set("unique", "replace")
		local("pubkey", "%any")
		c.open("remote")
		c.set("auth", "pubkey")
		c.set("cacerts", "ghostlink-ca.pem")
		c.set("revocation", "relaxed")
		c.close()
		child("gl-ikev2", ikev2ESP, false)
		c.close()

		c.open(ConnIKEv2EAP)
		common("2", "gl-ikev2", ikev2Proposals)
		c.set("unique", "replace")
		local("pubkey", "%any")
		c.open("remote")
		c.set("auth", "eap-mschapv2")
		c.set("eap_id", "%any")
		c.close()
		child("gl-ikev2", ikev2ESP, false)
		c.close()
	}
	if v := d.IKEv1; v != nil {
		c.open(ConnIKEv1Cert)
		common("1", "gl-ikev1", ikev1Proposals)
		c.set("rekey_time", "0s")
		c.set("unique", "replace")
		local("pubkey", d.ServerID)
		c.open("remote")
		c.set("auth", "pubkey")
		c.set("cacerts", "ghostlink-ca.pem")
		c.set("revocation", "relaxed")
		c.close()
		c.open("remote-xauth")
		c.set("auth", "xauth-generic")
		c.close()
		child("gl-ikev1", ikev1ESP, true)
		c.close()

		if v.PSK != "" {
			// Apple's "IPsec" with a group name and shared secret uses Aggressive Mode.
			c.open(ConnIKEv1PSK)
			common("1", "gl-ikev1", ikev1Proposals)
			c.set("aggressive", "yes")
			c.set("rekey_time", "0s")
			c.set("unique", "never")
			local("psk", "")
			c.open("remote")
			c.set("auth", "psk")
			c.set("id", "keyid:"+v.Group)
			c.close()
			c.open("remote-xauth")
			c.set("auth", "xauth-generic")
			c.close()
			child("gl-ikev1", ikev1ESP, true)
			c.close()
		}
	}
	c.close()

	c.open("pools")
	if v := d.IKEv2; v != nil {
		addrs, err := poolRange(v.Pool, v.Gateway)
		if err != nil {
			return nil, err
		}
		c.open("gl-ikev2")
		c.set("addrs", addrs)
		c.set("dns", v.Gateway)
		c.close()
	}
	if v := d.IKEv1; v != nil {
		addrs, err := poolRange(v.Pool, v.Gateway)
		if err != nil {
			return nil, err
		}
		c.open("gl-ikev1")
		c.set("addrs", addrs)
		c.set("dns", v.Gateway)
		c.close()
	}
	c.close()

	c.open("secrets")
	if v := d.IKEv2; v != nil {
		eap := append([]ipsecproto.NTLMSecret{}, v.EAP...)
		sort.Slice(eap, func(i, j int) bool { return eap[i].ID < eap[j].ID })
		for i, s := range eap {
			c.open(fmt.Sprintf("ntlm-%d", i+1))
			c.set("id", s.ID)
			c.set("secret", "0x"+strings.ToLower(s.NTHash))
			c.close()
		}
	}
	if v := d.IKEv1; v != nil {
		xauth := append([]ipsecproto.XAuthSecret{}, v.XAuth...)
		sort.Slice(xauth, func(i, j int) bool { return xauth[i].ID < xauth[j].ID })
		for i, s := range xauth {
			c.open(fmt.Sprintf("xauth-%d", i+1))
			c.set("id", s.ID)
			c.set("secret", secret(s.Password))
			c.close()
		}
		if v.PSK != "" {
			c.open("ike-group")
			c.set("id", "keyid:"+v.Group)
			c.set("secret", secret(v.PSK))
			c.close()
		}
	}
	c.close()
	files["swanctl.conf"] = c.b.String()
	if d.IKEv2 != nil || d.IKEv1 != nil {
		files["x509ca/ghostlink-ca.pem"] = d.CA
		files["x509/server.pem"] = d.Server
		files["pkcs8/server.pem"] = d.ServerKey
		files["x509crl/ghostlink.crl"] = d.CRL
	}
	return files, nil
}

// requiredPlugins must be loaded for every method to work.
var requiredPlugins = []string{
	"openssl", "pem", "pkcs1", "pkcs8", "x509", "revocation", "pubkey", "kernel-netlink",
	"socket-default", "vici", "eap-identity", "eap-mschapv2", "xauth-generic",
}

// StrongswanConf is charon's configuration. aggressivePSK allows IKEv1 Aggressive Mode with a
// pre-shared key, which Apple's IPsec needs and strongSwan refuses unless told otherwise.
func StrongswanConf(aggressivePSK bool) string {
	var c conf
	c.b.WriteString("# Written by ghostlink-ipsec-agent; do not edit.\n")
	c.open("charon")
	// The container already runs with only the capabilities charon needs.
	c.set("user", "root")
	c.set("group", "root")
	c.set("port", "500")
	c.set("port_nat_t", "4500")
	c.set("install_virtual_ip", "no")
	c.set("cisco_unity", "no")
	if aggressivePSK {
		c.set("i_dont_care_about_security_and_use_aggressive_mode_psk", "yes")
	}
	load := []string{"random", "nonce", "kdf", "gmp", "attr", "constraints"}
	for _, p := range requiredPlugins {
		load = append(load, "!"+p)
	}
	c.set("load", strings.Join(load, " "))
	c.open("plugins")
	c.open("openssl")
	// MD4 and DES for EAP-MSCHAPv2 live in OpenSSL 3's legacy provider.
	c.set("load_legacy", "yes")
	c.close()
	c.close()
	c.open("filelog")
	c.open("stderr")
	c.set("default", "0")
	c.set("ike", "1")
	c.set("cfg", "1")
	c.set("knl", "1")
	c.set("ike_name", "yes")
	c.close()
	c.close()
	c.close()
	return c.b.String()
}
