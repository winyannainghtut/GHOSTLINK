// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// --- a minimal, deterministic property-list writer ---

type plistValue interface{ write(b *strings.Builder) }

type plistDict []plistEntry
type plistEntry struct {
	key   string
	value plistValue
}
type plistString string
type plistInt int64
type plistBool bool
type plistData []byte
type plistArray []plistValue

func escapeXML(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (d plistDict) write(b *strings.Builder) {
	b.WriteString("<dict>")
	for _, e := range d {
		b.WriteString("<key>" + escapeXML(e.key) + "</key>")
		e.value.write(b)
	}
	b.WriteString("</dict>")
}
func (s plistString) write(b *strings.Builder) {
	b.WriteString("<string>" + escapeXML(string(s)) + "</string>")
}
func (i plistInt) write(b *strings.Builder) { fmt.Fprintf(b, "<integer>%d</integer>", int64(i)) }
func (v plistBool) write(b *strings.Builder) {
	if v {
		b.WriteString("<true/>")
	} else {
		b.WriteString("<false/>")
	}
}
func (d plistData) write(b *strings.Builder) {
	b.WriteString("<data>" + base64.StdEncoding.EncodeToString(d) + "</data>")
}
func (a plistArray) write(b *strings.Builder) {
	b.WriteString("<array>")
	for _, v := range a {
		v.write(b)
	}
	b.WriteString("</array>")
}

func plistDocument(root plistDict) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">`)
	root.write(&b)
	b.WriteString("</plist>\n")
	return b.String()
}

// --- profiles ---

// ProfileOptions adjusts a generated profile.
type ProfileOptions struct {
	// PromptPassword leaves the certificate password out, so iOS asks for it on install.
	PromptPassword bool
	// OnDemand makes the device reconnect the VPN automatically.
	OnDemand bool
}

var errNotApple = errors.New("only IKEv2 and IPsec keys have an Apple profile")

func (k *Key) isApple() bool { return k.Protocol == IKEv2 || k.Protocol == IPsec }

// AppleProfile renders an Apple configuration profile (.mobileconfig) for an IKEv2 or IPsec key,
// using the built-in NEVPNProtocolIKEv2 / NEVPNProtocolIPSec. It carries the server's CA so the
// self-signed server certificate is trusted for this VPN only.
func (s *State) AppleProfile(user *User, key *Key, options ProfileOptions) (string, error) {
	if !key.isApple() {
		return "", errNotApple
	}
	ca, err := parseCertPEM(s.IPsec.CAPEM)
	if err != nil {
		return "", errors.New("the IPsec component has not been set up yet")
	}
	server, err := parseCertPEM(s.IPsec.ServerPEM)
	if err != nil {
		return "", errors.New("the IPsec component has not been set up yet")
	}
	id := func(part string) string { return stableUUID(s.IPsec.CAPEM, key.ID, part) }
	prefix := "org.ghostlink." + identityLabel(strings.ToLower(s.Name)) + "." + key.ID
	identity := key.localIdentity(user)
	address := key.ServerAddress
	if address == "" {
		address = s.Hostname
	}
	remoteID := key.RemoteID
	if remoteID == "" {
		remoteID = s.serverIdentity()
	}
	caDER, _ := pem.Decode([]byte(s.IPsec.CAPEM))
	payloads := plistArray{plistDict{
		{"PayloadType", plistString("com.apple.security.root")},
		{"PayloadVersion", plistInt(1)},
		{"PayloadIdentifier", plistString(prefix + ".ca")},
		{"PayloadUUID", plistString(id("ca"))},
		{"PayloadDisplayName", plistString(s.ipsecCAName())},
		{"PayloadCertificateFileName", plistString("ghostlink-ca.cer")},
		{"PayloadContent", plistData(caDER.Bytes)},
	}}
	certUUID := id("identity")
	if key.Auth == AuthCertificate {
		bundle, err := s.clientP12(key)
		if err != nil {
			return "", err
		}
		identityPayload := plistDict{
			{"PayloadType", plistString("com.apple.security.pkcs12")},
			{"PayloadVersion", plistInt(1)},
			{"PayloadIdentifier", plistString(prefix + ".identity")},
			{"PayloadUUID", plistString(certUUID)},
			{"PayloadDisplayName", plistString(identity)},
			{"PayloadCertificateFileName", plistString(identityLabel(user.Name) + ".p12")},
			{"PayloadContent", plistData(bundle)},
		}
		if !options.PromptPassword {
			identityPayload = append(identityPayload, plistEntry{"Password", plistString(key.P12Password)})
		}
		payloads = append(payloads, identityPayload)
	}

	var vpnType string
	var settings plistDict
	switch key.Protocol {
	case IKEv2:
		vpnType = "IKEv2"
		sa := func(minutes int64) plistDict {
			return plistDict{
				{"EncryptionAlgorithm", plistString("AES-256-GCM")},
				{"IntegrityAlgorithm", plistString("SHA2-256")},
				{"DiffieHellmanGroup", plistInt(19)},
				{"LifeTimeInMinutes", plistInt(minutes)},
			}
		}
		settings = plistDict{
			{"RemoteAddress", plistString(address)},
			{"RemoteIdentifier", plistString(remoteID)},
			{"LocalIdentifier", plistString(identity)},
			{"ServerCertificateIssuerCommonName", plistString(ca.Subject.CommonName)},
			{"ServerCertificateCommonName", plistString(server.Subject.CommonName)},
			{"CertificateType", plistString("RSA")},
			{"EnablePFS", plistInt(1)},
			{"DeadPeerDetectionRate", plistString("Medium")},
			{"DisableMOBIKE", plistInt(0)},
			{"DisableRedirect", plistInt(0)},
			{"EnableCertificateRevocationCheck", plistInt(0)},
			{"NATKeepAliveInterval", plistInt(20)},
			{"NATKeepAliveOffloadEnable", plistInt(1)},
			{"UseConfigurationAttributeInternalIPSubnet", plistInt(0)},
			{"IKESecurityAssociationParameters", sa(1440)},
			{"ChildSecurityAssociationParameters", sa(480)},
		}
		if key.Auth == AuthCertificate {
			settings = append(settings,
				plistEntry{"AuthenticationMethod", plistString("Certificate")},
				plistEntry{"ExtendedAuthEnabled", plistInt(0)},
				plistEntry{"PayloadCertificateUUID", plistString(certUUID)})
		} else {
			settings = append(settings,
				plistEntry{"AuthenticationMethod", plistString("None")},
				plistEntry{"ExtendedAuthEnabled", plistInt(1)},
				plistEntry{"AuthName", plistString(identity)},
				plistEntry{"AuthPassword", plistString(key.Secret)})
		}
	case IPsec:
		vpnType = "IPSec"
		settings = plistDict{
			{"RemoteAddress", plistString(address)},
			{"XAuthEnabled", plistInt(1)},
			{"XAuthName", plistString(identity)},
			{"XAuthPassword", plistString(key.Secret)},
			{"PromptForVPNPIN", plistBool(false)},
		}
		if key.Auth == AuthPSK {
			// The group name is the server's; local_identifier names the XAuth user.
			settings = append(settings,
				plistEntry{"AuthenticationMethod", plistString("SharedSecret")},
				plistEntry{"LocalIdentifier", plistString(s.IPsec.GroupName)},
				plistEntry{"LocalIdentifierType", plistString("KeyID")},
				plistEntry{"SharedSecret", plistData([]byte(s.IPsec.PSK))})
		} else {
			settings = append(settings,
				plistEntry{"AuthenticationMethod", plistString("Certificate")},
				plistEntry{"PayloadCertificateUUID", plistString(certUUID)})
		}
	}
	if options.OnDemand {
		settings = append(settings,
			plistEntry{"OnDemandEnabled", plistInt(1)},
			plistEntry{"OnDemandRules", plistArray{plistDict{{"Action", plistString("Connect")}}}})
	}
	name := fmt.Sprintf("%s (%s)", s.Name, map[string]string{IKEv2: "IKEv2", IPsec: "IPsec"}[key.Protocol])
	payloads = append(payloads, plistDict{
		{"PayloadType", plistString("com.apple.vpn.managed")},
		{"PayloadVersion", plistInt(1)},
		{"PayloadIdentifier", plistString(prefix + ".vpn")},
		{"PayloadUUID", plistString(id("vpn"))},
		{"PayloadDisplayName", plistString(name)},
		{"UserDefinedName", plistString(name)},
		{"VPNType", plistString(vpnType)},
		{vpnType, settings},
		{"IPv4", plistDict{{"OverridePrimary", plistInt(1)}}},
	})
	return plistDocument(plistDict{
		{"PayloadType", plistString("Configuration")},
		{"PayloadVersion", plistInt(1)},
		{"PayloadIdentifier", plistString(prefix)},
		{"PayloadUUID", plistString(id("profile"))},
		{"PayloadDisplayName", plistString(name + " · " + user.Name)},
		{"PayloadDescription", plistString(fmt.Sprintf("VPN for %s on %s. Created %s by Ghostlink server.", user.Name, s.Name, time.Now().UTC().Format("2 Jan 2006")))},
		{"PayloadOrganization", plistString("Ghostlink")},
		{"PayloadRemovalDisallowed", plistBool(false)},
		{"PayloadContent", payloads},
	}), nil
}
