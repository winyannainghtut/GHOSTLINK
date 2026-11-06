// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package awg provides an "amneziawg" sing-box endpoint backed by unmodified amneziawg-go.
// It serves both roles: a client with one peer, and a server listening for many peers.
package awg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Type is the sing-box endpoint type name.
const Type = "amneziawg"

// Options configures the endpoint. Obfuscation values use amneziawg-go UAPI names and syntax.
type Options struct {
	Name        string                           `json:"name,omitempty"`
	MTU         uint32                           `json:"mtu,omitempty"`
	Address     badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey  string                           `json:"private_key"`
	ListenPort  uint16                           `json:"listen_port,omitempty"`
	Peers       []Peer                           `json:"peers,omitempty"`
	UDPTimeout  badoption.Duration               `json:"udp_timeout,omitempty"`
	Obfuscation map[string]string                `json:"obfuscation,omitempty"`
	option.DialerOptions
}

// Peer is one remote party. On a server, User names the account the peer belongs to so that
// routing rules can match it with auth_user.
type Peer struct {
	User                string                           `json:"user,omitempty"`
	Address             string                           `json:"address,omitempty"`
	Port                uint16                           `json:"port,omitempty"`
	PublicKey           string                           `json:"public_key"`
	PreSharedKey        string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs          badoption.Listable[netip.Prefix] `json:"allowed_ips"`
	PersistentKeepalive string                           `json:"persistent_keepalive,omitempty"`
}

// Device-level UAPI keys accepted for obfuscation. Anything else is rejected so that a config
// can never inject other UAPI settings.
var obfuscationKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"header_protection_key": true, "content_padding_addition": true,
	"rekey_after_time": true, "rekey_timeout": true, "reject_after_time": true,
	"keepalive_timeout": true, "max_handshake_attempts": true,
	"random_trailers": true, "disable_cookies": true,
}

// Order in which obfuscation keys are written; amneziawg-go validates some keys against others.
var obfuscationOrder = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5", "header_protection_key", "content_padding_addition",
	"rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout",
	"max_handshake_attempts", "random_trailers", "disable_cookies",
}

// uapiValue rejects anything that could break out of a single UAPI "key=value" line.
func uapiValue(name, value string) error {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "=\r\n\x00") {
		return fmt.Errorf("invalid %s value", name)
	}
	return nil
}

func keyHex(name, value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%s must be a base64 32-byte key", name)
	}
	return hex.EncodeToString(raw), nil
}

// deviceConfig renders the device-level UAPI configuration (private key, port, obfuscation).
func (o Options) deviceConfig() (string, error) {
	privateKey, err := keyHex("private_key", o.PrivateKey)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("private_key=" + privateKey)
	if o.ListenPort != 0 {
		fmt.Fprintf(&b, "\nlisten_port=%d", o.ListenPort)
	}
	for name := range o.Obfuscation {
		if !obfuscationKeys[name] {
			return "", fmt.Errorf("unsupported obfuscation parameter %q", name)
		}
	}
	for _, name := range obfuscationOrder {
		value, present := o.Obfuscation[name]
		if !present {
			continue
		}
		if err := uapiValue(name, value); err != nil {
			return "", err
		}
		b.WriteString("\n" + name + "=" + value)
	}
	return b.String(), nil
}

// peerConfig renders one peer's UAPI lines. endpoint is empty for server-side peers.
func (p Peer) peerConfig(endpoint netip.AddrPort) (string, error) {
	publicKey, err := keyHex("public_key", p.PublicKey)
	if err != nil {
		return "", err
	}
	if len(p.AllowedIPs) == 0 {
		return "", fmt.Errorf("peer has no allowed_ips")
	}
	var b strings.Builder
	b.WriteString("\npublic_key=" + publicKey)
	if endpoint.IsValid() {
		b.WriteString("\nendpoint=" + endpoint.String())
	}
	if p.PreSharedKey != "" {
		psk, err := keyHex("pre_shared_key", p.PreSharedKey)
		if err != nil {
			return "", err
		}
		b.WriteString("\npreshared_key=" + psk)
	}
	if p.PersistentKeepalive != "" {
		if err := uapiValue("persistent_keepalive", p.PersistentKeepalive); err != nil {
			return "", err
		}
		b.WriteString("\npersistent_keepalive_interval=" + p.PersistentKeepalive)
	}
	for _, prefix := range p.AllowedIPs {
		b.WriteString("\nallowed_ip=" + prefix.String())
	}
	return b.String(), nil
}
