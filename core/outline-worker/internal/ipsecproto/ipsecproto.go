// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package ipsecproto is the file contract between the unprivileged Ghostlink server and the
// privileged IPsec agent. The server writes Desired; the agent validates every field before
// applying it and reports back with Status. Nothing in Desired is passed to a shell, and the
// algorithms are fixed in the agent, not taken from this file.
package ipsecproto

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	DesiredFile = "desired.json"
	StatusFile  = "status.json"
	Version     = 1
)

type Desired struct {
	Version    int    `json:"version"`
	Generation int64  `json:"generation"`
	CA         string `json:"ca_pem"`
	Server     string `json:"server_pem"`
	ServerKey  string `json:"server_key_pem"`
	CRL        string `json:"crl_pem"`
	// ServerID is the identity the server presents (its hostname or IP).
	ServerID string   `json:"server_id"`
	IKEv2    *IKEv2   `json:"ikev2,omitempty"`
	IKEv1    *IKEv1   `json:"ikev1,omitempty"`
	Firewall Firewall `json:"firewall"`
	Allowed  []string `json:"allowed"`
}

type IKEv2 struct {
	Pool    string `json:"pool"`
	Gateway string `json:"gateway"`
	// EAP holds NT hashes (EAP-MSCHAPv2), never plaintext passwords.
	EAP          []NTLMSecret `json:"eap"`
	Certificates bool         `json:"certificates"`
}

type IKEv1 struct {
	Pool    string `json:"pool"`
	Gateway string `json:"gateway"`
	// Group and PSK are set only when a PSK key exists.
	Group        string        `json:"group,omitempty"`
	PSK          string        `json:"psk,omitempty"`
	XAuth        []XAuthSecret `json:"xauth"`
	Certificates bool          `json:"certificates"`
}

type NTLMSecret struct {
	ID     string `json:"id"`
	NTHash string `json:"nt_hash"`
}

type XAuthSecret struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}

// Firewall describes what VPN clients may not reach; the agent turns it into iptables rules.
type Firewall struct {
	// Internal ranges are always blocked (loopback, private, metadata…).
	Internal []string `json:"internal"`
	Blocked  []string `json:"blocked"`
	// Ports are "N" or "LO-HI", blocked for TCP and UDP.
	Ports     []string `json:"ports"`
	BlockSMTP bool     `json:"block_smtp"`
	ServerIP  string   `json:"server_ip,omitempty"`
	// DNSPort is where the server answers the pools' DNS; the agent forwards gateway:53 to it.
	DNSPort uint16 `json:"dns_port"`
}

// Status is what the agent reports every few seconds.
type Status struct {
	Version     int      `json:"version"`
	UpdatedUnix int64    `json:"updated_unix"`
	Running     bool     `json:"running"`
	Applied     int64    `json:"applied_generation"`
	Error       string   `json:"error,omitempty"`
	Plugins     []string `json:"plugins,omitempty"`
	SAs         []SA     `json:"sas"`
}

type SA struct {
	Name        string  `json:"name"`
	UniqueID    string  `json:"unique_id"`
	Version     int     `json:"version"`
	Identity    string  `json:"identity"`
	Remote      string  `json:"remote"`
	VirtualIP   string  `json:"virtual_ip,omitempty"`
	Established int64   `json:"established_seconds"`
	Children    []Child `json:"children"`
}

type Child struct {
	UniqueID string `json:"unique_id"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// ValidIdentity accepts IKE identities that need no quoting anywhere and that strongSwan
// reads as a name or e-mail address (never an IP address or a special @ form).
func ValidIdentity(id string) bool {
	if _, err := netip.ParseAddr(id); err == nil {
		return false
	}
	return identityPattern.MatchString(id)
}

// ValidServerID accepts the server's identity: a name as for ValidIdentity, or an IP address.
func ValidServerID(id string) bool {
	if _, err := netip.ParseAddr(id); err == nil {
		return true
	}
	return identityPattern.MatchString(id)
}

func validCertificate(text string, wantCA bool) error {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if cert.IsCA != wantCA {
		return errors.New("certificate role mismatch")
	}
	return nil
}

func validPool(pool, gateway string) error {
	prefix, err := netip.ParsePrefix(pool)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 24 {
		return errors.New("pool must be an IPv4 range from /16 to /24")
	}
	addr, err := netip.ParseAddr(gateway)
	if err != nil || addr != prefix.Masked().Addr().Next() {
		return errors.New("gateway must be the first address of the pool")
	}
	return nil
}

func validPort(text string) error {
	low, high, isRange := strings.Cut(text, "-")
	lo, err := strconv.ParseUint(low, 10, 16)
	if err != nil || lo == 0 {
		return fmt.Errorf("invalid port %q", text)
	}
	if isRange {
		hi, err := strconv.ParseUint(high, 10, 16)
		if err != nil || hi < lo {
			return fmt.Errorf("invalid port range %q", text)
		}
	}
	return nil
}

// Validate checks every field the agent will apply.
func (d *Desired) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("unsupported version %d", d.Version)
	}
	if d.IKEv2 == nil && d.IKEv1 == nil {
		return nil
	}
	if err := validCertificate(d.CA, true); err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	if err := validCertificate(d.Server, false); err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	if block, _ := pem.Decode([]byte(d.ServerKey)); block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("server key is not a PEM private key")
	}
	if block, _ := pem.Decode([]byte(d.CRL)); block == nil || block.Type != "X509 CRL" {
		return errors.New("CRL is not a PEM CRL")
	} else if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
		return fmt.Errorf("CRL: %w", err)
	}
	if !ValidServerID(d.ServerID) {
		return errors.New("invalid server identity")
	}
	if v := d.IKEv2; v != nil {
		if err := validPool(v.Pool, v.Gateway); err != nil {
			return fmt.Errorf("IKEv2: %w", err)
		}
		for _, s := range v.EAP {
			if raw, err := hex.DecodeString(s.NTHash); !ValidIdentity(s.ID) || err != nil || len(raw) != 16 {
				return errors.New("IKEv2: invalid EAP identity or hash")
			}
		}
	}
	if v := d.IKEv1; v != nil {
		if err := validPool(v.Pool, v.Gateway); err != nil {
			return fmt.Errorf("IPsec: %w", err)
		}
		if v.PSK != "" && (!ValidIdentity(v.Group) || len(v.PSK) < 32 || len(v.PSK) > 128) {
			return errors.New("IPsec: invalid group or pre-shared key")
		}
		for _, s := range v.XAuth {
			if !ValidIdentity(s.ID) || s.Password == "" || len(s.Password) > 128 || strings.ContainsAny(s.Password, "\x00\r\n") {
				return errors.New("IPsec: invalid XAuth identity or password")
			}
		}
	}
	for _, id := range d.Allowed {
		if !ValidIdentity(id) {
			return errors.New("invalid allowed identity")
		}
	}
	f := d.Firewall
	for _, cidr := range append(append([]string{}, f.Internal...), f.Blocked...) {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid range %q", cidr)
		}
	}
	for _, port := range f.Ports {
		if err := validPort(port); err != nil {
			return err
		}
	}
	if f.ServerIP != "" {
		if _, err := netip.ParseAddr(f.ServerIP); err != nil {
			return errors.New("invalid server IP")
		}
	}
	if f.DNSPort < 1024 {
		return errors.New("invalid DNS port")
	}
	return nil
}
