// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

const maxRuleEntries = 512

// normalizeDomain accepts "example.com", "*.example.com" or ".example.com" (all mean the site
// and its subdomains) and returns the lowercase bare name.
func normalizeDomain(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || len(domain) > 253 {
		return "", fmt.Errorf("invalid site %q", value)
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid site %q", value)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("invalid site %q (use the ASCII/punycode form)", value)
			}
		}
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return "", fmt.Errorf("%q is an IP address; put it in blocked IPs", value)
	}
	return domain, nil
}

// normalizePrefix accepts an IP address or CIDR range and returns canonical CIDR text.
func normalizePrefix(value string) (string, error) {
	text := strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("invalid IP address or range %q", value)
	}
	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String(), nil
}

// portRange parses "N" or "LO-HI" (1-65535).
func portRange(value string) (uint16, uint16, error) {
	text := strings.TrimSpace(value)
	low, high, isRange := strings.Cut(text, "-")
	parse := func(s string) (uint16, error) {
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil || n == 0 {
			return 0, fmt.Errorf("invalid port %q", value)
		}
		return uint16(n), nil
	}
	lo, err := parse(low)
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return lo, lo, nil
	}
	hi, err := parse(high)
	if err != nil || hi < lo {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	return lo, hi, nil
}

func normalizePort(value string) (string, error) {
	lo, hi, err := portRange(value)
	if err != nil {
		return "", err
	}
	if lo == hi {
		return strconv.Itoa(int(lo)), nil
	}
	return fmt.Sprintf("%d-%d", lo, hi), nil
}

func normalizeList(values []string, what string, normalize func(string) (string, error)) ([]string, error) {
	if len(values) > maxRuleEntries {
		return nil, fmt.Errorf("at most %d %s", maxRuleEntries, what)
	}
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		normalized, err := normalize(value)
		if err != nil {
			return nil, err
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result, nil
}

// Normalize validates rules and returns them in canonical form.
func (r Rules) Normalize() (Rules, error) {
	var err error
	out := Rules{BlockBitTorrent: r.BlockBitTorrent, BlockSMTP: r.BlockSMTP}
	if out.BlockedDomains, err = normalizeList(r.BlockedDomains, "blocked sites", normalizeDomain); err != nil {
		return Rules{}, err
	}
	if out.BlockedIPs, err = normalizeList(r.BlockedIPs, "blocked IP ranges", normalizePrefix); err != nil {
		return Rules{}, err
	}
	if out.BlockedPorts, err = normalizeList(r.BlockedPorts, "blocked ports", normalizePort); err != nil {
		return Rules{}, err
	}
	return out, nil
}

// Empty reports whether the rules block nothing.
func (r Rules) Empty() bool {
	return len(r.BlockedDomains) == 0 && len(r.BlockedIPs) == 0 && len(r.BlockedPorts) == 0 &&
		!r.BlockBitTorrent && !r.BlockSMTP
}

// ValidName accepts display names for users and the server: 1-64 printable characters.
func ValidName(name string) error {
	if strings.TrimSpace(name) == "" || len([]rune(name)) > 64 {
		return errors.New("names must be 1-64 characters")
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return errors.New("names may not contain control characters")
		}
	}
	return nil
}

// ValidHostname accepts the address clients use to reach the server: an IP or a DNS name.
func ValidHostname(host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" || !addr.IsValid() || addr.IsUnspecified() {
			return fmt.Errorf("invalid server address %q", host)
		}
		return nil
	}
	if normalized, err := normalizeDomain(host); err != nil || normalized != host {
		return fmt.Errorf("invalid server address %q", host)
	}
	return nil
}
