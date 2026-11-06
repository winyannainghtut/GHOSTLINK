// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Destinations no VPN user may reach, whatever the rules say. The server runs with host
// networking, so these would otherwise expose the host's own and neighbouring services.
var internalRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

type object = map[string]any

// listenAddress is where inbounds listen; tests use loopback so no firewall prompt appears.
var listenAddress = "::"

// ipsecDNSSources may use the IPsec DNS listener: the pools (tests add loopback).
var ipsecDNSSources = []string{ikev2Pool, ipsecPool}

// testInternalPort lets package tests reach one loopback port; it is never set otherwise.
var testInternalPort uint16

// internalBlock rejects destinations that must stay unreachable from the VPN.
func internalBlock(match object) object {
	if testInternalPort == 0 {
		match["action"] = "reject"
		return match
	}
	return object{"type": "logical", "mode": "and", "action": "reject",
		"rules": []any{match, object{"port": []uint16{testInternalPort}, "invert": true}}}
}

func (s *State) activeUsers() []*User {
	var users []*User
	for _, u := range s.Users {
		if u.Active() {
			users = append(users, u)
		}
	}
	return users
}

func (s *State) activeKeys(protocol string) []struct {
	user *User
	key  *Key
} {
	var keys []struct {
		user *User
		key  *Key
	}
	for _, u := range s.activeUsers() {
		for _, k := range u.Keys {
			if k.Protocol == protocol {
				keys = append(keys, struct {
					user *User
					key  *Key
				}{u, k})
			}
		}
	}
	return keys
}

func (s *State) inbounds() []any {
	var inbounds []any
	if keys := s.activeKeys(Shadowsocks); s.Shadowsocks.Enabled && len(keys) > 0 {
		users := []any{}
		for _, entry := range keys {
			users = append(users, object{"name": entry.user.Tag(), "password": entry.key.Password})
		}
		inbounds = append(inbounds, object{
			"type": "shadowsocks", "tag": Shadowsocks, "listen": listenAddress, "listen_port": s.Shadowsocks.Port,
			"method": s.Shadowsocks.Method, "users": users,
		})
	}
	if keys := s.activeKeys(VLESS); s.VLESS.Enabled && len(keys) > 0 {
		users := []any{}
		for _, entry := range keys {
			users = append(users, object{"name": entry.user.Tag(), "uuid": entry.key.UUID, "flow": "xtls-rprx-vision"})
		}
		inbounds = append(inbounds, object{
			"type": "vless", "tag": VLESS, "listen": listenAddress, "listen_port": s.VLESS.Port, "users": users,
			"tls": object{
				"enabled": true, "server_name": s.VLESS.Handshake,
				"reality": object{
					"enabled":     true,
					"handshake":   object{"server": s.VLESS.handshakeServer(), "server_port": s.VLESS.handshakePort()},
					"private_key": s.VLESS.PrivateKey,
					"short_id":    []string{s.VLESS.ShortID},
				},
			},
		})
	}
	// IPsec clients ask the pool gateway for DNS; the agent forwards gateway:53 here.
	if s.appleEnabled() && s.IPsec.DNSPort != 0 {
		inbounds = append(inbounds, object{"type": "direct", "tag": ipsecDNSTag, "listen": listenAddress, "listen_port": s.IPsec.DNSPort})
	}
	return inbounds
}

func (s *State) endpoints() []any {
	var endpoints []any
	for _, protocol := range []string{WireGuard, AmneziaWG} {
		server := s.wireGuardServer(protocol)
		keys := s.activeKeys(protocol)
		if !server.Enabled || len(keys) == 0 {
			continue
		}
		prefix, _ := netip.ParsePrefix(server.Subnet)
		peers := []any{}
		for _, entry := range keys {
			peers = append(peers, object{
				"user": entry.user.Tag(), "public_key": entry.key.PublicKey, "pre_shared_key": entry.key.PresharedKey,
				"allowed_ips": []string{entry.key.Address + "/32"},
			})
		}
		endpoint := object{
			"type": "amneziawg", "tag": protocol, "listen_port": server.Port, "mtu": clientMTU,
			"address":     []string{netip.PrefixFrom(prefix.Masked().Addr().Next(), prefix.Bits()).String()},
			"private_key": server.PrivateKey, "peers": peers,
		}
		if protocol == AmneziaWG {
			endpoint["obfuscation"] = s.AmneziaWG.Params.uapi()
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// blockRules turns one rule set into reject rules; scope narrows them (for example to a user).
func blockRules(rules Rules, scope object) []any {
	with := func(match object) object {
		rule := object{"action": "reject"}
		for k, v := range scope {
			rule[k] = v
		}
		for k, v := range match {
			rule[k] = v
		}
		return rule
	}
	var out []any
	destinations := object{}
	if len(rules.BlockedDomains) > 0 {
		destinations["domain_suffix"] = rules.BlockedDomains
	}
	if len(rules.BlockedIPs) > 0 {
		destinations["ip_cidr"] = rules.BlockedIPs
	}
	if len(destinations) > 0 {
		out = append(out, with(destinations))
	}
	var ports []uint16
	var ranges []string
	for _, entry := range rules.BlockedPorts {
		lo, hi, _ := portRange(entry)
		if lo == hi {
			ports = append(ports, lo)
		} else {
			ranges = append(ranges, fmt.Sprintf("%d:%d", lo, hi))
		}
	}
	if rules.BlockSMTP {
		ports = append(ports, 25)
	}
	if len(ports) > 0 || len(ranges) > 0 {
		match := object{}
		if len(ports) > 0 {
			match["port"] = ports
		}
		if len(ranges) > 0 {
			match["port_range"] = ranges
		}
		out = append(out, with(match))
	}
	if rules.BlockBitTorrent {
		out = append(out, with(object{"protocol": []string{"bittorrent"}}))
	}
	return out
}

func dnsBlockRule(domains []string, scope object) []any {
	if len(domains) == 0 {
		return nil
	}
	rule := object{"domain_suffix": domains, "action": "predefined", "rcode": "NXDOMAIN"}
	for k, v := range scope {
		rule[k] = v
	}
	return []any{rule}
}

func (s *State) routeRules() ([]any, []any) {
	rules := []any{}
	if s.appleEnabled() && s.IPsec.DNSPort != 0 {
		// Only the IPsec pools may use their DNS listener, and only for DNS.
		rules = append(rules,
			object{"inbound": []string{ipsecDNSTag}, "source_ip_cidr": ipsecDNSSources, "action": "hijack-dns"},
			object{"inbound": []string{ipsecDNSTag}, "action": "reject"})
	}
	rules = append(rules,
		object{"action": "sniff"},
		// All DNS goes to the server's resolver so site blocks cannot be skipped with another resolver.
		object{"type": "logical", "mode": "or", "rules": []any{object{"protocol": []string{"dns"}}, object{"port": []int{53}}}, "action": "hijack-dns"},
		// Resolve names here so that internal-address blocks also catch names pointing inside.
		object{"action": "resolve", "strategy": "prefer_ipv4"},
		internalBlock(object{"ip_is_private": true}),
		internalBlock(object{"ip_cidr": internalRanges}),
		object{"port": []uint16{s.API.Port}, "action": "reject"},
	)
	if addr, err := netip.ParseAddr(s.Hostname); err == nil {
		rules = append(rules, internalBlock(object{"ip_cidr": []string{netip.PrefixFrom(addr, addr.BitLen()).String()}}))
	}
	var dnsRules []any
	var exempt []string
	for _, u := range s.activeUsers() {
		scope := object{"auth_user": []string{u.Tag()}}
		rules = append(rules, blockRules(u.Rules, scope)...)
		dnsRules = append(dnsRules, dnsBlockRule(u.Rules.BlockedDomains, scope)...)
		if u.ExemptFromGlobalRules {
			exempt = append(exempt, u.Tag())
		}
	}
	if len(exempt) > 0 {
		rules = append(rules, object{"auth_user": exempt, "action": "route", "outbound": "direct"})
		dnsRules = append(dnsRules, object{"auth_user": exempt, "action": "route", "server": "local"})
	}
	rules = append(rules, blockRules(s.Rules, nil)...)
	dnsRules = append(dnsRules, dnsBlockRule(s.Rules.BlockedDomains, nil)...)
	return rules, dnsRules
}

// EngineConfig renders the sing-box configuration for the current state.
func (s *State) EngineConfig(logLevel string) ([]byte, error) {
	routeRules, dnsRules := s.routeRules()
	logOptions := object{"level": logLevel, "timestamp": true}
	if logLevel == "off" {
		logOptions = object{"disabled": true}
	}
	config := object{
		"log": logOptions,
		"dns": object{
			"servers":  []any{object{"type": "local", "tag": "local"}},
			"rules":    dnsRules,
			"final":    "local",
			"strategy": "prefer_ipv4",
		},
		"inbounds":  s.inbounds(),
		"endpoints": s.endpoints(),
		"outbounds": []any{object{"type": "direct", "tag": "direct"}},
		"route": object{
			"rules": routeRules, "final": "direct",
			"default_domain_resolver": object{"server": "local", "strategy": "prefer_ipv4"},
		},
	}
	return json.MarshalIndent(config, "", "  ")
}

// Listening describes the ports the engine needs, for conflict checks.
func (s *State) Listening() map[string]string {
	ports := map[string]string{"api": "tcp/" + strconv.Itoa(int(s.API.Port))}
	if s.Dashboard.Port != 0 {
		ports["dashboard"] = "tcp/" + strconv.Itoa(int(s.Dashboard.Port))
	}
	if s.Shadowsocks.Enabled {
		ports[Shadowsocks] = "tcp+udp/" + strconv.Itoa(int(s.Shadowsocks.Port))
	}
	if s.VLESS.Enabled {
		ports[VLESS] = "tcp/" + strconv.Itoa(int(s.VLESS.Port))
	}
	if s.WireGuard.Enabled {
		ports[WireGuard] = "udp/" + strconv.Itoa(int(s.WireGuard.Port))
	}
	if s.AmneziaWG.Enabled {
		ports[AmneziaWG] = "udp/" + strconv.Itoa(int(s.AmneziaWG.Port))
	}
	if s.appleEnabled() {
		// strongSwan owns 500 and 4500 (iOS cannot use other ports); the DNS listener is ours.
		ports["ipsec-ike"], ports["ipsec-natt"] = "udp/500", "udp/4500"
		if s.IPsec.DNSPort != 0 {
			ports[ipsecDNSTag] = "tcp+udp/" + strconv.Itoa(int(s.IPsec.DNSPort))
		}
	}
	return ports
}

// portsConflict reports two services sharing a port on the same transport.
func portsConflict(a, b string) bool {
	protoA, portA, _ := strings.Cut(a, "/")
	protoB, portB, _ := strings.Cut(b, "/")
	if portA != portB {
		return false
	}
	return strings.Contains(protoA, "tcp") && strings.Contains(protoB, "tcp") ||
		strings.Contains(protoA, "udp") && strings.Contains(protoB, "udp")
}

// CheckPorts rejects port collisions between the API and enabled protocols.
func (s *State) CheckPorts() error {
	ports := s.Listening()
	if s.Dashboard.Port != 0 && (s.Dashboard.Port < 1024 || s.Dashboard.Port == 443) {
		return fmt.Errorf("the dashboard needs its own port from 1024 to 65535 (not 443)")
	}
	names := []string{"api", "dashboard", Shadowsocks, VLESS, WireGuard, AmneziaWG, "ipsec-ike", "ipsec-natt", ipsecDNSTag}
	for i, a := range names {
		for _, b := range names[i+1:] {
			pa, okA := ports[a]
			pb, okB := ports[b]
			if okA && okB && portsConflict(pa, pb) {
				return fmt.Errorf("%s and %s cannot share port %s", a, b, strings.SplitN(pa, "/", 2)[1])
			}
		}
	}
	return nil
}
