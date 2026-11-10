// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	N "github.com/sagernet/sing/common/network"
)

// Destinations no VPN user may reach, whatever the rules say. The server runs with host
// networking, so these would otherwise expose the host's own and neighbouring services.
var internalRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

// internalPrefixes are internalRanges, parsed.
var internalPrefixes = func() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(internalRanges))
	for i, cidr := range internalRanges {
		prefixes[i] = netip.MustParsePrefix(cidr)
	}
	return prefixes
}()

// isInternal reports an address that internalRanges block already.
func isInternal(addr netip.Addr) bool {
	addr = addr.Unmap()
	return slices.ContainsFunc(internalPrefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

type object = map[string]any

// listenAddress is where inbounds listen; tests use loopback so no firewall prompt appears.
var listenAddress = "::"

// lowestPort is the lowest port the server can listen on (lowport_linux.go); tests replace it.
var lowestPort = listenFloor

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
		// Keys imported from Outline on other ports get one more inbound per port.
		users := map[uint16][]any{}
		methods := map[uint16]string{}
		for _, entry := range keys {
			port, method := s.shadowsocksEndpoint(entry.key)
			users[port] = append(users[port], object{"name": entry.user.Tag(), "password": entry.key.Password})
			methods[port] = method
		}
		for _, port := range s.shadowsocksPorts() {
			if len(users[port]) == 0 {
				continue
			}
			inbounds = append(inbounds, object{
				"type": "shadowsocks", "tag": shadowsocksTag(s, port), "listen": listenAddress, "listen_port": port,
				"method": methods[port], "users": users[port],
			})
		}
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
		inbounds = append(inbounds, object{"type": ipsecDNSType, "tag": ipsecDNSTag, "listen": listenAddress, "listen_port": s.IPsec.DNSPort})
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
		object{"port": s.privatePorts(), "action": "reject"},
	)
	if addrs := s.serverAddresses(); len(addrs) > 0 {
		var own []string
		for _, addr := range addrs {
			own = append(own, netip.PrefixFrom(addr, addr.BitLen()).String())
		}
		rules = append(rules, internalBlock(object{"ip_cidr": own}))
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

// privatePorts are this server's own service ports, which VPN users must never reach, on any
// address: the server may be reachable through addresses it does not know about.
func (s *State) privatePorts() []uint16 {
	ports := []uint16{s.API.Port}
	if s.Dashboard.Port != 0 {
		ports = append(ports, s.Dashboard.Port)
	}
	if s.meshEnabled() {
		ports = append(ports, s.Mesh.Port)
	}
	return ports
}

// hostAddresses lists the addresses on this host's interfaces. The server runs with host
// networking, so a VPN user's connection to one of them is delivered over loopback, past host
// firewall allowlists, to every service on the host. Tests replace it.
var hostAddresses = func() []netip.Addr {
	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, a := range interfaceAddrs {
		network, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(network.IP); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs
}

// serverAddresses are the addresses VPN users must not reach the server itself at: its
// hostname when that is an address, and every public address of the host. Addresses the
// internal ranges block anyway (private and reserved ones, and the mesh's 100.64.0.0/10) are
// left out, so that one coming or going, as when this host joins or leaves a mesh, does not
// change the engine's configuration and restart it (code review 2026-11-09, F5).
func (s *State) serverAddresses() []netip.Addr {
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(s.Hostname); err == nil {
		addrs = append(addrs, addr)
	}
	for _, addr := range hostAddresses() {
		if N.IsPublicAddr(addr) && !isInternal(addr) && !slices.Contains(addrs, addr) {
			addrs = append(addrs, addr)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return addrs
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
		for _, port := range s.shadowsocksPorts() {
			ports[shadowsocksTag(s, port)] = "tcp+udp/" + strconv.Itoa(int(port))
		}
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
	if s.meshEnabled() {
		ports["mesh"] = "tcp/" + strconv.Itoa(int(s.Mesh.Port))
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

// shadowsocksEndpoint is the port and cipher a Shadowsocks key uses: its own (imported from
// Outline) or the server's.
func (s *State) shadowsocksEndpoint(k *Key) (uint16, string) {
	port, method := s.Shadowsocks.Port, s.Shadowsocks.Method
	if k.Port != 0 {
		port = k.Port
	}
	if k.Method != "" {
		method = k.Method
	}
	return port, method
}

// shadowsocksPorts lists the main Shadowsocks port, then the extra ports of imported keys.
func (s *State) shadowsocksPorts() []uint16 {
	ports := []uint16{s.Shadowsocks.Port}
	seen := map[uint16]bool{s.Shadowsocks.Port: true}
	var extra []uint16
	for _, u := range s.Users {
		for _, k := range u.Keys {
			if k.Protocol == Shadowsocks && k.Port != 0 && !seen[k.Port] {
				seen[k.Port] = true
				extra = append(extra, k.Port)
			}
		}
	}
	slices.Sort(extra)
	return append(ports, extra...)
}

// shadowsocksTag names a Shadowsocks inbound: the main one, or shadowsocks-<port>.
func shadowsocksTag(s *State, port uint16) string {
	if port == s.Shadowsocks.Port {
		return Shadowsocks
	}
	return Shadowsocks + "-" + strconv.Itoa(int(port))
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
	if s.meshEnabled() && (s.Mesh.Port < 1024 || s.Mesh.Port == 443) {
		return fmt.Errorf("the mesh needs its own port from 1024 to 65535 (not 443)")
	}
	names := []string{"api", "dashboard", "mesh", Shadowsocks, VLESS, WireGuard, AmneziaWG, "ipsec-ike", "ipsec-natt", ipsecDNSTag}
	for _, port := range s.shadowsocksPorts() {
		if tag := shadowsocksTag(s, port); tag != Shadowsocks {
			names = append(names, tag)
		}
	}
	for _, u := range s.Users {
		for _, k := range u.Keys {
			if k.Protocol == Shadowsocks && k.Port != 0 && k.Port == s.Shadowsocks.Port {
				return fmt.Errorf("Shadowsocks port %d is already used by keys imported from Outline", k.Port)
			}
		}
	}
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

// checkReservedPorts is CheckPorts with every VPN protocol counted, on or off: a protocol that
// is off keeps its port for when it is turned on, so no other service may take it.
func (s *State) checkReservedPorts() error {
	if err := s.CheckPorts(); err != nil {
		return err
	}
	all := *s
	all.Shadowsocks.Enabled, all.VLESS.Enabled, all.WireGuard.Enabled, all.AmneziaWG.Enabled = true, true, true, true
	if err := all.CheckPorts(); err != nil {
		return fmt.Errorf("%w (a protocol that is off keeps its port for when it is turned on)", err)
	}
	return nil
}

// heldPort is a port on one transport, "tcp" or "udp": TCP and UDP can share a port number, so
// holding one of them says nothing about the other.
type heldPort struct {
	network string
	port    uint16
}

// listenerNetworks are the transports each kind of engine listener binds.
var listenerNetworks = map[string][]string{"shadowsocks": {"tcp", "udp"}, "vless": {"tcp"}, ipsecDNSType: {"tcp", "udp"}, "amneziawg": {"udp"}}

// heldPorts are the ports this server's own listeners hold now, per transport: the API, the
// dashboard, the mesh while it is on (TCP), and what the running engine binds, read from the
// configuration it runs (running: from Engine.Running, nil while the engine is down). A change
// may move a service onto one of them on the same transport, as when two services swap ports.
// What the saved state would bind does not count: an engine that could not start (another
// program holds one of its ports) holds none of its ports, so each is tried again (code review
// 2026-11-10, R2). A protocol that is off, or has no keys yet, holds no port either, so turning
// it on tries its port: another program may have taken it since the server was created.
func (s *State) heldPorts(running []byte) map[heldPort]bool {
	held := map[heldPort]bool{{"tcp", s.API.Port}: true}
	if s.Dashboard.Port != 0 {
		held[heldPort{"tcp", s.Dashboard.Port}] = true
	}
	if s.meshEnabled() {
		held[heldPort{"tcp", s.Mesh.Port}] = true
	}
	var config struct {
		Inbounds  []engineListener `json:"inbounds"`
		Endpoints []engineListener `json:"endpoints"`
	}
	if len(running) > 0 && json.Unmarshal(running, &config) == nil {
		for _, listener := range append(config.Inbounds, config.Endpoints...) {
			for _, network := range listenerNetworks[listener.Type] {
				if listener.ListenPort != 0 {
					held[heldPort{network, listener.ListenPort}] = true
				}
			}
		}
	}
	return held
}

// engineListener is what heldPorts reads of an inbound or endpoint in an engine configuration.
type engineListener struct {
	Type       string `json:"type"`
	ListenPort uint16 `json:"listen_port"`
}
