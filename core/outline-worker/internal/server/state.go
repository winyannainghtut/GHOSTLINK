// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package server is the Ghostlink server: one sing-box instance hosting Shadowsocks,
// VLESS-REALITY, WireGuard and AmneziaWG, managed through an HTTPS API (Outline-style).
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"ghostlink.local/outline-worker/internal/mesh"
)

const (
	StateFile         = "state.json"
	ManagementKeyFile = "management-key.json"
	SchemaVersion     = 1
	MaxUsers          = 500
	MaxKeysPerUser    = 16
)

// Protocol names used by the API and in keys.
const (
	Shadowsocks = "shadowsocks"
	VLESS       = "vless"
	WireGuard   = "wireguard"
	AmneziaWG   = "amneziawg"
)

var Protocols = []string{AmneziaWG, WireGuard, VLESS, Shadowsocks}

// Apple's built-in VPN protocols, served by the optional IPsec component (strongSwan).
const (
	IKEv2 = "ikev2"
	IPsec = "ipsec" // IKEv1 "Cisco IPsec"
)

var AppleProtocols = []string{IKEv2, IPsec}

// Authentication methods for IKEv2 and IPsec keys.
const (
	AuthEAP         = "eap"         // IKEv2 username/password (EAP-MSCHAPv2)
	AuthCertificate = "certificate" // a client certificate from the server's own CA
	AuthPSK         = "psk"         // IKEv1 shared group key + per-user XAuth password
)

type APIConfig struct {
	Port    uint16 `json:"port"`
	Secret  string `json:"secret"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type ShadowsocksServer struct {
	Enabled bool   `json:"enabled"`
	Port    uint16 `json:"port"`
	Method  string `json:"method"`
}

type VLESSServer struct {
	Enabled    bool   `json:"enabled"`
	Port       uint16 `json:"port"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	// REALITY borrows the TLS handshake of this public site (TLS 1.3, port 443).
	Handshake string `json:"handshake"`
	// Optional address and port to reach the handshake site at (state file only).
	HandshakeServer string `json:"handshake_server,omitempty"`
	HandshakePort   uint16 `json:"handshake_port,omitempty"`
}

func (v VLESSServer) handshakeServer() string {
	if v.HandshakeServer != "" {
		return v.HandshakeServer
	}
	return v.Handshake
}

func (v VLESSServer) handshakePort() uint16 {
	if v.HandshakePort != 0 {
		return v.HandshakePort
	}
	return 443
}

type WireGuardServer struct {
	Enabled    bool   `json:"enabled"`
	Port       uint16 `json:"port"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Subnet     string `json:"subnet"`
}

// AWGParams are the AmneziaWG obfuscation settings shared by the server and its clients.
type AWGParams struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1,omitempty"`
}

type AmneziaWGServer struct {
	WireGuardServer
	Params AWGParams `json:"params"`
}

// Rules block traffic for everyone (global) or one user.
type Rules struct {
	BlockedDomains  []string `json:"blocked_domains"`
	BlockedIPs      []string `json:"blocked_ips"`
	BlockedPorts    []string `json:"blocked_ports"`
	BlockBitTorrent bool     `json:"block_bittorrent"`
	BlockSMTP       bool     `json:"block_smtp"`
}

type Key struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	CreatedUnix int64  `json:"created_unix"`
	// Shadowsocks
	Password string `json:"password,omitempty"`
	// VLESS
	UUID string `json:"uuid,omitempty"`
	// WireGuard / AmneziaWG
	PrivateKey   string `json:"private_key,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Address      string `json:"address,omitempty"`
	// IKEv2 / IPsec
	Auth string `json:"auth,omitempty"`
	// Secret is the EAP or XAuth password.
	Secret      string `json:"secret,omitempty"`
	CertPEM     string `json:"cert_pem,omitempty"`
	CertKeyPEM  string `json:"cert_key_pem,omitempty"`
	CertSerial  int64  `json:"cert_serial,omitempty"`
	P12Password string `json:"p12_password,omitempty"`
	// Optional overrides for Apple profiles.
	ServerAddress string `json:"server_address,omitempty"`
	RemoteID      string `json:"remote_id,omitempty"`
	LocalID       string `json:"local_id,omitempty"`
}

type User struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	CreatedUnix           int64  `json:"created_unix"`
	Enabled               bool   `json:"enabled"`
	DataLimitBytes        uint64 `json:"data_limit_bytes"`
	UsageBytes            uint64 `json:"usage_bytes"`
	OverLimit             bool   `json:"over_limit"`
	ExemptFromGlobalRules bool   `json:"exempt_from_global_rules"`
	Rules                 Rules  `json:"rules"`
	Keys                  []*Key `json:"keys"`
}

// Tag is the sing-box user name; stable and free of user-controlled text.
func (u *User) Tag() string { return "u" + u.ID }

// Active users may connect: enabled and within any data limit.
func (u *User) Active() bool { return u.Enabled && !u.OverLimit }

type State struct {
	SchemaVersion int               `json:"schema_version"`
	Name          string            `json:"name"`
	Hostname      string            `json:"hostname"`
	CreatedUnix   int64             `json:"created_unix"`
	API           APIConfig         `json:"api"`
	Shadowsocks   ShadowsocksServer `json:"shadowsocks"`
	VLESS         VLESSServer       `json:"vless"`
	WireGuard     WireGuardServer   `json:"wireguard"`
	AmneziaWG     AmneziaWGServer   `json:"amneziawg"`
	IPsec         IPsecServer       `json:"ipsec"`
	// Mesh is the private overlay network this server coordinates (nil until turned on).
	Mesh      *mesh.Network   `json:"mesh,omitempty"`
	Rules     Rules           `json:"rules"`
	Monitor   MonitorSettings `json:"monitor"`
	Dashboard DashboardConfig `json:"dashboard"`
	Users     []*User         `json:"users"`
	NextID    int             `json:"next_id"`
}

// IPsecServer is the optional IKEv2/IPsec service for Apple's built-in VPN. The server holds
// its CA and credentials; the privileged IPsec agent applies them to strongSwan.
type IPsecServer struct {
	IKEv2Enabled bool   `json:"ikev2_enabled"`
	IPsecEnabled bool   `json:"ipsec_enabled"`
	CAPEM        string `json:"ca_pem,omitempty"`
	CAKeyPEM     string `json:"ca_key_pem,omitempty"`
	ServerPEM    string `json:"server_pem,omitempty"`
	ServerKeyPEM string `json:"server_key_pem,omitempty"`
	// ServerFor is the address the server certificate was issued for (renewed on change).
	ServerFor string `json:"server_for,omitempty"`
	// PSK is the IKEv1 group key for PSK keys; GroupName is the group identifier.
	PSK       string `json:"psk,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	// DNSPort is where the server answers IPsec clients' DNS (the agent forwards port 53).
	DNSPort    uint16          `json:"dns_port,omitempty"`
	NextSerial int64           `json:"next_serial,omitempty"`
	Revoked    []RevokedSerial `json:"revoked,omitempty"`
}

type RevokedSerial struct {
	Serial int64 `json:"serial"`
	At     int64 `json:"at_unix"`
}

const (
	ikev2Pool     = "10.79.0.0/20"
	ipsecPool     = "10.80.0.0/20"
	ikev2Gateway  = "10.79.0.1"
	ipsecGateway  = "10.80.0.1"
	defaultGroup  = "ghostlink"
	maxRevocation = 4096
)

// MonitorSettings control what the server records about traffic and for how long.
type MonitorSettings struct {
	// SiteStats records per-user totals per site/service. Off by default.
	SiteStats bool `json:"site_stats"`
	// Retention in days; zero means the default.
	HistoryDays int `json:"history_days,omitempty"`
	SiteDays    int `json:"site_days,omitempty"`
	// HistoryMaxMB caps history.json; zero means the default.
	HistoryMaxMB int `json:"history_max_mb,omitempty"`
}

const (
	defaultHistoryDays  = 90
	defaultSiteDays     = 30
	defaultHistoryMaxMB = 20
	hourlyDays          = 7
	clientDays          = 30
	clientsPerUser      = 20
)

func (m MonitorSettings) historyDays() int {
	if m.HistoryDays > 0 {
		return m.HistoryDays
	}
	return defaultHistoryDays
}

func (m MonitorSettings) siteDays() int {
	if m.SiteDays > 0 {
		return m.SiteDays
	}
	return defaultSiteDays
}

func (m MonitorSettings) historyMaxBytes() int {
	if m.HistoryMaxMB > 0 {
		return m.HistoryMaxMB << 20
	}
	return defaultHistoryMaxMB << 20
}

// DashboardConfig is the admin web dashboard. Private mode serves plain HTTP on 127.0.0.1 only
// (reach it through an SSH tunnel); public mode serves HTTPS on all addresses.
type DashboardConfig struct {
	Port   uint16 `json:"port"`
	Public bool   `json:"public"`
	// Token is the login secret. The state file is as sensitive as the management key.
	Token string `json:"token"`
}

// ensureDashboard gives servers created before the dashboard existed a port and token.
func (s *State) ensureDashboard(free func(string, uint16) bool) (bool, error) {
	changed := false
	if s.Dashboard.Token == "" {
		s.Dashboard.Token = base64.RawURLEncoding.EncodeToString(random(16))
		changed = true
	}
	if s.Dashboard.Port == 0 {
		port, err := pickPort(s.usedPorts(), free, "tcp")
		if err != nil {
			return false, err
		}
		s.Dashboard.Port = port
		changed = true
	}
	return changed, nil
}

func (s *State) newID() string {
	s.NextID++
	return fmt.Sprint(s.NextID)
}

func (s *State) User(id string) *User {
	for _, u := range s.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// usedAddresses lists tunnel addresses already assigned in a subnet.
func (s *State) usedAddresses() map[string]bool {
	used := map[string]bool{}
	for _, u := range s.Users {
		for _, k := range u.Keys {
			if k.Address != "" {
				used[k.Address] = true
			}
		}
	}
	return used
}

// nextAddress picks the next free host address (/32) in subnet, after the server's .1.
func (s *State) nextAddress(subnet string) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", err
	}
	used := s.usedAddresses()
	server := prefix.Masked().Addr().Next()
	for addr := server.Next(); prefix.Contains(addr); addr = addr.Next() {
		if !used[addr.String()] && addr.Next().IsValid() && prefix.Contains(addr.Next()) {
			return addr.String(), nil
		}
	}
	return "", errors.New("the tunnel subnet has no free addresses")
}

// Store persists state atomically; callers hold mu while reading or changing State.
type Store struct {
	mu    sync.Mutex
	dir   string
	State *State
}

func Load(dir string) (*Store, error) {
	data, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("state is corrupt: %w", err)
	}
	if state.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported state schema %d", state.SchemaVersion)
	}
	return &Store{dir: dir, State: &state}, nil
}

// writeFile replaces path atomically with mode 0600.
func writeFile(path string, data []byte) error { return writeFileMode(path, data, 0o600) }

// writeFileMode replaces path atomically with a new file of the given mode.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".pending"
	_ = os.Remove(temporary)
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	file, err := os.Open(temporary)
	if err == nil {
		_ = file.Sync()
		file.Close()
	}
	return os.Rename(temporary, path)
}

// Save writes the current state; the caller holds mu.
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, StateFile), data)
}

func (s *Store) Lock()   { s.mu.Lock() }
func (s *Store) Unlock() { s.mu.Unlock() }
func (s *Store) Dir() string {
	return s.dir
}

// refreshLimit recomputes OverLimit after usage or the limit changed.
func (u *User) refreshLimit() {
	u.OverLimit = u.DataLimitBytes > 0 && u.UsageBytes >= u.DataLimitBytes
}
