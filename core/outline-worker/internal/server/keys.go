// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/crypto/curve25519"
)

const clientMTU = 1376

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS random source never fails in practice; continuing would be unsafe
	}
	return b
}

func randomInt(lo, hi int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		panic(err)
	}
	return lo + int(n.Int64())
}

// x25519 returns a clamped private key and its public key.
func x25519() ([]byte, []byte) {
	private := random(32)
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return private, public
}

func wireGuardKeyPair() (string, string) {
	private, public := x25519()
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)
}

func realityKeyPair() (string, string) {
	private, public := x25519()
	return base64.RawURLEncoding.EncodeToString(private), base64.RawURLEncoding.EncodeToString(public)
}

// newAWGParams draws AmneziaWG 2.0 parameters compatible with current Amnezia clients:
// junk packets, distinct S1/S2 (S1+56 != S2), small S3/S4 and four disjoint header ranges.
func newAWGParams() AWGParams {
	jmin := randomInt(8, 16)
	s1 := randomInt(15, 150)
	s2 := randomInt(15, 150)
	for s1+56 == s2 {
		s2 = randomInt(15, 150)
	}
	quarters := []int{0, 1, 2, 3}
	for i := range quarters {
		j := randomInt(i, 3)
		quarters[i], quarters[j] = quarters[j], quarters[i]
	}
	headers := make([]string, 4)
	const span = 1_000_000_000
	for i, q := range quarters {
		lo := 5 + q*span + randomInt(0, span/2)
		headers[i] = fmt.Sprintf("%d-%d", lo, lo+randomInt(10_000, 1_000_000))
	}
	return AWGParams{
		Jc: randomInt(4, 6), Jmin: jmin, Jmax: jmin + randomInt(40, 90),
		S1: s1, S2: s2, S3: randomInt(8, 32), S4: randomInt(4, 16),
		H1: headers[0], H2: headers[1], H3: headers[2], H4: headers[3],
		I1: "<r 32>",
	}
}

// uapi returns the amneziawg-go UAPI parameter map.
func (p AWGParams) uapi() map[string]string {
	m := map[string]string{
		"jc": fmt.Sprint(p.Jc), "jmin": fmt.Sprint(p.Jmin), "jmax": fmt.Sprint(p.Jmax),
		"s1": fmt.Sprint(p.S1), "s2": fmt.Sprint(p.S2), "s3": fmt.Sprint(p.S3), "s4": fmt.Sprint(p.S4),
		"h1": p.H1, "h2": p.H2, "h3": p.H3, "h4": p.H4,
	}
	if p.I1 != "" {
		m["i1"] = p.I1
	}
	return m
}

// conf returns the .conf [Interface] lines in amneziawg-tools syntax.
func (p AWGParams) conf() string {
	lines := fmt.Sprintf("Jc = %d\nJmin = %d\nJmax = %d\nS1 = %d\nS2 = %d\nS3 = %d\nS4 = %d\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n",
		p.Jc, p.Jmin, p.Jmax, p.S1, p.S2, p.S3, p.S4, p.H1, p.H2, p.H3, p.H4)
	if p.I1 != "" {
		lines += "I1 = " + p.I1 + "\n"
	}
	return lines
}

// NewKey creates key material for one protocol on a user.
func (s *State) NewKey(user *User, protocol string) (*Key, error) {
	return s.NewKeyWith(user, protocol, KeyOptions{})
}

// NewKeyWith also takes the IKEv2/IPsec authentication method and identifiers.
func (s *State) NewKeyWith(user *User, protocol string, options KeyOptions) (*Key, error) {
	if len(user.Keys) >= MaxKeysPerUser {
		return nil, fmt.Errorf("a user can have at most %d keys", MaxKeysPerUser)
	}
	options, err := options.validate(protocol)
	if err != nil {
		return nil, err
	}
	key := &Key{ID: s.newID(), Protocol: protocol, CreatedUnix: time.Now().Unix(), Auth: options.Auth,
		ServerAddress: options.ServerAddress, RemoteID: options.RemoteID, LocalID: options.LocalID}
	switch protocol {
	case IKEv2, IPsec:
		if s.IPsec.CAPEM == "" {
			return nil, errIPsecNotRunning
		}
		if options.LocalID != "" {
			for _, u := range s.Users {
				for _, k := range u.Keys {
					if k.isApple() && strings.EqualFold(k.localIdentity(u), options.LocalID) {
						return nil, fmt.Errorf("identifier %q is already used by another key", options.LocalID)
					}
				}
			}
		}
		key.Secret = base64.RawURLEncoding.EncodeToString(random(15))
		if key.Auth == AuthCertificate {
			if err := s.issueClientCert(user, key, time.Now()); err != nil {
				return nil, err
			}
		}
	case Shadowsocks:
		key.Password = base64.RawURLEncoding.EncodeToString(random(24))
	case VLESS:
		key.UUID = uuid.Must(uuid.NewV4()).String()
	case WireGuard, AmneziaWG:
		subnet := s.WireGuard.Subnet
		if protocol == AmneziaWG {
			subnet = s.AmneziaWG.Subnet
		}
		address, err := s.nextAddress(subnet)
		if err != nil {
			return nil, err
		}
		key.PrivateKey, key.PublicKey = wireGuardKeyPair()
		key.PresharedKey = base64.StdEncoding.EncodeToString(random(32))
		key.Address = address
	default:
		return nil, fmt.Errorf("unknown protocol %q", protocol)
	}
	return key, nil
}

// IssuedKey is what a client imports.
type IssuedKey struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	// IKEv2/IPsec keys are installed with an Apple profile (GET …/profile) instead of a key.
	Auth     string `json:"auth,omitempty"`
	Identity string `json:"identity,omitempty"`
	Address  string `json:"server_address,omitempty"`
	RemoteID string `json:"remote_identifier,omitempty"`
	Warning  string `json:"warning,omitempty"`
	// CertificatePassword opens the certificate in a profile saved with prompt_password=1.
	CertificatePassword string `json:"certificate_password,omitempty"`
	// Single-line key for Ghostlink (ss://, vless:// or Amnezia-compatible vpn://).
	AccessKey string `json:"access_key"`
	// Native configuration for WireGuard/AmneziaWG apps.
	Config string `json:"config,omitempty"`
}

func endpointHost(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return "[" + host + "]"
	}
	return host
}

func (s *State) serverTunnelIP(protocol string) string {
	subnet := s.WireGuard.Subnet
	if protocol == AmneziaWG {
		subnet = s.AmneziaWG.Subnet
	}
	prefix, _ := netip.ParsePrefix(subnet)
	return prefix.Masked().Addr().Next().String()
}

// wireGuardServer returns the server half (keys, port, subnet) for a WireGuard-family key.
func (s *State) wireGuardServer(protocol string) WireGuardServer {
	if protocol == AmneziaWG {
		return s.AmneziaWG.WireGuardServer
	}
	return s.WireGuard
}

func (s *State) wireGuardConf(key *Key) string {
	server, params := s.wireGuardServer(key.Protocol), ""
	if key.Protocol == AmneziaWG {
		params = s.AmneziaWG.Params.conf()
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\nMTU = %d\n%s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		key.PrivateKey, key.Address, s.serverTunnelIP(key.Protocol), clientMTU, params,
		server.PublicKey, key.PresharedKey, endpointHost(s.Hostname), server.Port)
}

// amneziaKey encodes a document like Amnezia's exporter: qCompress (length + zlib), base64url.
func amneziaKey(document any) (string, error) {
	raw, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(raw)))
	buffer.Write(header)
	writer, err := zlib.NewWriterLevel(&buffer, 8)
	if err != nil {
		return "", err
	}
	writer.Write(raw)
	writer.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

func (s *State) amneziaWireGuardKey(user *User, key *Key, conf string) (string, error) {
	server := s.wireGuardServer(key.Protocol)
	container, sub := "amnezia-wireguard", "wireguard"
	if key.Protocol == AmneziaWG {
		container, sub = "amnezia-awg2", "awg"
	}
	last := map[string]any{
		"config": conf, "hostName": s.Hostname, "port": int(server.Port), "client_ip": key.Address,
		"client_priv_key": key.PrivateKey, "client_pub_key": key.PublicKey, "server_pub_key": server.PublicKey,
		"psk_key": key.PresharedKey, "allowed_ips": []string{"0.0.0.0/0", "::/0"},
		"persistent_keep_alive": "25", "mtu": fmt.Sprint(clientMTU),
	}
	if key.Protocol == AmneziaWG {
		p := s.AmneziaWG.Params
		for name, value := range map[string]any{"Jc": p.Jc, "Jmin": p.Jmin, "Jmax": p.Jmax, "S1": p.S1, "S2": p.S2, "S3": p.S3, "S4": p.S4,
			"H1": p.H1, "H2": p.H2, "H3": p.H3, "H4": p.H4, "I1": p.I1} {
			last[name] = fmt.Sprint(value)
		}
	}
	lastJSON, _ := json.Marshal(last)
	return amneziaKey(map[string]any{
		"containers": []any{map[string]any{
			"container": container,
			sub:         map[string]any{"last_config": string(lastJSON), "port": fmt.Sprint(server.Port), "transport_proto": "udp"},
		}},
		"defaultContainer": container,
		"description":      user.Name + " @ " + s.Name,
		"dns1":             "1.1.1.1",
		"dns2":             "1.0.0.1",
		"hostName":         s.Hostname,
	})
}

// Render builds the client-facing key for one stored key.
func (s *State) Render(user *User, key *Key) (IssuedKey, error) {
	label := url.PathEscape(user.Name + " @ " + s.Name)
	result := IssuedKey{ID: key.ID, Protocol: key.Protocol}
	switch key.Protocol {
	case Shadowsocks:
		credential := base64.RawURLEncoding.EncodeToString([]byte(s.Shadowsocks.Method + ":" + key.Password))
		result.AccessKey = fmt.Sprintf("ss://%s@%s:%d/?outline=1#%s", credential, endpointHost(s.Hostname), s.Shadowsocks.Port, label)
	case VLESS:
		query := url.Values{"type": {"tcp"}, "security": {"reality"}, "sni": {s.VLESS.Handshake}, "fp": {"chrome"},
			"pbk": {s.VLESS.PublicKey}, "sid": {s.VLESS.ShortID}, "flow": {"xtls-rprx-vision"}, "encryption": {"none"}}
		result.AccessKey = fmt.Sprintf("vless://%s@%s:%d?%s#%s", key.UUID, endpointHost(s.Hostname), s.VLESS.Port, query.Encode(), label)
	case WireGuard, AmneziaWG:
		result.Config = s.wireGuardConf(key)
		encoded, err := s.amneziaWireGuardKey(user, key, result.Config)
		if err != nil {
			return IssuedKey{}, err
		}
		result.AccessKey = encoded
	case IKEv2, IPsec:
		result.Auth, result.Identity = key.Auth, key.localIdentity(user)
		result.Address, result.RemoteID = key.ServerAddress, key.RemoteID
		if result.Address == "" {
			result.Address = s.Hostname
		}
		if result.RemoteID == "" && key.Protocol == IKEv2 {
			result.RemoteID = s.serverIdentity()
		}
		if key.Auth == AuthPSK {
			result.Warning = pskWarning
		}
		if key.Auth == AuthCertificate {
			result.CertificatePassword = key.P12Password
		}
	default:
		return IssuedKey{}, errors.New("unknown protocol")
	}
	return result, nil
}

// ManagementKey is printed at install time and pasted into the Ghostlink app.
type ManagementKey struct {
	APIURL     string `json:"apiUrl"`
	CertSHA256 string `json:"certSha256"`
}

func (s *State) ManagementKey(certSHA256 string) ManagementKey {
	return ManagementKey{
		APIURL:     fmt.Sprintf("https://%s:%d/%s", endpointHost(s.Hostname), s.API.Port, s.API.Secret),
		CertSHA256: strings.ToUpper(certSHA256),
	}
}
