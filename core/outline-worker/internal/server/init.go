// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultHandshake is the public TLS 1.3 site whose handshake VLESS-REALITY borrows.
const DefaultHandshake = "www.googletagmanager.com"

type InitOptions struct {
	Name     string
	Hostname string
	// DetectHostname finds the server's public address when Hostname is empty.
	DetectHostname func() (string, error)
	// PortFree reports whether a port can be bound; tests replace it.
	PortFree func(network string, port uint16) bool
}

// portFree reports whether a port can be bound where the server will listen. In production
// that is every address, so it tries the dual-stack wildcard and the IPv4 one: Windows reserves
// port ranges per IP version, so a port free on [::] can still be refused on 0.0.0.0 or
// 127.0.0.1. Tests listen on loopback only, so they check just that address, which also keeps
// Windows Defender Firewall from asking about every freshly built test binary.
func portFree(network string, port uint16) bool {
	addresses := []string{fmt.Sprintf(":%d", port), fmt.Sprintf("0.0.0.0:%d", port)}
	if ip := net.ParseIP(listenAddress); ip != nil && ip.IsLoopback() {
		addresses = []string{net.JoinHostPort(listenAddress, fmt.Sprint(port))}
	}
	for _, address := range addresses {
		switch network {
		case "tcp":
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return false
			}
			listener.Close()
		case "udp":
			conn, err := net.ListenPacket("udp", address)
			if err != nil {
				return false
			}
			conn.Close()
		}
	}
	return true
}

func pickPort(used map[uint16]bool, free func(string, uint16) bool, networks ...string) (uint16, error) {
	for attempt := 0; attempt < 200; attempt++ {
		port := uint16(randomInt(10_000, 32_000))
		if used[port] {
			continue
		}
		ok := true
		for _, network := range networks {
			ok = ok && free(network, port)
		}
		if ok {
			used[port] = true
			return port, nil
		}
	}
	return 0, errors.New("could not find a free port")
}

func selfSignedCertificate(hostname string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial := new(big.Int).SetBytes(random(16))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if addr, err := netip.ParseAddr(hostname); err == nil {
		template.IPAddresses = []net.IP{addr.AsSlice()}
	} else {
		template.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM), nil
}

// CertSHA256 returns the uppercase hex SHA-256 of the API certificate (what clients pin).
func (s *State) CertSHA256() (string, error) {
	cert, err := tls.X509KeyPair([]byte(s.API.CertPEM), []byte(s.API.KeyPEM))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// NewState creates a server with fresh keys, random ports and default rules. Only Shadowsocks
// (Outline-compatible) is on; the other protocols get their keys and ports now and stay off
// until an administrator turns them on.
func NewState(options InitOptions) (*State, error) {
	free := options.PortFree
	if free == nil {
		free = portFree
	}
	hostname := strings.TrimSpace(options.Hostname)
	if hostname == "" && options.DetectHostname != nil {
		detected, err := options.DetectHostname()
		if err != nil {
			return nil, fmt.Errorf("could not detect this server's public address (%v); pass --hostname", err)
		}
		hostname = detected
	}
	if hostname == "" {
		return nil, errors.New("the server's public address is required (--hostname)")
	}
	if err := ValidHostname(hostname); err != nil {
		return nil, err
	}
	name := options.Name
	if name == "" {
		name = "Ghostlink server"
	}
	if err := ValidName(name); err != nil {
		return nil, err
	}
	used := map[uint16]bool{}
	ports := make([]uint16, 5)
	for i, networks := range [][]string{{"tcp"}, {"tcp", "udp"}, {"tcp"}, {"udp"}, {"udp"}} {
		port, err := pickPort(used, free, networks...)
		if err != nil {
			return nil, err
		}
		ports[i] = port
	}
	certPEM, keyPEM, err := selfSignedCertificate(hostname)
	if err != nil {
		return nil, err
	}
	realityPrivate, realityPublic := realityKeyPair()
	wgPrivate, wgPublic := wireGuardKeyPair()
	awgPrivate, awgPublic := wireGuardKeyPair()
	return &State{
		SchemaVersion: SchemaVersion,
		Name:          name,
		Hostname:      hostname,
		CreatedUnix:   time.Now().Unix(),
		API: APIConfig{
			Port: ports[0], Secret: base64.RawURLEncoding.EncodeToString(random(16)),
			CertPEM: certPEM, KeyPEM: keyPEM,
		},
		Shadowsocks: ShadowsocksServer{Enabled: true, Port: ports[1], Method: "chacha20-ietf-poly1305"},
		VLESS: VLESSServer{
			Enabled: false, Port: ports[2], PrivateKey: realityPrivate, PublicKey: realityPublic,
			ShortID: hex.EncodeToString(random(8)), Handshake: DefaultHandshake,
		},
		WireGuard: WireGuardServer{Enabled: false, Port: ports[3], PrivateKey: wgPrivate, PublicKey: wgPublic, Subnet: "10.77.0.0/20"},
		AmneziaWG: AmneziaWGServer{
			WireGuardServer: WireGuardServer{Enabled: false, Port: ports[4], PrivateKey: awgPrivate, PublicKey: awgPublic, Subnet: "10.78.0.0/20"},
			Params:          newAWGParams(),
		},
		Rules: Rules{BlockSMTP: true, BlockedDomains: []string{}, BlockedIPs: []string{}, BlockedPorts: []string{}},
		Users: []*User{},
	}, nil
}

// Initialize loads the server in dir, creating it on first use. A non-empty hostname replaces
// the stored one. It always rewrites the management key file and reports whether it created
// the server.
func Initialize(dir string, options InitOptions) (*Store, bool, error) {
	store, err := Load(dir)
	created := false
	free := options.PortFree
	if free == nil {
		free = portFree
	}
	switch {
	case err == nil:
		if changed, err := store.State.ensureDashboard(free); err != nil {
			return nil, false, err
		} else if changed {
			if err := store.Save(); err != nil {
				return nil, false, err
			}
		}
		// Apple keys keep the identity they were created with, even if their user is renamed.
		if store.State.pinIdentities(time.Now()) {
			if err := store.Save(); err != nil {
				return nil, false, err
			}
		}
		if host := strings.TrimSpace(options.Hostname); host != "" && host != store.State.Hostname {
			if err := ValidHostname(host); err != nil {
				return nil, false, err
			}
			store.State.Hostname = host
			// IKEv2/IPsec profiles name the new address, so the server certificate must too
			// (as when the address is changed through the API).
			if store.State.IPsec.CAPEM != "" {
				if err := store.State.ensureIPsecPKI(time.Now(), free); err != nil {
					return nil, false, err
				}
			}
			if err := store.Save(); err != nil {
				return nil, false, err
			}
		}
	case errors.Is(err, fs.ErrNotExist):
		state, err := NewState(options)
		if err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, false, err
		}
		if _, err := state.ensureDashboard(free); err != nil {
			return nil, false, err
		}
		store = &Store{dir: dir, State: state}
		if err := store.Save(); err != nil {
			return nil, false, err
		}
		created = true
	default:
		return nil, false, err
	}
	if err := store.WriteManagementKey(); err != nil {
		return nil, false, err
	}
	return store, created, nil
}

// WriteManagementKey stores the management key next to the state for `show-key`.
func (s *Store) WriteManagementKey() error {
	fingerprint, err := s.State.CertSHA256()
	if err != nil {
		return err
	}
	data, err := json.Marshal(s.State.ManagementKey(fingerprint))
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, ManagementKeyFile), append(data, '\n'))
}
