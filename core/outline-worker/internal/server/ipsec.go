// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// IPsecDir holds the files shared with the IPsec agent.
const IPsecDir = "ipsec"

// ipsecDNSTag names the DNS listener IPsec clients reach through their pool gateway.
const ipsecDNSTag = "ipsec-dns"

// statusFresh is how recent the agent's status must be for the component to count as running.
const statusFresh = 20 * time.Second

var errIPsecNotRunning = errors.New("start the IPsec component first: sudo ghostlink-server ipsec enable")

func (s *State) appleEnabled() bool { return s.IPsec.IKEv2Enabled || s.IPsec.IPsecEnabled }

// IPsecDesired builds the agent's configuration: identities of active users only, NT hashes for
// EAP, and the firewall the pools are held to.
func (s *State) IPsecDesired(now time.Time) (ipsecproto.Desired, error) {
	desired := ipsecproto.Desired{Version: ipsecproto.Version, Generation: now.UnixNano(), Allowed: []string{}}
	if !s.appleEnabled() || s.IPsec.CAPEM == "" {
		return desired, nil
	}
	crl, err := s.CRL(now)
	if err != nil {
		return desired, err
	}
	desired.CA, desired.Server, desired.ServerKey, desired.CRL = s.IPsec.CAPEM, s.IPsec.ServerPEM, s.IPsec.ServerKeyPEM, crl
	desired.ServerID = s.serverIdentity()
	if s.IPsec.IKEv2Enabled {
		desired.IKEv2 = &ipsecproto.IKEv2{Pool: ikev2Pool, Gateway: ikev2Gateway, EAP: []ipsecproto.NTLMSecret{}}
	}
	if s.IPsec.IPsecEnabled {
		desired.IKEv1 = &ipsecproto.IKEv1{Pool: ipsecPool, Gateway: ipsecGateway, XAuth: []ipsecproto.XAuthSecret{}}
	}
	for _, u := range s.activeUsers() {
		for _, k := range u.Keys {
			identity := k.localIdentity(u)
			switch {
			case k.Protocol == IKEv2 && desired.IKEv2 != nil:
				desired.Allowed = append(desired.Allowed, identity)
				if k.Auth == AuthCertificate {
					desired.IKEv2.Certificates = true
				} else {
					desired.IKEv2.EAP = append(desired.IKEv2.EAP, ipsecproto.NTLMSecret{ID: identity, NTHash: ntHash(k.Secret)})
				}
			case k.Protocol == IPsec && desired.IKEv1 != nil:
				desired.Allowed = append(desired.Allowed, identity)
				desired.IKEv1.XAuth = append(desired.IKEv1.XAuth, ipsecproto.XAuthSecret{ID: identity, Password: k.Secret})
				if k.Auth == AuthPSK {
					desired.IKEv1.Group, desired.IKEv1.PSK = s.IPsec.GroupName, s.IPsec.PSK
				} else {
					desired.IKEv1.Certificates = true
				}
			}
		}
	}
	firewall := ipsecproto.Firewall{
		Internal: internalRanges, Blocked: s.Rules.BlockedIPs, Ports: append([]string{}, s.Rules.BlockedPorts...),
		BlockSMTP: s.Rules.BlockSMTP, DNSPort: s.IPsec.DNSPort,
	}
	if addr, err := netip.ParseAddr(s.Hostname); err == nil {
		firewall.ServerIP = addr.String()
	}
	if firewall.Blocked == nil {
		firewall.Blocked = []string{}
	}
	desired.Firewall = firewall
	return desired, desired.Validate()
}

// WriteIPsecDesired gives the agent the current configuration (also refreshing the CRL).
func (svc *Service) WriteIPsecDesired(now time.Time) error {
	var desired ipsecproto.Desired
	var err error
	svc.Read(func(s *State) { desired, err = s.IPsecDesired(now) })
	if err != nil {
		return err
	}
	// The agent runs as root with no file capabilities, in this account's group: the directory
	// and the settings are shared with the group only.
	dir := filepath.Join(svc.store.Dir(), IPsecDir)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		return err
	}
	data, err := json.MarshalIndent(desired, "", "  ")
	if err != nil {
		return err
	}
	return writeFileMode(filepath.Join(dir, ipsecproto.DesiredFile), data, 0o640)
}

// IPsecStatus reads the agent's report; ok is false when it is missing or stale.
func (svc *Service) IPsecStatus(now time.Time) (ipsecproto.Status, bool) {
	var status ipsecproto.Status
	data, err := os.ReadFile(filepath.Join(svc.store.Dir(), IPsecDir, ipsecproto.StatusFile))
	if err != nil || json.Unmarshal(data, &status) != nil {
		return status, false
	}
	return status, status.Running && now.Sub(time.Unix(status.UpdatedUnix, 0)) < statusFresh
}

// recordIPsec turns the agent's per-SA byte counters into per-user traffic.
func (svc *Service) recordIPsec(now time.Time) {
	status, fresh := svc.IPsecStatus(now)
	if !fresh {
		return
	}
	users := map[string]string{} // identity -> user tag
	svc.Read(func(s *State) {
		for _, u := range s.Users {
			for _, k := range u.Keys {
				if k.isApple() {
					users[strings.ToLower(k.localIdentity(u))] = u.Tag()
				}
			}
		}
	})
	seen := map[string][2]uint64{}
	for _, sa := range status.SAs {
		tag, ok := users[strings.ToLower(sa.Identity)]
		if !ok {
			continue
		}
		protocol := IKEv2
		if sa.Version == 1 {
			protocol = IPsec
		}
		remote := strings.Trim(sa.Remote, "[]")
		for _, child := range sa.Children {
			key := sa.UniqueID + "/" + child.UniqueID
			previous := svc.ipsecSeen[key]
			seen[key] = [2]uint64{child.BytesIn, child.BytesOut}
			var up, down uint64
			if child.BytesIn >= previous[0] {
				up = child.BytesIn - previous[0]
			}
			if child.BytesOut >= previous[1] {
				down = child.BytesOut - previous[1]
			}
			svc.monitor.AddExternal(tag, protocol, up, down, remote, now)
		}
		if len(sa.Children) == 0 {
			svc.monitor.AddExternal(tag, protocol, 0, 0, remote, now)
		}
	}
	svc.ipsecSeen = seen
}

// ipsecComponent describes the component for the API and the app.
type ipsecComponent struct {
	Running bool     `json:"running"`
	Error   string   `json:"error,omitempty"`
	Plugins []string `json:"plugins,omitempty"`
	Online  int      `json:"connections"`
	Ports   string   `json:"ports"`
}

func (svc *Service) ipsecComponent(now time.Time) ipsecComponent {
	status, fresh := svc.IPsecStatus(now)
	component := ipsecComponent{Running: fresh, Ports: "UDP 500 and 4500"}
	if fresh {
		component.Error, component.Plugins, component.Online = status.Error, status.Plugins, len(status.SAs)
	}
	return component
}

// KeyOptions are the IKEv2/IPsec choices made when a key is created.
type KeyOptions struct {
	Auth          string
	ServerAddress string
	RemoteID      string
	LocalID       string
}

func (o KeyOptions) validate(protocol string) (KeyOptions, error) {
	switch protocol {
	case IKEv2:
		if o.Auth == "" {
			o.Auth = AuthEAP
		}
		if o.Auth != AuthEAP && o.Auth != AuthCertificate {
			return o, errors.New("IKEv2 keys use auth eap (username and password) or certificate")
		}
	case IPsec:
		if o.Auth == "" {
			o.Auth = AuthCertificate
		}
		if o.Auth != AuthCertificate && o.Auth != AuthPSK {
			return o, errors.New("IPsec keys use auth certificate or psk")
		}
	default:
		if o != (KeyOptions{}) {
			return o, fmt.Errorf("%s keys take no authentication options", protocol)
		}
		return o, nil
	}
	if o.ServerAddress != "" {
		if err := ValidHostname(o.ServerAddress); err != nil {
			return o, err
		}
	}
	if o.LocalID != "" && !ipsecproto.ValidIdentity(o.LocalID) {
		return o, fmt.Errorf("local identifier %q must start with a letter or digit and use letters, digits and . _ @ - only (not an IP address)", o.LocalID)
	}
	if o.RemoteID != "" {
		if protocol != IKEv2 {
			return o, errors.New("a remote identifier can only be set for IKEv2 keys")
		}
		if !ipsecproto.ValidServerID(o.RemoteID) {
			return o, fmt.Errorf("remote identifier %q must be a DNS name or IP address of this server", o.RemoteID)
		}
	}
	return o, nil
}

// pskWarning is returned with every IPsec pre-shared-key key.
const pskWarning = "IPsec with a pre-shared key is weak: everyone with this server's group key can impersonate the server to other users, and aggressive mode exposes the key to offline guessing. Prefer certificates or IKEv2."
