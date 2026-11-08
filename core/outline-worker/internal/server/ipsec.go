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

// agentIdentity is the key's identity, if the agent will accept it. The agent refuses a whole
// file for one identity it does not like, and then no user's change would arrive any more, so a
// key with such an identity (only a hand-edited state has one) is left out: it cannot connect.
func (k *Key) agentIdentity(user *User) (string, bool) {
	identity := k.localIdentity(user)
	return identity, k.isApple() && ipsecproto.ValidIdentity(identity)
}

// IPsecDesired builds the agent's configuration: identities of active users only, NT hashes for
// EAP, and the firewall the pools are held to.
func (s *State) IPsecDesired(now time.Time) (ipsecproto.Desired, error) {
	return s.signIPsec(s.ipsecSettings(now), now)
}

// signIPsec adds the CRL, which is signed with the CA key (the slow part), and validates.
func (s *State) signIPsec(desired ipsecproto.Desired, now time.Time) (ipsecproto.Desired, error) {
	if desired.CA != "" {
		crl, err := s.CRL(now)
		if err != nil {
			return desired, err
		}
		desired.CRL = crl
	}
	return desired, desired.Validate()
}

// ipsecFingerprint identifies what the agent would be told, leaving out what changes with every
// write: the generation, and the CRL's dates and signature (the CRL's entries are included).
func (s *State) ipsecFingerprint(desired ipsecproto.Desired) string {
	desired.Generation, desired.CRL = 0, ""
	data, _ := json.Marshal(desired)
	var holds strings.Builder
	for _, e := range s.crlEntries(time.Time{}) {
		fmt.Fprintf(&holds, "%s/%d,", e.SerialNumber, e.ReasonCode)
	}
	return string(data) + "|" + holds.String()
}

// ipsecSettings is IPsecDesired without the CRL.
func (s *State) ipsecSettings(now time.Time) ipsecproto.Desired {
	desired := ipsecproto.Desired{Version: ipsecproto.Version, Generation: now.UnixNano(), Allowed: []string{}}
	if !s.appleEnabled() || s.IPsec.CAPEM == "" {
		return desired
	}
	desired.CA, desired.Server, desired.ServerKey = s.IPsec.CAPEM, s.IPsec.ServerPEM, s.IPsec.ServerKeyPEM
	desired.ServerID = s.serverIdentity()
	if s.IPsec.IKEv2Enabled {
		desired.IKEv2 = &ipsecproto.IKEv2{Pool: ikev2Pool, Gateway: ikev2Gateway, EAP: []ipsecproto.NTLMSecret{}}
	}
	if s.IPsec.IPsecEnabled {
		desired.IKEv1 = &ipsecproto.IKEv1{Pool: ipsecPool, Gateway: ipsecGateway, XAuth: []ipsecproto.XAuthSecret{}}
	}
	for _, u := range s.activeUsers() {
		for _, k := range u.Keys {
			identity, ok := k.agentIdentity(u)
			if !ok {
				continue
			}
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
	// Speed limits of active clients that have IKEv2/IPsec keys (the agent caps their sessions).
	for _, u := range s.activeUsers() {
		bps := s.SpeedLimitBps(u)
		if bps <= 0 {
			continue
		}
		limit := ipsecproto.SpeedLimit{Name: u.Tag(), BytesPerSecond: bps}
		for _, k := range u.Keys {
			if identity, ok := k.agentIdentity(u); ok && ((k.Protocol == IKEv2 && desired.IKEv2 != nil) || (k.Protocol == IPsec && desired.IKEv1 != nil)) {
				limit.Identities = append(limit.Identities, identity)
			}
		}
		if len(limit.Identities) > 0 {
			desired.SpeedLimits = append(desired.SpeedLimits, limit)
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
	return desired
}

// WriteIPsecDesired gives the agent the current configuration, also refreshing the CRL.
func (svc *Service) WriteIPsecDesired(now time.Time) error { return svc.writeIPsecDesired(now, true) }

// writeIPsecDesired writes the agent's configuration. Unless force is set, it writes nothing
// when the agent would be told what it was told last (apart from the CRL's dates): each write
// makes the agent reload strongSwan and its firewall, and every saved change calls this, the
// 30-second usage accounting included. Writes go one at a time, each taking its snapshot after
// the one before it finished, so the file always ends up holding the newest state.
func (svc *Service) writeIPsecDesired(now time.Time, force bool) error {
	svc.ipsecMu.Lock()
	defer svc.ipsecMu.Unlock()
	var desired ipsecproto.Desired
	var fingerprint string
	var unchanged bool
	var err error
	svc.Read(func(s *State) {
		desired = s.ipsecSettings(now)
		fingerprint = s.ipsecFingerprint(desired)
		if unchanged = !force && fingerprint == svc.ipsecWritten; unchanged {
			return
		}
		desired, err = s.signIPsec(desired, now)
	})
	if err != nil || unchanged {
		return err
	}
	svc.ipsecWritten = ""
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
	if err := writeFileMode(filepath.Join(dir, ipsecproto.DesiredFile), data, 0o640); err != nil {
		return err
	}
	svc.ipsecWritten = fingerprint
	return nil
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

// ipsecBaseline is a CHILD_SA's byte counters at the last report that had it, and when.
type ipsecBaseline struct {
	in, out uint64
	at      time.Time
}

// ipsecKeep is how long a child's counters are remembered after it was last reported. The agent
// lists a session its enforcement ended only a few seconds later, as a closed child (which it
// keeps reporting for a minute), and a failed listing leaves sessions out of a report: the
// final counters must still find their baseline, or the whole total would be counted again.
const ipsecKeep = 3 * time.Minute

// recordIPsec turns the agent's per-SA byte counters into per-user traffic. It runs from Run
// only (and tests), so it needs no lock.
func (svc *Service) recordIPsec(now time.Time) {
	status, fresh := svc.IPsecStatus(now)
	if !fresh {
		return
	}
	// The counters are totals since each session began, and the agent and its sessions outlive
	// this server. The first report after a start (or after a long gap) therefore only sets the
	// baseline: counting it would add every live session's whole total a second time.
	baseline := svc.ipsecLast.IsZero() || now.Sub(svc.ipsecLast) > ipsecKeep
	svc.ipsecLast = now
	if baseline {
		svc.ipsecSeen = map[string]ipsecBaseline{}
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
	// Counters are per CHILD_SA (its unique ID survives an IKE rekey). A child is counted
	// against its last known counters once per report, whether still up or just closed.
	counted := map[string]bool{}
	for i, sa := range append(append([]ipsecproto.SA{}, status.SAs...), status.Closed...) {
		tag, ok := users[strings.ToLower(sa.Identity)]
		if !ok {
			continue
		}
		ended := i >= len(status.SAs)
		protocol := IKEv2
		if sa.Version == 1 {
			protocol = IPsec
		}
		remote := strings.Trim(sa.Remote, "[]")
		for _, child := range sa.Children {
			key := child.UniqueID
			if counted[key] || key == "" {
				continue
			}
			counted[key] = true
			previous := svc.ipsecSeen[key]
			svc.ipsecSeen[key] = ipsecBaseline{child.BytesIn, child.BytesOut, now}
			var up, down uint64
			if !baseline {
				if child.BytesIn >= previous.in {
					up = child.BytesIn - previous.in
				}
				if child.BytesOut >= previous.out {
					down = child.BytesOut - previous.out
				}
			}
			// A closed child stays in the report for a minute. Its final bytes count once, but
			// reporting it again must not keep the client looking present after it left.
			if ended && up+down == 0 {
				continue
			}
			svc.monitor.AddExternal(tag, protocol, up, down, remote, now)
		}
		if len(sa.Children) == 0 && !ended {
			svc.monitor.AddExternal(tag, protocol, 0, 0, remote, now)
		}
	}
	for key, b := range svc.ipsecSeen {
		if now.Sub(b.at) > ipsecKeep {
			delete(svc.ipsecSeen, key)
		}
	}
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
