// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Importing an Outline server (Jigsaw's shadowbox) that ran on this machine: every Outline
// access key becomes a Ghostlink client whose Shadowsocks key has the same password, port and
// cipher, so the ss:// keys people already use keep working.

// outlineCiphers are the Shadowsocks ciphers Outline offers; Ghostlink serves all of them.
var outlineCiphers = []string{"chacha20-ietf-poly1305", "aes-256-gcm", "aes-192-gcm", "aes-128-gcm"}

const (
	outlineDefaultCipher = "chacha20-ietf-poly1305"
	maxOutlineBytes      = 4 << 20
)

// outlineID is an access key id, a string in Outline's files (a number in very old ones).
type outlineID string

func (id *outlineID) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) == nil {
		*id = outlineID(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return errors.New("an access key id is neither text nor a number")
	}
	*id = outlineID(number.String())
	return nil
}

type outlineDataLimit struct {
	Bytes float64 `json:"bytes"`
}

func (d *outlineDataLimit) bytes() (uint64, bool) {
	if d == nil || d.Bytes < 0 || math.IsNaN(d.Bytes) {
		return 0, false
	}
	return uint64(math.Min(d.Bytes, math.MaxInt64)), true
}

// outlineKey is one entry of shadowbox_config.json's accessKeys.
type outlineKey struct {
	ID        outlineID         `json:"id"`
	Name      string            `json:"name"`
	Password  string            `json:"password"`
	Port      int               `json:"port"`
	Method    string            `json:"encryptionMethod"`
	DataLimit *outlineDataLimit `json:"dataLimit"`
}

// outlineKeys is shadowbox_config.json.
type outlineKeys struct {
	AccessKeys []outlineKey `json:"accessKeys"`
}

// outlineServer is shadowbox_server_config.json.
type outlineServer struct {
	Name               string            `json:"name"`
	Hostname           string            `json:"hostname"`
	PortForNewKeys     int               `json:"portForNewAccessKeys"`
	AccessKeyDataLimit *outlineDataLimit `json:"accessKeyDataLimit"`
}

// outlineImport carries Outline's two files as they are.
type outlineImport struct {
	Server     json.RawMessage `json:"server"`
	AccessKeys json.RawMessage `json:"access_keys"`
	DryRun     bool            `json:"dry_run"`
}

// outlineReport says what the import does (or did). It holds no passwords.
type outlineReport struct {
	DryRun bool `json:"dry_run"`
	// Clients created, one per Outline access key, and how many kept their own ss:// key.
	Clients int `json:"clients"`
	Kept    int `json:"kept"`
	// Port and Method are the server's Shadowsocks port and cipher from now on; ExtraPorts
	// carry keys that used other ports.
	Port       uint16   `json:"port"`
	Method     string   `json:"method"`
	ExtraPorts []uint16 `json:"extra_ports,omitempty"`
	Hostname   string   `json:"hostname"`
	// HostnameChanged: the server now uses Outline's address (the management key changes).
	HostnameChanged bool   `json:"hostname_changed"`
	Name            string `json:"name"`
	// NewKeys are clients that got a new Shadowsocks key: their Outline key cannot be served.
	NewKeys []outlineNewKey `json:"new_keys,omitempty"`
	// Moved are Ghostlink ports that made way for Outline's.
	Moved    []outlineMove `json:"moved,omitempty"`
	Disabled []string      `json:"disabled,omitempty"`
	Notes    []string      `json:"notes,omitempty"`
}

type outlineNewKey struct {
	Client string `json:"client"`
	Reason string `json:"reason"`
}

type outlineMove struct {
	Service string `json:"service"`
	From    uint16 `json:"from"`
	To      uint16 `json:"to"`
	// Off: the protocol is turned off, so nothing listens on its new port until it is turned on.
	Off bool `json:"off,omitempty"`
}

var errDryRun = errors.New("dry run")

func (a *API) importOutline(r *http.Request) (int, any, error) {
	var request outlineImport
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxOutlineBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return 0, nil, InputError{fmt.Errorf("invalid request body: %v", err)}
	}
	if decoder.More() {
		return 0, nil, InputError{errors.New("invalid request body: trailing data")}
	}
	var keys outlineKeys
	var server outlineServer
	if err := json.Unmarshal(request.AccessKeys, &keys); err != nil {
		return 0, nil, InputError{fmt.Errorf("Outline's access keys (shadowbox_config.json) cannot be read: %v", err)}
	}
	if len(request.Server) > 0 && string(request.Server) != "null" {
		if err := json.Unmarshal(request.Server, &server); err != nil {
			return 0, nil, InputError{fmt.Errorf("Outline's server settings (shadowbox_server_config.json) cannot be read: %v", err)}
		}
	}
	var report outlineReport
	err := a.service.Change(func(s *State) error {
		var err error
		if report, err = s.importOutline(server, keys.AccessKeys, portFree, time.Now()); err != nil {
			return err
		}
		if request.DryRun {
			if err := s.CheckPorts(); err != nil {
				return InputError{err}
			}
			return errDryRun
		}
		return nil
	})
	switch {
	case errors.Is(err, errDryRun):
		report.DryRun = true
		return http.StatusOK, report, nil
	case err != nil:
		return 0, nil, err
	}
	if report.HostnameChanged {
		a.service.store.Lock()
		err = a.service.store.WriteManagementKey()
		a.service.store.Unlock()
		if err != nil {
			// The import is saved: failing now would tell the host script it did not happen.
			report.Notes = append(report.Notes, fmt.Sprintf("the management key file could not be rewritten for the new address (%v); write it again with: sudo ghostlink-server setup", err))
		}
	}
	return http.StatusOK, report, nil
}

// outlineCandidate is an Outline key that can keep working as it is.
type outlineCandidate struct {
	port   uint16
	method string
}

// importOutline turns Outline's access keys into clients on a server that has none.
func (s *State) importOutline(server outlineServer, keys []outlineKey, free func(string, uint16) bool, now time.Time) (outlineReport, error) {
	var report outlineReport
	if len(s.Users) > 0 {
		return report, InputError{errors.New("this server already has clients: an Outline server can only be imported into a new Ghostlink server")}
	}
	if len(keys) == 0 {
		return report, InputError{errors.New("the Outline server has no access keys to import")}
	}
	if len(keys) > MaxUsers {
		return report, InputError{fmt.Errorf("the Outline server has %d access keys; a Ghostlink server can have at most %d clients", len(keys), MaxUsers)}
	}

	// Which keys can keep their port, cipher and password, and why the others cannot. Ports
	// below 1024, such as 443, are kept too: the host script's container may listen there.
	floor := int(lowestPort())
	reasons := make([]string, len(keys))
	candidates := make([]outlineCandidate, len(keys))
	for i, k := range keys {
		method := strings.TrimSpace(k.Method)
		if method == "" {
			method = outlineDefaultCipher
		}
		switch {
		case !slices.Contains(outlineCiphers, method):
			reasons[i] = fmt.Sprintf("its cipher %q is not one Outline or Ghostlink offers", method)
		case !validOutlinePassword(k.Password):
			reasons[i] = "its password is empty, too long or not plain text"
		case k.Port < 1 || k.Port > 65535:
			reasons[i] = "it has no valid port"
		case k.Port < floor:
			reasons[i] = fmt.Sprintf("it uses port %d, and this server cannot listen below port %d", k.Port, floor)
		default:
			candidates[i] = outlineCandidate{uint16(k.Port), method}
		}
	}

	// Ghostlink ports that cannot move: the management API (its key is pinned to the port),
	// the dashboard, the mesh and IKEv2/IPsec (its DNS listener, and UDP 500 and 4500 while on).
	fixed := map[uint16]string{s.API.Port: "the management API"}
	if s.Dashboard.Port != 0 {
		fixed[s.Dashboard.Port] = "the dashboard"
	}
	if s.Mesh != nil && s.Mesh.Port != 0 {
		// Kept while the mesh is off too: turning it on again reuses its port.
		fixed[s.Mesh.Port] = "the mesh"
	}
	if s.IPsec.DNSPort != 0 {
		// Kept for IKEv2/IPsec even while it is off, so turning it on later still works.
		fixed[s.IPsec.DNSPort] = "the IKEv2/IPsec DNS listener"
	}
	if s.appleEnabled() {
		fixed[500] = "IKEv2/IPsec (UDP 500)"
		fixed[4500] = "IKEv2/IPsec (UDP 4500)"
	}
	for i, c := range candidates {
		if c.port != 0 {
			if service, clash := fixed[c.port]; clash {
				reasons[i] = fmt.Sprintf("its port %d is used by %s", c.port, service)
				candidates[i] = outlineCandidate{}
			}
		}
	}

	// The main port is the one most keys use (ties: Outline's port for new keys, then the
	// lowest); its cipher is the one most of its keys use.
	byPort := map[uint16][]int{}
	for i, c := range candidates {
		if c.port != 0 {
			byPort[c.port] = append(byPort[c.port], i)
		}
	}
	ports := make([]uint16, 0, len(byPort))
	for port := range byPort {
		ports = append(ports, port)
	}
	slices.SortFunc(ports, func(a, b uint16) int {
		if d := len(byPort[b]) - len(byPort[a]); d != 0 {
			return d
		}
		if preferred := uint16(max(0, server.PortForNewKeys)); a == preferred || b == preferred {
			if a == preferred {
				return -1
			}
			return 1
		}
		return int(a) - int(b)
	})
	methods := map[uint16]string{}
	for _, port := range ports {
		methods[port] = commonCipher(byPort[port], candidates)
		for _, i := range byPort[port] {
			if candidates[i].method != methods[port] {
				reasons[i] = fmt.Sprintf("it shares port %d with keys that use another cipher", port)
				candidates[i] = outlineCandidate{}
			}
		}
	}
	if len(ports) > 0 {
		s.Shadowsocks.Port, s.Shadowsocks.Method = ports[0], methods[ports[0]]
	}
	s.Shadowsocks.Enabled = true
	report.Port, report.Method = s.Shadowsocks.Port, s.Shadowsocks.Method

	// Ghostlink's other protocols make way for Outline's ports.
	used := map[uint16]bool{s.API.Port: true, s.Dashboard.Port: true, s.IPsec.DNSPort: true}
	if s.Mesh != nil && s.Mesh.Port != 0 {
		used[s.Mesh.Port] = true
	}
	for _, port := range ports {
		used[port] = true
	}
	// They move whether they are on or not: a protocol that is off keeps its port for when it
	// is turned on (only Shadowsocks is on in a new server).
	movable := []struct {
		name, network string
		port          *uint16
		on            bool
	}{
		{"VLESS", "tcp", &s.VLESS.Port, s.VLESS.Enabled},
		{"WireGuard", "udp", &s.WireGuard.Port, s.WireGuard.Enabled},
		{"AmneziaWG", "udp", &s.AmneziaWG.Port, s.AmneziaWG.Enabled},
	}
	for _, m := range movable {
		if _, clash := byPort[*m.port]; !clash {
			used[*m.port] = true
		}
	}
	for _, m := range movable {
		if _, clash := byPort[*m.port]; !clash {
			continue
		}
		port, err := pickPort(used, free, m.network)
		if err != nil {
			return report, err
		}
		report.Moved = append(report.Moved, outlineMove{m.name, *m.port, port, !m.on})
		*m.port = port
	}

	// The server's name and address become Outline's.
	if name := cleanName(server.Name); name != "" {
		s.Name = name
	}
	if host := strings.TrimSpace(server.Hostname); host != "" && host != s.Hostname {
		if err := ValidHostname(host); err != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("Outline's address %q is not valid here; the server keeps %s", host, s.Hostname))
		} else {
			s.Hostname, report.HostnameChanged = host, true
			if s.IPsec.CAPEM != "" {
				if err := s.ensureIPsecPKI(now, free); err != nil {
					return report, err
				}
			}
		}
	}
	report.Hostname, report.Name = s.Hostname, s.Name

	// One client per key, in Outline's order.
	defaultLimit, hasDefault := server.AccessKeyDataLimit.bytes()
	passwords := map[string]string{}
	limited := 0
	for i, k := range keys {
		u := &User{ID: s.newID(), Name: s.uniqueName(outlineKeyName(k, i)), CreatedUnix: now.Unix(), Enabled: true, Keys: []*Key{},
			Rules: Rules{BlockedDomains: []string{}, BlockedIPs: []string{}, BlockedPorts: []string{}}}
		limit, hasLimit := k.DataLimit.bytes()
		if !hasLimit {
			limit, hasLimit = defaultLimit, hasDefault
		}
		if hasLimit {
			if limit == 0 {
				// Outline's way to pause a key; Ghostlink's limit of 0 means "no limit".
				u.Enabled = false
				report.Disabled = append(report.Disabled, u.Name)
			} else {
				limited++
			}
			u.DataLimitBytes = limit
		}
		if c := candidates[i]; c.port != 0 {
			key := &Key{ID: s.newID(), Protocol: Shadowsocks, CreatedUnix: now.Unix(), Password: k.Password}
			if c.port != s.Shadowsocks.Port {
				key.Port = c.port
			}
			if c.method != s.Shadowsocks.Method {
				key.Method = c.method
			}
			u.Keys = append(u.Keys, key)
			report.Kept++
			endpoint := strconv.Itoa(int(c.port)) + "/" + k.Password
			if first, shared := passwords[endpoint]; shared {
				report.Notes = append(report.Notes, fmt.Sprintf("%s has the same key as %s: the server cannot tell them apart, so each connection counts for either of them, and turning one of them off does not stop the key", u.Name, first))
			} else {
				passwords[endpoint] = u.Name
			}
		} else {
			key, err := s.NewKeyWith(u, Shadowsocks, KeyOptions{})
			if err != nil {
				return report, err
			}
			u.Keys = append(u.Keys, key)
			report.NewKeys = append(report.NewKeys, outlineNewKey{u.Name, reasons[i]})
		}
		u.refreshLimit()
		s.Users = append(s.Users, u)
	}
	if limited > 0 {
		// The same number means something else here: say so, or clients are cut off weeks later.
		who := fmt.Sprintf("%d clients keep their", limited)
		if limited == 1 {
			who = "1 client keeps its"
		}
		report.Notes = append(report.Notes, who+" Outline data limit. Outline counts only the last 30 days; here usage counts from now on and is not reset on its own, so a client that reaches its limit stays off until you reset its usage or raise the limit")
	}
	report.Clients = len(s.Users)
	report.ExtraPorts = s.shadowsocksPorts()[1:]
	return report, nil
}

// commonCipher is the cipher most of these keys use (ties: Outline's default, then the
// strongest AES).
func commonCipher(indexes []int, candidates []outlineCandidate) string {
	counts := map[string]int{}
	for _, i := range indexes {
		counts[candidates[i].method]++
	}
	best := ""
	for _, method := range outlineCiphers {
		if counts[method] > counts[best] {
			best = method
		}
	}
	return best
}

func validOutlinePassword(password string) bool {
	if password == "" || len(password) > 256 {
		return false
	}
	for _, r := range password {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

// cleanName makes text a valid client or server name: printable, trimmed, at most 64 characters.
func cleanName(text string) string {
	text = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, text)
	text = strings.TrimSpace(text)
	if runes := []rune(text); len(runes) > 64 {
		text = strings.TrimSpace(string(runes[:64]))
	}
	return text
}

func outlineKeyName(k outlineKey, index int) string {
	if name := cleanName(k.Name); name != "" {
		return name
	}
	if id := cleanName(string(k.ID)); id != "" {
		return cleanName("Key " + id)
	}
	return "Key " + strconv.Itoa(index+1)
}

// uniqueName adds " (2)", " (3)", … to a name another client already has.
func (s *State) uniqueName(name string) string {
	if s.UserByName(name) == nil {
		return name
	}
	for n := 2; ; n++ {
		suffix := fmt.Sprintf(" (%d)", n)
		base := []rune(name)
		if len(base)+len([]rune(suffix)) > 64 {
			base = base[:64-len([]rune(suffix))]
		}
		if candidate := strings.TrimSpace(string(base)) + suffix; s.UserByName(candidate) == nil {
			return candidate
		}
	}
}
