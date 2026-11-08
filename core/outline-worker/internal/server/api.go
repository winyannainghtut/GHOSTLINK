// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxRequestBytes = 64 << 10

// apiListenHost is empty (all addresses) in production; tests use loopback.
var apiListenHost = ""

// API is the management interface: HTTPS with a pinned self-signed certificate, under a
// secret path. Anyone with the management key is the server's administrator.
type API struct {
	service *Service
	secret  string
	version string
	mux     *http.ServeMux
	limiter *failureLimiter
}

var errNotFound = errors.New("not found")

func NewAPI(service *Service, version string) *API {
	a := &API{service: service, version: version, mux: http.NewServeMux(), limiter: newFailureLimiter()}
	service.Read(func(s *State) { a.secret = s.API.Secret })
	routes := map[string]func(*http.Request) (int, any, error){
		"GET /server":                          a.getServer,
		"PATCH /server":                        a.patchServer,
		"GET /users":                           a.listUsers,
		"POST /users":                          a.createUser,
		"GET /users/{id}":                      a.getUser,
		"PATCH /users/{id}":                    a.patchUser,
		"DELETE /users/{id}":                   a.deleteUser,
		"GET /users/{id}/keys":                 a.listKeys,
		"POST /users/{id}/keys":                a.createKey,
		"DELETE /users/{id}/keys/{keyID}":      a.deleteKey,
		"GET /rules":                           a.getRules,
		"PUT /rules":                           a.putRules,
		"GET /metrics":                         a.metrics,
		"GET /live":                            a.live,
		"GET /stats":                           a.stats,
		"GET /clients":                         a.clients,
		"GET /users/{id}/keys/{keyID}/qr":      a.keyQR,
		"GET /users/{id}/kit":                  a.kit,
		"GET /users/{id}/keys/{keyID}/profile": a.keyProfile,
		"GET /dashboard":                       a.dashboardInfo,
		"GET /mesh":                            a.getMesh,
		"PATCH /mesh":                          a.patchMesh,
		"POST /mesh/invites":                   a.createInvite,
		"GET /mesh/invites":                    a.listInvites,
		"DELETE /mesh/invites/{id}":            a.deleteInvite,
		"PATCH /mesh/nodes/{id}":               a.patchMeshNode,
		"DELETE /mesh/nodes/{id}":              a.deleteMeshNode,
		"GET /mesh/rules":                      a.getMeshRules,
		"PUT /mesh/rules":                      a.putMeshRules,
		"GET /mesh/topology":                   a.meshTopology,
		"POST /import/outline":                 a.importOutline,
	}
	for pattern, handler := range routes {
		a.mux.HandleFunc(pattern, a.wrap(handler))
	}
	return a
}

// ServeHTTP accepts only requests under the secret path; everything else looks like nothing.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if a.limiter.blocked(host) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	segment, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if subtle.ConstantTimeCompare([]byte(segment), []byte(a.secret)) != 1 || a.secret == "" {
		a.limiter.fail(host)
		http.NotFound(w, r)
		return
	}
	inner := r.Clone(r.Context())
	inner.URL.Path, inner.URL.RawPath = "/"+rest, ""
	w.Header().Set("Cache-Control", "no-store")
	a.mux.ServeHTTP(w, inner)
}

func (a *API) wrap(handler func(*http.Request) (int, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, body, err := handler(r)
		if raw, ok := body.(rawBody); ok && err == nil {
			w.Header().Set("Content-Type", raw.contentType)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, raw.data)
			return
		}
		if err != nil {
			var input InputError
			switch {
			case errors.As(err, &input):
				status = http.StatusBadRequest
			case errors.Is(err, errNotFound):
				status = http.StatusNotFound
			case status < 400:
				status = http.StatusInternalServerError
			}
			body = map[string]string{"error": err.Error()}
		}
		if status == http.StatusNoContent {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

func decode(r *http.Request, v any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return InputError{fmt.Errorf("invalid request body: %v", err)}
	}
	if decoder.More() {
		return InputError{errors.New("invalid request body: trailing data")}
	}
	return nil
}

// Listen serves the API over TLS 1.3 until the listener closes.
func (a *API) Listen() (*http.Server, net.Listener, error) {
	var certPEM, keyPEM string
	var port uint16
	a.service.Read(func(s *State) { certPEM, keyPEM, port = s.API.CertPEM, s.API.KeyPEM, s.API.Port })
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", apiListenHost, port))
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{
		Handler:           a,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		// Internet scanners cause constant handshake errors; they are not worth logging.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return server, listener, nil
}

// --- server ---

type protocolInfo struct {
	Enabled bool   `json:"enabled"`
	Port    uint16 `json:"port"`
}

type serverInfo struct {
	Name              string                  `json:"name"`
	Hostname          string                  `json:"hostname"`
	Version           string                  `json:"version"`
	CreatedUnix       int64                   `json:"created_unix"`
	APIPort           uint16                  `json:"api_port"`
	Protocols         map[string]protocolInfo `json:"protocols"`
	VLESSHandshake    string                  `json:"vless_handshake"`
	ShadowsocksMethod string                  `json:"shadowsocks_method"`
	// ShadowsocksExtraPorts are the ports of keys imported from Outline that kept their own port.
	ShadowsocksExtraPorts []uint16 `json:"shadowsocks_extra_ports,omitempty"`
	Users                 int      `json:"users"`
	SiteStats             bool     `json:"site_stats"`
	HistoryDays           int      `json:"history_days"`
	SiteDays              int      `json:"site_days"`
	HistoryMaxMB          int      `json:"history_max_mb"`
	// DefaultSpeedLimitBps caps every client without a limit of its own, bytes/s (0: none).
	DefaultSpeedLimitBps uint64         `json:"default_speed_limit_bps"`
	DashboardPort        uint16         `json:"dashboard_port"`
	DashboardPublic      bool           `json:"dashboard_public"`
	IPsecComponent       ipsecComponent `json:"ipsec_component"`
	// AddressPools are the WireGuard and AmneziaWG tunnel subnets: how full each is and the
	// address the next key gets.
	AddressPools []addressPool `json:"address_pools"`
}

type addressPool struct {
	Protocol string `json:"protocol"`
	CIDR     string `json:"cidr"`
	Used     int    `json:"used"`
	Capacity int    `json:"capacity"`
	Next     string `json:"next,omitempty"`
}

// rawBody is a non-JSON answer (SVG, terminal text, HTML).
type rawBody struct{ contentType, data string }

func (a *API) serverInfo(s *State) serverInfo {
	return serverInfo{
		Name: s.Name, Hostname: s.Hostname, Version: a.version, CreatedUnix: s.CreatedUnix, APIPort: s.API.Port,
		Protocols: map[string]protocolInfo{
			AmneziaWG:   {s.AmneziaWG.Enabled, s.AmneziaWG.Port},
			WireGuard:   {s.WireGuard.Enabled, s.WireGuard.Port},
			VLESS:       {s.VLESS.Enabled, s.VLESS.Port},
			Shadowsocks: {s.Shadowsocks.Enabled, s.Shadowsocks.Port},
			IKEv2:       {s.IPsec.IKEv2Enabled, 500},
			IPsec:       {s.IPsec.IPsecEnabled, 500},
		},
		IPsecComponent: a.service.ipsecComponent(time.Now()), AddressPools: s.addressPools(),
		VLESSHandshake: s.VLESS.Handshake, ShadowsocksMethod: s.Shadowsocks.Method, Users: len(s.Users),
		ShadowsocksExtraPorts: s.shadowsocksPorts()[1:],
		SiteStats:             s.Monitor.SiteStats, DefaultSpeedLimitBps: s.DefaultSpeedLimitBps, HistoryDays: s.Monitor.historyDays(), SiteDays: s.Monitor.siteDays(),
		HistoryMaxMB: s.Monitor.historyMaxMB(), DashboardPort: s.Dashboard.Port, DashboardPublic: s.Dashboard.Public,
	}
}

func (a *API) getServer(*http.Request) (int, any, error) {
	var info serverInfo
	a.service.Read(func(s *State) { info = a.serverInfo(s) })
	return http.StatusOK, info, nil
}

type protocolPatch struct {
	Enabled *bool   `json:"enabled"`
	Port    *uint16 `json:"port"`
}

type serverPatch struct {
	Name           *string                  `json:"name"`
	Hostname       *string                  `json:"hostname"`
	VLESSHandshake *string                  `json:"vless_handshake"`
	Protocols      map[string]protocolPatch `json:"protocols"`
	// Monitoring: turning site_stats off deletes every recorded site.
	SiteStats    *bool `json:"site_stats"`
	HistoryDays  *int  `json:"history_days"`
	SiteDays     *int  `json:"site_days"`
	HistoryMaxMB *int  `json:"history_max_mb"`
	// Dashboard: its own port (never 443), private (127.0.0.1) or public (HTTPS).
	DashboardPort       *uint16 `json:"dashboard_port"`
	DashboardPublic     *bool   `json:"dashboard_public"`
	ResetDashboardToken bool    `json:"reset_dashboard_token"`
	// RotateIPsecPSK replaces the IPsec group key; every IPsec PSK profile must be reinstalled.
	RotateIPsecPSK bool `json:"rotate_ipsec_psk"`
	// DefaultSpeedLimitBps caps every client without a limit of its own, bytes/s (0: none).
	DefaultSpeedLimitBps *uint64 `json:"default_speed_limit_bps"`
}

func (s *State) protocolSettings(protocol string) (*bool, *uint16) {
	switch protocol {
	case Shadowsocks:
		return &s.Shadowsocks.Enabled, &s.Shadowsocks.Port
	case VLESS:
		return &s.VLESS.Enabled, &s.VLESS.Port
	case WireGuard:
		return &s.WireGuard.Enabled, &s.WireGuard.Port
	case AmneziaWG:
		return &s.AmneziaWG.Enabled, &s.AmneziaWG.Port
	case IKEv2:
		return &s.IPsec.IKEv2Enabled, nil
	case IPsec:
		return &s.IPsec.IPsecEnabled, nil
	}
	return nil, nil
}

func (a *API) patchServer(r *http.Request) (int, any, error) {
	var patch serverPatch
	if err := decode(r, &patch); err != nil {
		return 0, nil, err
	}
	var info serverInfo
	hostnameChanged := false
	err := a.service.Change(func(s *State) error {
		if patch.Name != nil {
			if err := ValidName(*patch.Name); err != nil {
				return InputError{err}
			}
			s.Name = *patch.Name
		}
		if patch.Hostname != nil {
			if err := ValidHostname(*patch.Hostname); err != nil {
				return InputError{err}
			}
			hostnameChanged = *patch.Hostname != s.Hostname
			s.Hostname = *patch.Hostname
		}
		if patch.VLESSHandshake != nil {
			if domain, err := normalizeDomain(*patch.VLESSHandshake); err != nil || domain != *patch.VLESSHandshake {
				return InputError{errors.New("the REALITY handshake site must be a public DNS name such as www.example.com")}
			}
			s.VLESS.Handshake = *patch.VLESSHandshake
		}
		if patch.SiteStats != nil {
			s.Monitor.SiteStats = *patch.SiteStats
		}
		if patch.HistoryDays != nil {
			if *patch.HistoryDays < 7 || *patch.HistoryDays > 365 {
				return InputError{errors.New("history_days must be 7-365")}
			}
			s.Monitor.HistoryDays = *patch.HistoryDays
		}
		if patch.SiteDays != nil {
			if *patch.SiteDays < 1 || *patch.SiteDays > 90 {
				return InputError{errors.New("site_days must be 1-90")}
			}
			s.Monitor.SiteDays = *patch.SiteDays
		}
		if s.Monitor.siteDays() > s.Monitor.historyDays() {
			return InputError{errors.New("site_days cannot be longer than history_days")}
		}
		if patch.DefaultSpeedLimitBps != nil {
			if *patch.DefaultSpeedLimitBps > maxSpeedLimitBps {
				return InputError{errors.New("default_speed_limit_bps must be 0 (none) or 1-1250000000 bytes per second")}
			}
			s.DefaultSpeedLimitBps = *patch.DefaultSpeedLimitBps
		}
		if patch.HistoryMaxMB != nil {
			if *patch.HistoryMaxMB < 1 || *patch.HistoryMaxMB > 1024 {
				return InputError{errors.New("history_max_mb must be 1-1024")}
			}
			s.Monitor.HistoryMaxMB = *patch.HistoryMaxMB
		}
		if patch.DashboardPort != nil {
			s.Dashboard.Port = *patch.DashboardPort
		}
		if patch.DashboardPublic != nil {
			s.Dashboard.Public = *patch.DashboardPublic
		}
		if patch.ResetDashboardToken {
			s.Dashboard.Token = base64.RawURLEncoding.EncodeToString(random(16))
		}
		for protocol, change := range patch.Protocols {
			enabled, port := s.protocolSettings(protocol)
			if enabled == nil {
				return InputError{fmt.Errorf("unknown protocol %q", protocol)}
			}
			if change.Enabled != nil {
				if *change.Enabled && !*enabled && (protocol == IKEv2 || protocol == IPsec) {
					if _, running := a.service.IPsecStatus(time.Now()); !running {
						return InputError{errIPsecNotRunning}
					}
					if err := s.ensureIPsecPKI(time.Now(), portFree); err != nil {
						return err
					}
				}
				*enabled = *change.Enabled
			}
			if change.Port != nil {
				if port == nil {
					return InputError{errors.New("IKEv2 and IPsec use the fixed ports UDP 500 and 4500")}
				}
				if *change.Port == 0 {
					return InputError{errors.New("port must be 1-65535")}
				}
				*port = *change.Port
			}
		}
		if patch.RotateIPsecPSK {
			s.IPsec.PSK = base64.RawURLEncoding.EncodeToString(random(32))
		}
		// A new address needs a new server certificate for IKEv2/IPsec.
		if hostnameChanged && s.IPsec.CAPEM != "" {
			if err := s.ensureIPsecPKI(time.Now(), portFree); err != nil {
				return err
			}
		}
		info = a.serverInfo(s)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if hostnameChanged {
		a.service.store.Lock()
		err = a.service.store.WriteManagementKey()
		a.service.store.Unlock()
		if err != nil {
			return 0, nil, err
		}
	}
	return http.StatusOK, info, nil
}

// --- users ---

type keySummary struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	CreatedUnix int64  `json:"created_unix"`
	// Auth is the IKEv2/IPsec method (eap, certificate or psk).
	Auth string `json:"auth,omitempty"`
	// Address is a WireGuard/AmneziaWG key's tunnel address.
	Address string `json:"address,omitempty"`
}

type userView struct {
	ID                    string       `json:"id"`
	Name                  string       `json:"name"`
	CreatedUnix           int64        `json:"created_unix"`
	Enabled               bool         `json:"enabled"`
	DataLimitBytes        uint64       `json:"data_limit_bytes"`
	UsageBytes            uint64       `json:"usage_bytes"`
	OverLimit             bool         `json:"over_limit"`
	ExemptFromGlobalRules bool         `json:"exempt_from_global_rules"`
	Rules                 Rules        `json:"rules"`
	Keys                  []keySummary `json:"keys"`
	// SpeedLimitBps is the client's own setting in bytes per second (0 server default, -1 none);
	// EffectiveSpeedLimitBps is the cap that applies (0 none).
	SpeedLimitBps          int64 `json:"speed_limit_bps"`
	EffectiveSpeedLimitBps int64 `json:"effective_speed_limit_bps"`
}

func viewUser(s *State, u *User) userView {
	keys := []keySummary{}
	for _, k := range u.Keys {
		keys = append(keys, keySummary{k.ID, k.Protocol, k.CreatedUnix, k.Auth, k.Address})
	}
	return userView{u.ID, u.Name, u.CreatedUnix, u.Enabled, u.DataLimitBytes, u.UsageBytes, u.OverLimit,
		u.ExemptFromGlobalRules, u.Rules, keys, u.SpeedLimitBps, s.SpeedLimitBps(u)}
}

func (a *API) listUsers(*http.Request) (int, any, error) {
	users := []userView{}
	a.service.Read(func(s *State) {
		for _, u := range s.Users {
			users = append(users, viewUser(s, u))
		}
	})
	return http.StatusOK, users, nil
}

func (a *API) getUser(r *http.Request) (int, any, error) {
	var view *userView
	a.service.Read(func(s *State) {
		if u := s.User(r.PathValue("id")); u != nil {
			v := viewUser(s, u)
			view = &v
		}
	})
	if view == nil {
		return 0, nil, fmt.Errorf("user %w", errNotFound)
	}
	return http.StatusOK, view, nil
}

type userChange struct {
	Name                  *string `json:"name"`
	Enabled               *bool   `json:"enabled"`
	DataLimitBytes        *uint64 `json:"data_limit_bytes"`
	ExemptFromGlobalRules *bool   `json:"exempt_from_global_rules"`
	Rules                 *Rules  `json:"rules"`
	ResetUsage            bool    `json:"reset_usage"`
	// SpeedLimitBps in bytes per second: 0 follows the server default, -1 means no limit.
	SpeedLimitBps *int64 `json:"speed_limit_bps"`
}

// UserByName finds a user by name, ignoring case.
func (s *State) UserByName(name string) *User {
	for _, u := range s.Users {
		if strings.EqualFold(u.Name, strings.TrimSpace(name)) {
			return u
		}
	}
	return nil
}

func (c userChange) apply(s *State, u *User) error {
	if c.Name != nil {
		if err := ValidName(*c.Name); err != nil {
			return InputError{err}
		}
		if other := s.UserByName(*c.Name); other != nil && other != u {
			return InputError{fmt.Errorf("another user is already called %q", other.Name)}
		}
		name := strings.TrimSpace(*c.Name)
		// An IKEv2/IPsec key without an identifier of its own takes one from the client's name.
		// A rename keeps it: installed profiles and issued certificates carry the old one.
		for _, k := range u.Keys {
			if k.isApple() && k.LocalID == "" && name != u.Name {
				k.LocalID = k.localIdentity(u)
			}
		}
		u.Name = name
	}
	if c.Enabled != nil {
		u.Enabled = *c.Enabled
	}
	if c.DataLimitBytes != nil {
		u.DataLimitBytes = *c.DataLimitBytes
	}
	if c.ExemptFromGlobalRules != nil {
		u.ExemptFromGlobalRules = *c.ExemptFromGlobalRules
	}
	if c.Rules != nil {
		rules, err := c.Rules.Normalize()
		if err != nil {
			return InputError{err}
		}
		u.Rules = rules
	}
	if c.ResetUsage {
		u.UsageBytes = 0
	}
	if c.SpeedLimitBps != nil {
		if v := *c.SpeedLimitBps; v < noSpeedLimit || v > maxSpeedLimitBps {
			return InputError{errors.New("speed_limit_bps must be -1 (no limit), 0 (server default) or 1-1250000000 bytes per second")}
		}
		u.SpeedLimitBps = *c.SpeedLimitBps
	}
	u.refreshLimit()
	return nil
}

func (a *API) createUser(r *http.Request) (int, any, error) {
	var change userChange
	if err := decode(r, &change); err != nil {
		return 0, nil, err
	}
	if change.Name == nil {
		return 0, nil, InputError{errors.New("name is required")}
	}
	var view userView
	err := a.service.Change(func(s *State) error {
		if len(s.Users) >= MaxUsers {
			return InputError{fmt.Errorf("a server can have at most %d users", MaxUsers)}
		}
		u := &User{ID: s.newID(), CreatedUnix: time.Now().Unix(), Enabled: true, Keys: []*Key{},
			Rules: Rules{BlockedDomains: []string{}, BlockedIPs: []string{}, BlockedPorts: []string{}}}
		if err := change.apply(s, u); err != nil {
			return err
		}
		s.Users = append(s.Users, u)
		view = viewUser(s, u)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, view, nil
}

func (a *API) patchUser(r *http.Request) (int, any, error) {
	var change userChange
	if err := decode(r, &change); err != nil {
		return 0, nil, err
	}
	var view userView
	err := a.service.Change(func(s *State) error {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return fmt.Errorf("user %w", errNotFound)
		}
		if err := change.apply(s, u); err != nil {
			return err
		}
		view = viewUser(s, u)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, view, nil
}

func (a *API) deleteUser(r *http.Request) (int, any, error) {
	err := a.service.Change(func(s *State) error {
		id := r.PathValue("id")
		index := slices.IndexFunc(s.Users, func(u *User) bool { return u.ID == id })
		if index < 0 {
			return fmt.Errorf("user %w", errNotFound)
		}
		for _, k := range s.Users[index].Keys {
			s.revoke(k, time.Now())
		}
		s.Users = slices.Delete(s.Users, index, index+1)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

// --- keys ---

type keyView struct {
	IssuedKey
	CreatedUnix int64 `json:"created_unix"`
}

func (a *API) listKeys(r *http.Request) (int, any, error) {
	keys := []keyView{}
	var err error
	found := false
	a.service.Read(func(s *State) {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return
		}
		found = true
		for _, k := range u.Keys {
			rendered, renderErr := s.Render(u, k)
			if renderErr != nil {
				err = renderErr
				return
			}
			keys = append(keys, keyView{rendered, k.CreatedUnix})
		}
	})
	if !found {
		return 0, nil, fmt.Errorf("user %w", errNotFound)
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, keys, nil
}

func (a *API) createKey(r *http.Request) (int, any, error) {
	var request struct {
		Protocol         string `json:"protocol"`
		Auth             string `json:"auth"`
		ServerAddress    string `json:"server_address"`
		RemoteIdentifier string `json:"remote_identifier"`
		LocalIdentifier  string `json:"local_identifier"`
	}
	if err := decode(r, &request); err != nil {
		return 0, nil, err
	}
	options := KeyOptions{Auth: request.Auth, ServerAddress: request.ServerAddress, RemoteID: request.RemoteIdentifier, LocalID: request.LocalIdentifier}
	var view keyView
	err := a.service.Change(func(s *State) error {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return fmt.Errorf("user %w", errNotFound)
		}
		enabled, _ := s.protocolSettings(request.Protocol)
		if enabled == nil {
			return InputError{fmt.Errorf("protocol must be one of %s", strings.Join(append(append([]string{}, Protocols...), AppleProtocols...), ", "))}
		}
		if !*enabled {
			return InputError{fmt.Errorf("%s is turned off on this server", request.Protocol)}
		}
		key, err := s.NewKeyWith(u, request.Protocol, options)
		if err != nil {
			return InputError{err}
		}
		u.Keys = append(u.Keys, key)
		if key.RemoteID != "" {
			// The server certificate must also carry this identifier.
			if err := s.ensureIPsecPKI(time.Now(), portFree); err != nil {
				return err
			}
		}
		rendered, err := s.Render(u, key)
		if err != nil {
			return err
		}
		view = keyView{rendered, key.CreatedUnix}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, view, nil
}

func (a *API) deleteKey(r *http.Request) (int, any, error) {
	err := a.service.Change(func(s *State) error {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return fmt.Errorf("user %w", errNotFound)
		}
		id := r.PathValue("keyID")
		index := slices.IndexFunc(u.Keys, func(k *Key) bool { return k.ID == id })
		if index < 0 {
			return fmt.Errorf("key %w", errNotFound)
		}
		s.revoke(u.Keys[index], time.Now())
		u.Keys = slices.Delete(u.Keys, index, index+1)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

// --- rules and metrics ---

func (a *API) getRules(*http.Request) (int, any, error) {
	var rules Rules
	a.service.Read(func(s *State) { rules = s.Rules })
	return http.StatusOK, rules, nil
}

func (a *API) putRules(r *http.Request) (int, any, error) {
	var rules Rules
	if err := decode(r, &rules); err != nil {
		return 0, nil, err
	}
	normalized, err := rules.Normalize()
	if err != nil {
		return 0, nil, InputError{err}
	}
	if err := a.service.Change(func(s *State) error { s.Rules = normalized; return nil }); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, normalized, nil
}

type userUsage struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	UsageBytes     uint64 `json:"usage_bytes"`
	DataLimitBytes uint64 `json:"data_limit_bytes"`
	OverLimit      bool   `json:"over_limit"`
}

func (a *API) metrics(*http.Request) (int, any, error) {
	if err := a.service.Account(); err != nil {
		return 0, nil, err
	}
	result := struct {
		Users      []userUsage `json:"users"`
		TotalBytes uint64      `json:"total_bytes"`
	}{Users: []userUsage{}}
	a.service.Read(func(s *State) {
		for _, u := range s.Users {
			result.Users = append(result.Users, userUsage{u.ID, u.Name, u.UsageBytes, u.DataLimitBytes, u.OverLimit})
			result.TotalBytes += u.UsageBytes
		}
	})
	return http.StatusOK, result, nil
}

// --- monitoring ---

type liveUser struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	UpBps      int64  `json:"up_bps"`
	DownBps    int64  `json:"down_bps"`
	Active     int64  `json:"active"`
	Online     bool   `json:"online"`
	LastActive int64  `json:"last_active_unix"`
}

func (a *API) live(*http.Request) (int, any, error) {
	users, series := a.service.monitor.Live()
	now := time.Now().Unix()
	result := struct {
		Time    int64        `json:"time_unix"`
		UpBps   int64        `json:"up_bps"`
		DownBps int64        `json:"down_bps"`
		Active  int64        `json:"active"`
		Online  int          `json:"online_users"`
		Series  []rateSample `json:"series"`
		// Minutes are per-minute average rates for the last hour.
		Minutes []rateSample `json:"minutes"`
		Users   []liveUser   `json:"users"`
		Health  Health       `json:"health"`
	}{Time: now, Series: series, Minutes: a.service.monitor.Minutes(), Users: []liveUser{}, Health: a.service.Health()}
	if n := len(series); n > 0 {
		result.UpBps, result.DownBps = series[n-1].Up, series[n-1].Down
	}
	a.service.Read(func(s *State) {
		for _, u := range s.Users {
			live := users[u.Tag()]
			online := isOnline(live.LastActive, now)
			result.Users = append(result.Users, liveUser{u.ID, u.Name, live.UpBps, live.DownBps, live.Active, online, live.LastActive})
			result.Active += live.Active
			if online {
				result.Online++
			}
		}
	})
	return http.StatusOK, result, nil
}

// statsUser resolves an optional ?user= to a tag, refusing unknown users.
func (a *API) statsUser(r *http.Request) (string, error) {
	id := r.URL.Query().Get("user")
	if id == "" {
		return "", nil
	}
	found := false
	a.service.Read(func(s *State) { found = s.User(id) != nil })
	if !found {
		return "", fmt.Errorf("user %w", errNotFound)
	}
	return tagOf(id), nil
}

func (a *API) stats(r *http.Request) (int, any, error) {
	tag, err := a.statsUser(r)
	if err != nil {
		return 0, nil, err
	}
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "7d"
	}
	a.service.Record(time.Now())
	var result StatsResult
	a.service.Read(func(s *State) { result, err = a.service.monitor.Stats(s, rangeName, tag, time.Now()) })
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, result, nil
}

func (a *API) clients(r *http.Request) (int, any, error) {
	tag, err := a.statsUser(r)
	if err != nil {
		return 0, nil, err
	}
	a.service.Record(time.Now())
	var clients []clientView
	a.service.Read(func(s *State) { clients = a.service.monitor.Clients(s, tag) })
	return http.StatusOK, map[string]any{"clients": clients}, nil
}

func (a *API) keyQR(r *http.Request) (int, any, error) {
	var issued IssuedKey
	var err error
	found := false
	a.service.Read(func(s *State) {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return
		}
		for _, k := range u.Keys {
			if k.ID == r.PathValue("keyID") {
				found = true
				issued, err = s.Render(u, k)
			}
		}
	})
	if !found {
		return 0, nil, fmt.Errorf("key %w", errNotFound)
	}
	if err != nil {
		return 0, nil, err
	}
	content, err := qrContent(issued, r.URL.Query().Get("content"))
	if err != nil {
		return 0, nil, err
	}
	switch r.URL.Query().Get("format") {
	case "", "svg":
		svg, err := QRSVG(content)
		if err != nil {
			return 0, nil, InputError{err}
		}
		return http.StatusOK, rawBody{"image/svg+xml", svg}, nil
	case "text":
		text, err := QRText(content)
		if err != nil {
			return 0, nil, InputError{err}
		}
		return http.StatusOK, rawBody{"text/plain; charset=utf-8", text}, nil
	}
	return 0, nil, InputError{errors.New("format must be svg or text")}
}

func (a *API) kit(r *http.Request) (int, any, error) {
	var page string
	var err error
	found := false
	a.service.Read(func(s *State) {
		if u := s.User(r.PathValue("id")); u != nil {
			found = true
			page, err = s.Kit(u)
		}
	})
	if !found {
		return 0, nil, fmt.Errorf("user %w", errNotFound)
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, rawBody{"text/html; charset=utf-8", page}, nil
}

// keyProfile answers with the Apple configuration profile of an IKEv2 or IPsec key.
func (a *API) keyProfile(r *http.Request) (int, any, error) {
	options := ProfileOptions{PromptPassword: r.URL.Query().Get("prompt_password") == "1", OnDemand: r.URL.Query().Get("on_demand") == "1"}
	var profile string
	var err error
	found := false
	a.service.Read(func(s *State) {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return
		}
		for _, k := range u.Keys {
			if k.ID == r.PathValue("keyID") {
				found = true
				profile, err = s.AppleProfile(u, k, options)
			}
		}
	})
	if !found {
		return 0, nil, fmt.Errorf("key %w", errNotFound)
	}
	if err != nil {
		return 0, nil, InputError{err}
	}
	return http.StatusOK, rawBody{"application/x-apple-aspen-config", profile}, nil
}

// dashboardInfo gives the administrator what is needed to open the dashboard.
func (a *API) dashboardInfo(*http.Request) (int, any, error) {
	var info map[string]any
	a.service.Read(func(s *State) {
		info = map[string]any{"port": s.Dashboard.Port, "public": s.Dashboard.Public, "token": s.Dashboard.Token, "hostname": s.Hostname}
	})
	return http.StatusOK, info, nil
}

// --- throttling ---

// failureLimiter slows down guessing: after 20 wrong paths in a minute an address is refused
// for the rest of that minute. The secret has 128 random bits; this only limits noise.
type failureLimiter struct {
	mu       sync.Mutex
	window   time.Time
	failures map[string]int
}

func newFailureLimiter() *failureLimiter { return &failureLimiter{failures: map[string]int{}} }

func (l *failureLimiter) roll() {
	if time.Since(l.window) > time.Minute || len(l.failures) > 10_000 {
		l.window, l.failures = time.Now(), map[string]int{}
	}
}

func (l *failureLimiter) blocked(host string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll()
	return l.failures[host] >= 20
}

func (l *failureLimiter) fail(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll()
	l.failures[host]++
}
