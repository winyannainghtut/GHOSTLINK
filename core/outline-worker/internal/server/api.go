// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto/subtle"
	"crypto/tls"
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
		"GET /server":                     a.getServer,
		"PATCH /server":                   a.patchServer,
		"GET /users":                      a.listUsers,
		"POST /users":                     a.createUser,
		"GET /users/{id}":                 a.getUser,
		"PATCH /users/{id}":               a.patchUser,
		"DELETE /users/{id}":              a.deleteUser,
		"GET /users/{id}/keys":            a.listKeys,
		"POST /users/{id}/keys":           a.createKey,
		"DELETE /users/{id}/keys/{keyID}": a.deleteKey,
		"GET /rules":                      a.getRules,
		"PUT /rules":                      a.putRules,
		"GET /metrics":                    a.metrics,
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
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
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
	Users             int                     `json:"users"`
}

func (a *API) serverInfo(s *State) serverInfo {
	return serverInfo{
		Name: s.Name, Hostname: s.Hostname, Version: a.version, CreatedUnix: s.CreatedUnix, APIPort: s.API.Port,
		Protocols: map[string]protocolInfo{
			AmneziaWG:   {s.AmneziaWG.Enabled, s.AmneziaWG.Port},
			WireGuard:   {s.WireGuard.Enabled, s.WireGuard.Port},
			VLESS:       {s.VLESS.Enabled, s.VLESS.Port},
			Shadowsocks: {s.Shadowsocks.Enabled, s.Shadowsocks.Port},
		},
		VLESSHandshake: s.VLESS.Handshake, ShadowsocksMethod: s.Shadowsocks.Method, Users: len(s.Users),
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
		for protocol, change := range patch.Protocols {
			enabled, port := s.protocolSettings(protocol)
			if enabled == nil {
				return InputError{fmt.Errorf("unknown protocol %q", protocol)}
			}
			if change.Enabled != nil {
				*enabled = *change.Enabled
			}
			if change.Port != nil {
				if *change.Port == 0 {
					return InputError{errors.New("port must be 1-65535")}
				}
				*port = *change.Port
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
}

func viewUser(u *User) userView {
	keys := []keySummary{}
	for _, k := range u.Keys {
		keys = append(keys, keySummary{k.ID, k.Protocol, k.CreatedUnix})
	}
	return userView{u.ID, u.Name, u.CreatedUnix, u.Enabled, u.DataLimitBytes, u.UsageBytes, u.OverLimit,
		u.ExemptFromGlobalRules, u.Rules, keys}
}

func (a *API) listUsers(*http.Request) (int, any, error) {
	users := []userView{}
	a.service.Read(func(s *State) {
		for _, u := range s.Users {
			users = append(users, viewUser(u))
		}
	})
	return http.StatusOK, users, nil
}

func (a *API) getUser(r *http.Request) (int, any, error) {
	var view *userView
	a.service.Read(func(s *State) {
		if u := s.User(r.PathValue("id")); u != nil {
			v := viewUser(u)
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
}

func (c userChange) apply(u *User) error {
	if c.Name != nil {
		if err := ValidName(*c.Name); err != nil {
			return InputError{err}
		}
		u.Name = *c.Name
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
		if err := change.apply(u); err != nil {
			return err
		}
		s.Users = append(s.Users, u)
		view = viewUser(u)
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
		if err := change.apply(u); err != nil {
			return err
		}
		view = viewUser(u)
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
		Protocol string `json:"protocol"`
	}
	if err := decode(r, &request); err != nil {
		return 0, nil, err
	}
	var view keyView
	err := a.service.Change(func(s *State) error {
		u := s.User(r.PathValue("id"))
		if u == nil {
			return fmt.Errorf("user %w", errNotFound)
		}
		enabled, _ := s.protocolSettings(request.Protocol)
		if enabled == nil {
			return InputError{fmt.Errorf("protocol must be one of %s", strings.Join(Protocols, ", "))}
		}
		if !*enabled {
			return InputError{fmt.Errorf("%s is turned off on this server", request.Protocol)}
		}
		key, err := s.NewKey(u, request.Protocol)
		if err != nil {
			return InputError{err}
		}
		u.Keys = append(u.Keys, key)
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
