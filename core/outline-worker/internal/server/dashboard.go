// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed dashboard
var dashboardFiles embed.FS

const (
	sessionCookie   = "ghostlink_session"
	sessionLifetime = 12 * time.Hour
	csrfHeader      = "X-Ghostlink-Dashboard"
)

// Dashboard is the administrator's web interface. Private mode listens on 127.0.0.1 only
// (reach it through an SSH tunnel); public mode serves HTTPS on all addresses. Either way it
// has its own port and needs the login token, and its API calls go through the same handlers
// as the management API.
type Dashboard struct {
	service  *Service
	api      *API
	static   fs.FS
	mu       sync.Mutex
	server   *http.Server
	running  DashboardConfig
	sessions map[string]time.Time
	limiter  *failureLimiter
	// Listen is replaceable in tests.
	listen func(network, address string) (net.Listener, error)
}

func NewDashboard(service *Service, api *API) *Dashboard {
	static, _ := fs.Sub(dashboardFiles, "dashboard")
	return &Dashboard{service: service, api: api, static: static, sessions: map[string]time.Time{},
		limiter: newFailureLimiter(), listen: net.Listen}
}

// Apply starts, moves or stops the listener to match the stored configuration. A new token
// signs everyone out.
func (d *Dashboard) Apply() error {
	var config DashboardConfig
	var certPEM, keyPEM string
	d.service.Read(func(s *State) { config, certPEM, keyPEM = s.Dashboard, s.API.CertPEM, s.API.KeyPEM })
	d.mu.Lock()
	defer d.mu.Unlock()
	if config.Token != d.running.Token {
		d.sessions = map[string]time.Time{}
	}
	if d.server != nil && config.Port == d.running.Port && config.Public == d.running.Public {
		d.running = config
		return nil
	}
	if d.server != nil {
		_ = d.server.Close()
		d.server = nil
	}
	d.running = config
	if config.Port == 0 {
		return nil
	}
	address := fmt.Sprintf("127.0.0.1:%d", config.Port)
	if config.Public {
		address = fmt.Sprintf(":%d", config.Port)
	}
	listener, err := d.listen("tcp", address)
	if err != nil {
		return fmt.Errorf("dashboard port %d: %w", config.Port, err)
	}
	server := &http.Server{
		Handler:           d,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if config.Public {
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			listener.Close()
			return err
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		listener = tls.NewListener(listener, server.TLSConfig)
	}
	d.server = server
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (d *Dashboard) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.server != nil {
		_ = d.server.Close()
		d.server = nil
	}
}

// allowedHost guards against DNS rebinding: a page on another site that rebinds its name to
// this address cannot pass the Host check.
func (d *Dashboard) allowedHost(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	d.mu.Lock()
	public := d.running.Public
	d.mu.Unlock()
	if !public {
		return false
	}
	var hostname string
	d.service.Read(func(s *State) { hostname = s.Hostname })
	return host == strings.Trim(strings.ToLower(hostname), "[]")
}

func (d *Dashboard) session(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	expires, ok := d.sessions[cookie.Value]
	if ok && time.Now().After(expires) {
		delete(d.sessions, cookie.Value)
		return false
	}
	return ok
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if !d.allowedHost(r) {
		http.Error(w, "open the dashboard at 127.0.0.1 through your SSH tunnel", http.StatusForbidden)
		return
	}
	switch {
	case r.URL.Path == "/login" && r.Method == http.MethodPost:
		d.login(w, r)
	case r.URL.Path == "/logout" && r.Method == http.MethodPost:
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			d.mu.Lock()
			delete(d.sessions, cookie.Value)
			d.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/api/"):
		if !d.session(r) {
			http.Error(w, `{"error":"sign in with the link from sudo ghostlink-server dashboard"}`, http.StatusUnauthorized)
			return
		}
		if r.Header.Get(csrfHeader) != "1" {
			http.Error(w, `{"error":"missing dashboard header"}`, http.StatusForbidden)
			return
		}
		inner := r.Clone(r.Context())
		inner.URL.Path, inner.URL.RawPath = strings.TrimPrefix(r.URL.Path, "/api"), ""
		d.api.mux.ServeHTTP(w, inner)
	case r.Method == http.MethodGet:
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if strings.Contains(name, "/") || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, d.static, name)
	default:
		http.NotFound(w, r)
	}
}

func (d *Dashboard) login(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if d.limiter.blocked(host) {
		http.Error(w, `{"error":"too many attempts; wait a minute"}`, http.StatusTooManyRequests)
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	token, public := d.running.Token, d.running.Public
	d.mu.Unlock()
	if token == "" || subtle.ConstantTimeCompare([]byte(request.Token), []byte(token)) != 1 {
		d.limiter.fail(host)
		http.Error(w, `{"error":"this login link is not valid (it may have been reset)"}`, http.StatusUnauthorized)
		return
	}
	session := hex.EncodeToString(random(32))
	d.mu.Lock()
	now := time.Now()
	for id, expires := range d.sessions {
		if now.After(expires) {
			delete(d.sessions, id)
		}
	}
	d.sessions[session] = now.Add(sessionLifetime)
	d.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: public, MaxAge: int(sessionLifetime.Seconds())})
	w.WriteHeader(http.StatusNoContent)
}

// ErrDashboardPort explains a dashboard port that cannot be used.
var ErrDashboardPort = errors.New("the dashboard needs its own port from 1024 to 65535 (not 443)")
