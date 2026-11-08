// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"ghostlink.local/outline-worker/internal/mesh"
	"ghostlink.local/outline-worker/internal/meshproto"
)

// MeshScript is the one-line installer printed with every invite.
const MeshScript = "https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-mesh.sh"

// meshWait is how long a sync waits for a configuration change before answering anyway.
var meshWait = 10 * time.Second

// usedPorts lists every port the server listens on, for picking new ones.
func (s *State) usedPorts() map[uint16]bool {
	used := map[uint16]bool{s.API.Port: true, s.Dashboard.Port: true, s.Shadowsocks.Port: true, s.VLESS.Port: true,
		s.WireGuard.Port: true, s.AmneziaWG.Port: true, s.IPsec.DNSPort: true}
	if s.Mesh != nil {
		used[s.Mesh.Port] = true
	}
	// Also the ports of keys imported from Outline, even when nothing listens there right now.
	for _, port := range s.shadowsocksPorts() {
		used[port] = true
	}
	delete(used, 0)
	return used
}

func (s *State) meshEnabled() bool { return s.Mesh != nil && s.Mesh.Enabled }

// meshURL is where agents reach the coordinator.
func (s *State) meshURL(local bool) string {
	host := endpointHost(s.Hostname)
	if local {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("https://%s:%d", host, s.Mesh.Port)
}

// enableMesh turns the mesh on, creating it (and its port) on first use.
func (s *State) enableMesh(cidr, name string, free func(string, uint16) bool) error {
	if s.Mesh == nil {
		s.Mesh = &mesh.Network{}
	}
	port := s.Mesh.Port
	if port == 0 {
		var err error
		if port, err = pickPort(s.usedPorts(), free, "tcp"); err != nil {
			return err
		}
	}
	if cidr == "" {
		cidr = s.Mesh.CIDR
	}
	return s.Mesh.Enable(cidr, name, port)
}

// --- the agent API (its own port, TLS 1.3 with the API certificate, so agents pin the same
// fingerprint as the management key) ---

// MeshServer serves join, sync and leave for agents.
type MeshServer struct {
	service *Service
	limiter *failureLimiter
	listen  func(network, address string) (net.Listener, error)
	mu      sync.Mutex
	server  *http.Server
	port    uint16
}

// NewMeshServer returns a stopped mesh server; Apply starts it when the mesh is on.
func NewMeshServer(service *Service) *MeshServer {
	return &MeshServer{service: service, limiter: newFailureLimiter(), listen: net.Listen}
}

// Apply starts, moves or stops the listener to match the stored mesh.
func (m *MeshServer) Apply() error {
	var port uint16
	var certPEM, keyPEM string
	m.service.Read(func(s *State) {
		if s.meshEnabled() {
			port = s.Mesh.Port
		}
		certPEM, keyPEM = s.API.CertPEM, s.API.KeyPEM
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil && port == m.port {
		return nil
	}
	if m.server != nil {
		// Shutdown, unlike Close, lets the syncs being answered finish. When the mesh is turned
		// off, the waiting ones were just woken and answer "disabled", so their nodes take their
		// links down instead of seeing a closed port, which they treat as an outage.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := m.server.Shutdown(ctx); err != nil {
			_ = m.server.Close()
		}
		cancel()
		m.server = nil
	}
	m.port = port
	if port == 0 {
		return nil
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return err
	}
	listener, err := m.listen("tcp", fmt.Sprintf("%s:%d", apiListenHost, port))
	if err != nil {
		return fmt.Errorf("mesh port %d: %w", port, err)
	}
	server := &http.Server{
		Handler:           m,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      meshWait + 20*time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
	}
	m.server = server
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	return nil
}

// Close stops the listener.
func (m *MeshServer) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil {
		_ = m.server.Close()
		m.server = nil
	}
}

func remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func meshError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func meshJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (m *MeshServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := remoteAddr(r).String()
	if m.limiter.blocked(host) {
		meshError(w, http.StatusTooManyRequests, "too many failed attempts; wait a minute")
		return
	}
	if r.Method != http.MethodPost {
		meshError(w, http.StatusNotFound, "not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	switch r.URL.Path {
	case "/v1/join":
		m.join(w, r, host)
	case "/v1/sync":
		m.sync(w, r, host)
	case "/v1/leave":
		m.leave(w, r, host)
	default:
		meshError(w, http.StatusNotFound, "not found")
	}
}

func (m *MeshServer) join(w http.ResponseWriter, r *http.Request, host string) {
	var req meshproto.JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		meshError(w, http.StatusBadRequest, "unreadable request")
		return
	}
	var response meshproto.JoinResponse
	err := m.service.Change(func(s *State) error {
		if !s.meshEnabled() {
			return InputError{errors.New("the mesh is turned off on this server")}
		}
		node, secret, err := s.Mesh.Join(&req, time.Now())
		if err != nil {
			return InputError{err}
		}
		response = meshproto.JoinResponse{NodeID: node.ID, Secret: node.ID + "." + secret, Address: node.Address, Status: node.Status}
		return nil
	})
	switch {
	case errors.Is(err, mesh.ErrInvite):
		m.limiter.fail(host)
		meshError(w, http.StatusForbidden, err.Error())
	case err != nil:
		meshError(w, http.StatusBadRequest, err.Error())
	default:
		meshJSON(w, response)
	}
}

// node authenticates a request and returns the node's ID.
func (m *MeshServer) node(w http.ResponseWriter, r *http.Request, host string) (string, bool) {
	credential, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var id string
	if ok {
		m.service.Read(func(s *State) {
			if s.Mesh != nil {
				if node := s.Mesh.Authenticate(credential); node != nil {
					id = node.ID
				}
			}
		})
	}
	if id == "" {
		m.limiter.fail(host)
		meshError(w, http.StatusUnauthorized, "this node is not (or no longer) in the mesh")
		return "", false
	}
	return id, true
}

// response is what a node gets now, and whether the whole mesh is off.
func (m *MeshServer) response(id string) (meshproto.SyncResponse, bool) {
	var out meshproto.SyncResponse
	off := false
	m.service.Read(func(s *State) {
		node := (*mesh.Node)(nil)
		if s.Mesh != nil {
			node = s.Mesh.Node(id)
		}
		switch {
		case node == nil:
			out.Status = meshproto.StatusRemoved
		case !s.Mesh.Enabled:
			out.Status, off = meshproto.StatusDisabled, true
		case node.Status != meshproto.StatusActive:
			out.Status = node.Status
		default:
			config, err := m.service.meshLive.Config(s.Mesh, node, time.Now())
			if err != nil {
				m.service.report("mesh", fmt.Errorf("configuration for %s: %w", node.Name, err))
				out.Status = meshproto.StatusDisabled
				return
			}
			out.Status, out.Config = meshproto.StatusActive, config
		}
	})
	return out, off
}

func (m *MeshServer) sync(w http.ResponseWriter, r *http.Request, host string) {
	id, ok := m.node(w, r, host)
	if !ok {
		return
	}
	var req meshproto.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		meshError(w, http.StatusBadRequest, "unreadable request")
		return
	}
	if err := req.Check(); err != nil {
		meshError(w, http.StatusBadRequest, err.Error())
		return
	}
	// What the node reports about itself is stored when it changes (it rarely does).
	changed := false
	m.service.Read(func(s *State) {
		if node := s.Mesh.Node(id); node != nil {
			changed = node.ListenPort != req.ListenPort || node.Version != req.Version ||
				!slices.Equal(node.Endpoints, req.Endpoints) || !slices.Equal(node.AdvertisedRoutes, req.AdvertiseRoutes)
		}
	})
	if changed {
		err := m.service.Change(func(s *State) error {
			node := s.Mesh.Node(id)
			if node == nil {
				return nil
			}
			node.ListenPort, node.Version = req.ListenPort, req.Version
			node.Endpoints = append([]string{}, req.Endpoints...)
			node.AdvertisedRoutes = append([]string{}, req.AdvertiseRoutes...)
			// A subnet the node stops offering is no longer shared.
			node.ApprovedRoutes = slices.DeleteFunc(node.ApprovedRoutes, func(route string) bool { return !slices.Contains(node.AdvertisedRoutes, route) })
			return nil
		})
		if err != nil {
			meshError(w, http.StatusInternalServerError, "could not save the node's report")
			return
		}
	}
	m.service.meshLive.Record(id, remoteAddr(r), &req, time.Now())
	deadline := time.Now().Add(meshWait)
	for {
		wake := m.service.meshLive.Changed()
		out, off := m.response(id)
		// Answer at once when the node has something to do: apply a new configuration, take its
		// links down or clean up, and when the mesh is turned off (its port is closing). A node
		// waiting for approval, or disabled with nothing set up, waits like an up-to-date one;
		// answering it at once made it ask again at once, over and over.
		answer := off || out.Status == meshproto.StatusRemoved ||
			(out.Status == meshproto.StatusActive && out.Config.Generation != req.Applied) ||
			(out.Status != meshproto.StatusActive && req.Applied != 0)
		if answer || !time.Now().Before(deadline) {
			meshJSON(w, out)
			return
		}
		select {
		case <-wake:
		case <-time.After(time.Until(deadline)):
		case <-r.Context().Done():
			return
		}
	}
}

func (m *MeshServer) leave(w http.ResponseWriter, r *http.Request, host string) {
	id, ok := m.node(w, r, host)
	if !ok {
		return
	}
	if err := m.service.Change(func(s *State) error { s.Mesh.Remove(id); return nil }); err != nil {
		meshError(w, http.StatusInternalServerError, "could not remove the node")
		return
	}
	meshJSON(w, map[string]string{"status": meshproto.StatusRemoved})
}

// --- the admin API (secret path, owner only) ---

type meshInfo struct {
	Enabled  bool             `json:"enabled"`
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	CIDR     string           `json:"cidr"`
	Port     uint16           `json:"port"`
	Ping     bool             `json:"ping"`
	URL      string           `json:"url"`
	Nodes    int              `json:"nodes"`
	Pending  int              `json:"pending"`
	Rules    int              `json:"rules"`
	Invites  []inviteView     `json:"invites"`
	Script   string           `json:"script"`
	Defaults meshDefaultsView `json:"defaults"`
}

type meshDefaultsView struct {
	CIDR        string `json:"cidr"`
	InviteHours int    `json:"invite_hours"`
	ListenPort  int    `json:"listen_port"`
}

type inviteView struct {
	ID          string   `json:"id"`
	CreatedUnix int64    `json:"created_unix"`
	ExpiresUnix int64    `json:"expires_unix"`
	UsesLeft    int      `json:"uses_left"`
	Tags        []string `json:"tags"`
	Relay       bool     `json:"relay"`
	Approval    bool     `json:"approval"`
	Note        string   `json:"note,omitempty"`
}

func (s *State) meshInfo() meshInfo {
	info := meshInfo{Invites: []inviteView{}, Script: MeshScript,
		Defaults: meshDefaultsView{CIDR: mesh.DefaultCIDR, InviteHours: mesh.DefaultInviteHours, ListenPort: meshproto.DefaultPort}}
	if s.Mesh == nil {
		return info
	}
	n := s.Mesh
	info.Enabled, info.ID, info.Name, info.CIDR, info.Port, info.Ping, info.Rules = n.Enabled, n.ID, n.Name, n.CIDR, n.Port, n.Ping, len(n.Rules)
	if n.Port != 0 {
		info.URL = s.meshURL(false)
	}
	for _, node := range n.Nodes {
		info.Nodes++
		if node.Status == meshproto.StatusPending {
			info.Pending++
		}
	}
	now := time.Now().Unix()
	for _, t := range n.Tokens {
		if t.UsesLeft > 0 && now < t.ExpiresUnix {
			info.Invites = append(info.Invites, inviteView{t.ID, t.CreatedUnix, t.ExpiresUnix, t.UsesLeft, t.Tags, t.Relay, t.Approval, t.Note})
		}
	}
	return info
}

func (a *API) getMesh(*http.Request) (int, any, error) {
	var info meshInfo
	a.service.Read(func(s *State) { info = s.meshInfo() })
	return http.StatusOK, info, nil
}

type meshPatch struct {
	Enabled *bool   `json:"enabled"`
	CIDR    *string `json:"cidr"`
	Name    *string `json:"name"`
	Ping    *bool   `json:"ping"`
}

func (a *API) patchMesh(r *http.Request) (int, any, error) {
	var patch meshPatch
	if err := decode(r, &patch); err != nil {
		return 0, nil, err
	}
	var info meshInfo
	err := a.service.Change(func(s *State) error {
		if patch.Enabled != nil && *patch.Enabled || (patch.CIDR != nil && s.Mesh == nil) {
			cidr, name := "", ""
			if patch.CIDR != nil {
				cidr = *patch.CIDR
			}
			if patch.Name != nil {
				name = *patch.Name
			}
			if err := s.enableMesh(cidr, name, portFree); err != nil {
				return InputError{err}
			}
		}
		if s.Mesh == nil {
			return InputError{errors.New("turn the mesh on first")}
		}
		if patch.Name != nil {
			name := strings.TrimSpace(*patch.Name)
			if err := ValidName(name); err != nil {
				return InputError{err}
			}
			s.Mesh.Name = name
		}
		if patch.CIDR != nil && *patch.CIDR != s.Mesh.CIDR {
			// Enable also turns the mesh on; a new network alone must not.
			enabled := s.Mesh.Enabled
			if err := s.Mesh.Enable(*patch.CIDR, "", s.Mesh.Port); err != nil {
				return InputError{err}
			}
			s.Mesh.Enabled = enabled
		}
		if patch.Enabled != nil && !*patch.Enabled {
			s.Mesh.Enabled = false
		}
		if patch.Ping != nil {
			s.Mesh.Ping = *patch.Ping
		}
		info = s.meshInfo()
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, info, nil
}

type inviteRequest struct {
	mesh.InviteOptions
	// Local makes the invite point at 127.0.0.1, for an agent on the coordinator's own host.
	Local bool `json:"local"`
}

type inviteCreated struct {
	inviteView
	Invite  string `json:"invite"`
	Command string `json:"command"`
}

func (a *API) createInvite(r *http.Request) (int, any, error) {
	var request inviteRequest
	if err := decode(r, &request); err != nil {
		return 0, nil, err
	}
	var out inviteCreated
	err := a.service.Change(func(s *State) error {
		if !s.meshEnabled() {
			return InputError{errors.New("turn the mesh on first")}
		}
		pin, err := s.CertSHA256()
		if err != nil {
			return err
		}
		t, secret, err := s.Mesh.CreateToken(request.InviteOptions, time.Now())
		if err != nil {
			return InputError{err}
		}
		out.inviteView = inviteView{t.ID, t.CreatedUnix, t.ExpiresUnix, t.UsesLeft, t.Tags, t.Relay, t.Approval, t.Note}
		out.Invite = meshproto.EncodeInvite(meshproto.Invite{URL: s.meshURL(request.Local), Pin: pin, Token: secret})
		out.Command = fmt.Sprintf("curl -fsSL %s | sudo bash -s -- --join '%s'", MeshScript, out.Invite)
		if t.Relay {
			// Forwarding needs the server's own consent: running a command that says --relay is it.
			out.Command += " --relay"
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, out, nil
}

func (a *API) listInvites(*http.Request) (int, any, error) {
	var info meshInfo
	a.service.Read(func(s *State) { info = s.meshInfo() })
	return http.StatusOK, info.Invites, nil
}

func (a *API) deleteInvite(r *http.Request) (int, any, error) {
	err := a.service.Change(func(s *State) error {
		if s.Mesh == nil || !s.Mesh.RevokeToken(r.PathValue("id")) {
			return fmt.Errorf("invite %w", errNotFound)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

func (a *API) patchMeshNode(r *http.Request) (int, any, error) {
	var change mesh.NodeChange
	if err := decode(r, &change); err != nil {
		return 0, nil, err
	}
	var view mesh.NodeView
	err := a.service.Change(func(s *State) error {
		node := (*mesh.Node)(nil)
		if s.Mesh != nil {
			node = s.Mesh.Node(r.PathValue("id"))
		}
		if node == nil {
			return fmt.Errorf("node %w", errNotFound)
		}
		if err := s.Mesh.Update(node, change); err != nil {
			return InputError{err}
		}
		for _, v := range a.service.meshLive.Topology(s.Mesh, time.Now()).Nodes {
			if v.ID == node.ID {
				view = v
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, view, nil
}

func (a *API) deleteMeshNode(r *http.Request) (int, any, error) {
	err := a.service.Change(func(s *State) error {
		if s.Mesh == nil || !s.Mesh.Remove(r.PathValue("id")) {
			return fmt.Errorf("node %w", errNotFound)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

func (a *API) getMeshRules(*http.Request) (int, any, error) {
	rules := []mesh.Rule{}
	a.service.Read(func(s *State) {
		if s.Mesh != nil && s.Mesh.Rules != nil {
			rules = s.Mesh.Rules
		}
	})
	return http.StatusOK, map[string]any{"rules": rules}, nil
}

func (a *API) putMeshRules(r *http.Request) (int, any, error) {
	var body struct {
		Rules []mesh.Rule `json:"rules"`
	}
	if err := decode(r, &body); err != nil {
		return 0, nil, err
	}
	if body.Rules == nil {
		body.Rules = []mesh.Rule{}
	}
	err := a.service.Change(func(s *State) error {
		if s.Mesh == nil {
			return InputError{errors.New("turn the mesh on first")}
		}
		if err := s.Mesh.SetRules(body.Rules); err != nil {
			return InputError{err}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"rules": body.Rules}, nil
}

func (a *API) meshTopology(*http.Request) (int, any, error) {
	topology := mesh.Topology{Nodes: []mesh.NodeView{}, Links: []mesh.LinkView{}}
	a.service.Read(func(s *State) {
		if s.Mesh != nil {
			topology = a.service.meshLive.Topology(s.Mesh, time.Now())
		}
	})
	return http.StatusOK, topology, nil
}
