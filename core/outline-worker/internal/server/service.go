// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"ghostlink.local/outline-worker/internal/mesh"
)

// Service ties stored state, the running engine and monitoring together. Every change is
// applied to a copy, started in the engine and only then saved, so a change the engine refuses
// (for example a port already in use) leaves the server as it was.
type Service struct {
	store        *Store
	engine       *Engine
	monitor      *Monitor
	health       *healthSampler
	hooksMu      sync.Mutex
	hooks        []func(previous, next *State)
	historyBytes atomic.Int64
	report       func(string, error)
	// ipsecSeen holds the agent's last byte counters per SA child (touched by Run only).
	ipsecSeen map[string][2]uint64
	// meshLive is what mesh agents last reported, and which pairs are relayed.
	meshLive *mesh.Live
}

func NewService(store *Store, engine *Engine, monitor *Monitor) *Service {
	service := &Service{store: store, engine: engine, monitor: monitor, health: newHealthSampler(),
		report: func(string, error) {}, ipsecSeen: map[string][2]uint64{}, meshLive: mesh.NewLive()}
	// Mesh agents waiting for a new configuration wake on every change to the mesh.
	service.OnChange(func(previous, next *State) {
		before, _ := json.Marshal(previous.Mesh)
		after, _ := json.Marshal(next.Mesh)
		if bytes.Equal(before, after) {
			return
		}
		if previous.Mesh != nil {
			for _, node := range previous.Mesh.Nodes {
				if next.Mesh == nil || next.Mesh.Node(node.ID) == nil {
					service.meshLive.Forget(node.ID)
				}
			}
		}
		service.meshLive.Notify()
	})
	// The IPsec agent follows every saved change.
	service.OnChange(func(previous, next *State) {
		if previous.appleEnabled() || next.appleEnabled() {
			if err := service.WriteIPsecDesired(time.Now()); err != nil {
				service.report("ipsec", err)
			}
		}
	})
	return service
}

// OnChange registers fn to run after every saved change, outside the state lock.
func (s *Service) OnChange(fn func(previous, next *State)) {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	s.hooks = append(s.hooks, fn)
}

// SetReporter receives background errors (they are logged by the server command).
func (s *Service) SetReporter(fn func(string, error)) { s.report = fn }

func (s *Service) historyPath() string { return filepath.Join(s.store.Dir(), HistoryFile) }

func clone(state *State) (*State, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var copied State
	return &copied, json.Unmarshal(data, &copied)
}

// Start loads recorded history and runs the engine for the stored state.
func (s *Service) Start() error {
	if err := s.monitor.LoadHistory(s.historyPath()); err != nil {
		s.report("history", err)
	}
	s.store.Lock()
	defer s.store.Unlock()
	s.monitor.SetSiteStats(s.store.State.Monitor.SiteStats)
	s.monitor.SetSpeedLimits(s.store.State.speedLimits())
	if err := s.engine.Apply(s.store.State); err != nil {
		return err
	}
	if s.store.State.appleEnabled() {
		go func() {
			if err := s.WriteIPsecDesired(time.Now()); err != nil {
				s.report("ipsec", err)
			}
		}()
	}
	return nil
}

// RenewIPsec reissues the server certificate when it nears expiry or the address changed, and
// rewrites the agent's configuration so its CRL stays current.
func (s *Service) RenewIPsec(now time.Time) {
	enabled := false
	s.Read(func(state *State) { enabled = state.appleEnabled() })
	if !enabled {
		return
	}
	if err := s.Change(func(state *State) error { return state.ensureIPsecPKI(now, portFree) }); err != nil {
		s.report("ipsec", err)
	}
	if err := s.WriteIPsecDesired(now); err != nil {
		s.report("ipsec", err)
	}
}

// Read runs fn with the current state; fn must not modify it.
func (s *Service) Read(fn func(*State)) {
	s.store.Lock()
	defer s.store.Unlock()
	fn(s.store.State)
}

// Change applies fn to a copy of the state. If the engine configuration changes, the engine
// restarts with it first; the state is saved only if that worked.
func (s *Service) Change(fn func(*State) error) error {
	previous, next, err := s.change(fn)
	if err != nil || previous == nil {
		return err
	}
	if previous.Monitor.SiteStats != next.Monitor.SiteStats {
		s.monitor.SetSiteStats(next.Monitor.SiteStats)
	}
	// Speed limits are not part of the engine configuration: they change live, with no reload.
	// They are read from the current state under its lock, so two changes at once cannot leave
	// the older one in force.
	s.Read(func(current *State) { s.monitor.SetSpeedLimits(current.speedLimits()) })
	for _, u := range previous.Users {
		if next.User(u.ID) == nil {
			s.monitor.Forget(u.Tag())
		}
	}
	s.hooksMu.Lock()
	hooks := append([]func(*State, *State){}, s.hooks...)
	s.hooksMu.Unlock()
	for _, hook := range hooks {
		hook(previous, next)
	}
	return nil
}

func (s *Service) change(fn func(*State) error) (*State, *State, error) {
	s.store.Lock()
	defer s.store.Unlock()
	next, err := clone(s.store.State)
	if err != nil {
		return nil, nil, err
	}
	if err := fn(next); err != nil {
		return nil, nil, err
	}
	if err := next.CheckPorts(); err != nil {
		return nil, nil, InputError{err}
	}
	before, err := s.store.State.EngineConfig(s.engine.logLevel)
	if err != nil {
		return nil, nil, err
	}
	after, err := next.EngineConfig(s.engine.logLevel)
	if err != nil {
		return nil, nil, err
	}
	reload := !bytes.Equal(before, after)
	if reload {
		if err := s.engine.Apply(next); err != nil {
			return nil, nil, err
		}
	}
	previous := s.store.State
	s.store.State = next
	if err := s.store.Save(); err != nil {
		s.store.State = previous
		if reload {
			_ = s.engine.Apply(previous)
		}
		return nil, nil, err
	}
	snapshot, err := clone(next)
	if err != nil {
		return nil, nil, err
	}
	return previous, snapshot, nil
}

// Account adds counted traffic to each user; users who reach their data limit are removed
// from the engine, which also ends their open connections.
func (s *Service) Account() error {
	counted := s.monitor.Drain()
	if len(counted) == 0 {
		return nil
	}
	return s.Change(func(state *State) error {
		for _, u := range state.Users {
			if n, ok := counted[u.Tag()]; ok {
				u.UsageBytes += n
				u.refreshLimit()
			}
		}
		return nil
	})
}

// pollPeers maps WireGuard/AmneziaWG peers back to users for their addresses, handshakes and
// whether they are still sending (see Monitor.PeersSeen).
func (s *Service) pollPeers(now time.Time) {
	byKey := map[string]string{}
	s.Read(func(state *State) {
		for _, u := range state.Users {
			for _, k := range u.Keys {
				if k.PublicKey != "" {
					byKey[k.Protocol+"/"+k.PublicKey] = u.Tag()
				}
			}
		}
	})
	var reports []PeerReport
	for protocol, peers := range s.engine.PeerStatus() {
		for key, status := range peers {
			if user, ok := byKey[protocol+"/"+key]; ok {
				reports = append(reports, PeerReport{User: user, Protocol: protocol, Key: key, Status: status})
			}
		}
	}
	s.monitor.PeersSeen(reports, now)
}

func (s *Service) settings() MonitorSettings {
	var settings MonitorSettings
	s.Read(func(state *State) { settings = state.Monitor })
	return settings
}

// Record flushes counted traffic into the history and checks the disk; it is safe to call at
// any time (the API calls it before answering statistics).
func (s *Service) Record(now time.Time) {
	s.pollPeers(now)
	s.monitor.Flush(now)
	if paused, changed := s.monitor.CheckDisk(s.store.Dir()); changed {
		if paused {
			s.report("disk", errLowDisk)
		} else {
			s.report("disk", nil)
		}
	}
}

// SaveHistory rotates and writes recorded traffic.
func (s *Service) SaveHistory(now time.Time) {
	size, err := s.monitor.SaveHistory(s.historyPath(), now, s.settings())
	if err != nil {
		s.report("history", err)
		return
	}
	s.historyBytes.Store(int64(size))
}

// Health returns the host snapshot plus monitoring state.
func (s *Service) Health() Health {
	health := s.health.Snapshot(s.store.Dir())
	health.EngineReloads = s.engine.Reloads()
	health.DetailPaused = s.monitor.detailPaused.Load()
	health.HistoryBytes = int(s.historyBytes.Load())
	return health
}

// Run samples rates every second, polls WireGuard/AmneziaWG peers and the IPsec component every
// 5 s, records and enforces limits every 30 s and saves history every 5 minutes, until ctx
// ends; then it records and saves once more.
func (s *Service) Run(ctx context.Context) {
	second := time.NewTicker(time.Second)
	defer second.Stop()
	var ticks int
	for {
		select {
		case <-ctx.Done():
			now := time.Now()
			if err := s.Account(); err != nil {
				s.report("usage", err)
			}
			s.Record(now)
			s.SaveHistory(now)
			return
		case now := <-second.C:
			ticks++
			s.monitor.Sample(now)
			if ticks%5 == 0 {
				s.health.Sample(now)
				// Often enough that a client who left shows as idle within about a minute.
				s.pollPeers(now)
				s.recordIPsec(now)
				s.Read(func(state *State) {
					if state.meshEnabled() {
						s.meshLive.Tick(state.Mesh, now)
					}
				})
			}
			if ticks%86400 == 0 {
				s.RenewIPsec(now)
			}
			if ticks%30 == 0 {
				if err := s.Account(); err != nil {
					s.report("usage", err)
				}
				s.Record(now)
			}
			if ticks%300 == 0 {
				s.SaveHistory(now)
			}
		}
	}
}

func (s *Service) Close() error { return s.engine.Close() }

// InputError is a problem with the request rather than the server.
type InputError struct{ Err error }

func (e InputError) Error() string { return e.Err.Error() }
func (e InputError) Unwrap() error { return e.Err }

type lowDisk struct{}

func (lowDisk) Error() string {
	return "the disk is nearly full; detailed traffic recording is paused until space is freed"
}

var errLowDisk error = lowDisk{}
