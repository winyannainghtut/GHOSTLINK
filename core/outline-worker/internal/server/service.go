// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
)

// Service ties stored state, the running engine and usage accounting together. Every change
// is applied to a copy, started in the engine and only then saved, so a change the engine
// refuses (for example a port already in use) leaves the server as it was.
type Service struct {
	store  *Store
	engine *Engine
	usage  *Usage
}

func NewService(store *Store, engine *Engine, usage *Usage) *Service {
	return &Service{store: store, engine: engine, usage: usage}
}

func clone(state *State) (*State, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var copied State
	return &copied, json.Unmarshal(data, &copied)
}

// Start runs the engine for the stored state.
func (s *Service) Start() error {
	s.store.Lock()
	defer s.store.Unlock()
	return s.engine.Apply(s.store.State)
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
	s.store.Lock()
	defer s.store.Unlock()
	next, err := clone(s.store.State)
	if err != nil {
		return err
	}
	if err := fn(next); err != nil {
		return err
	}
	if err := next.CheckPorts(); err != nil {
		return InputError{err}
	}
	before, err := s.store.State.EngineConfig(s.engine.logLevel)
	if err != nil {
		return err
	}
	after, err := next.EngineConfig(s.engine.logLevel)
	if err != nil {
		return err
	}
	reload := !bytes.Equal(before, after)
	if reload {
		if err := s.engine.Apply(next); err != nil {
			return err
		}
	}
	previous := s.store.State
	s.store.State = next
	if err := s.store.Save(); err != nil {
		s.store.State = previous
		if reload {
			_ = s.engine.Apply(previous)
		}
		return err
	}
	return nil
}

// Account adds counted traffic to each user; users who reach their data limit are removed
// from the engine, which also ends their open connections.
func (s *Service) Account() error {
	counted := s.usage.Drain()
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

// RunAccounting records usage every interval until ctx ends, then once more.
func (s *Service) RunAccounting(ctx context.Context, interval time.Duration, report func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.Account(); err != nil {
				report(err)
			}
			return
		case <-ticker.C:
			if err := s.Account(); err != nil {
				report(err)
			}
		}
	}
}

func (s *Service) Close() error { return s.engine.Close() }

// InputError is a problem with the request rather than the server.
type InputError struct{ Err error }

func (e InputError) Error() string { return e.Err.Error() }
func (e InputError) Unwrap() error { return e.Err }
