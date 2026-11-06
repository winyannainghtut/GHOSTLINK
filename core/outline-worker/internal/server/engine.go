// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"errors"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/vless"
	boxjson "github.com/sagernet/sing/common/json"

	"ghostlink.local/outline-worker/internal/awg"
)

// EngineContext registers exactly the protocols the server hosts.
func EngineContext() context.Context {
	in := inbound.NewRegistry()
	shadowsocks.RegisterInbound(in)
	vless.RegisterInbound(in)
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	endpoints := endpoint.NewRegistry()
	awg.Register(endpoints)
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	return box.Context(context.Background(), in, out, endpoints, dnsRegistry,
		boxservice.NewRegistry(), certificate.NewRegistry())
}

func newBox(config []byte) (*box.Box, error) {
	ctx := EngineContext()
	options, err := boxjson.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return nil, err
	}
	return box.New(box.Options{Context: ctx, Options: options})
}

// Check renders and fully validates the engine configuration without opening any port.
func Check(state *State) error {
	config, err := state.EngineConfig("error")
	if err != nil {
		return err
	}
	instance, err := newBox(config)
	if err != nil {
		return err
	}
	return instance.Close()
}

// Engine runs one sing-box instance and replaces it when the state changes.
type Engine struct {
	mu       sync.Mutex
	box      *box.Box
	lastGood []byte
	usage    *Usage
	logLevel string
}

func NewEngine(usage *Usage, logLevel string) *Engine {
	return &Engine{usage: usage, logLevel: logLevel}
}

func (e *Engine) start(config []byte) (*box.Box, error) {
	instance, err := newBox(config)
	if err != nil {
		return nil, err
	}
	instance.Router().AppendTracker(e.usage)
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, err
	}
	return instance, nil
}

// Apply switches to the configuration for state. Ports are released before the new instance
// binds them; if the new one fails to start, the previous configuration is restored.
func (e *Engine) Apply(state *State) error {
	config, err := state.EngineConfig(e.logLevel)
	if err != nil {
		return err
	}
	// Validate fully before touching the running instance.
	if candidate, err := newBox(config); err != nil {
		return err
	} else {
		candidate.Close()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box != nil {
		e.box.Close()
		e.box = nil
	}
	instance, err := e.start(config)
	if err != nil {
		if e.lastGood != nil {
			if previous, restoreErr := e.start(e.lastGood); restoreErr == nil {
				e.box = previous
			} else {
				err = errors.Join(err, restoreErr)
			}
		}
		return err
	}
	e.box, e.lastGood = instance, config
	return nil
}

// Close stops the engine.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil {
		return nil
	}
	err := e.box.Close()
	e.box = nil
	return err
}
