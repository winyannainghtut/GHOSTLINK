// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Usage counts bytes per user (both directions) for every routed connection and flow.
// One Usage outlives engine reloads, so nothing is lost when the configuration changes.
type Usage struct {
	mu       sync.Mutex
	counters map[string]*atomic.Int64
}

var _ adapter.ConnectionTracker = (*Usage)(nil)

func NewUsage() *Usage { return &Usage{counters: map[string]*atomic.Int64{}} }

func (u *Usage) counter(user string) *atomic.Int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	c, ok := u.counters[user]
	if !ok {
		c = new(atomic.Int64)
		u.counters[user] = c
	}
	return c
}

// Drain returns the bytes counted since the last call, per user tag.
func (u *Usage) Drain() map[string]uint64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	result := map[string]uint64{}
	for user, c := range u.counters {
		if n := c.Swap(0); n > 0 {
			result[user] = uint64(n)
		}
	}
	return result
}

func (u *Usage) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if metadata.User == "" {
		return conn
	}
	c := []*atomic.Int64{u.counter(metadata.User)}
	return bufio.NewInt64CounterConn(conn, c, c)
}

func (u *Usage) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	if metadata.User == "" {
		return conn
	}
	c := []*atomic.Int64{u.counter(metadata.User)}
	return bufio.NewInt64CounterPacketConn(conn, c, nil, c, nil)
}

func (u *Usage) RoutedFlow(_ context.Context, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	if metadata.User == "" {
		return nil
	}
	return flowCounter{u.counter(metadata.User)}
}

type flowCounter struct{ c *atomic.Int64 }

func (f flowCounter) AttachFlow(tun.FlowHandle)     {}
func (f flowCounter) CountForward(n int)            { f.c.Add(int64(n)) }
func (f flowCounter) CountReverse(n int)            { f.c.Add(int64(n)) }
func (f flowCounter) FlowEstablished()              {}
func (f flowCounter) CloseFlow(tun.FlowCloseReason) {}
