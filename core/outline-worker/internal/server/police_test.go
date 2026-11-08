// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// replies hands out count packets of size bytes, like UDP replies from the internet.
type replies struct{ count, size int }

func (r *replies) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if r.count == 0 {
		return M.Socksaddr{}, io.EOF
	}
	r.count--
	buffer.Extend(r.size)
	return M.ParseSocksaddrHostPort("198.51.100.9", 123), nil
}
func (r *replies) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}
func (r *replies) Close() error                     { return nil }
func (r *replies) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (r *replies) SetDeadline(time.Time) error      { return nil }
func (r *replies) SetReadDeadline(time.Time) error  { return nil }
func (r *replies) SetWriteDeadline(time.Time) error { return nil }

// framingInbound is a client's UDP connection whose writer, like Shadowsocks', puts a header in
// front of each packet and a tag after it, in the room the copy loop reserves for it.
type framingInbound struct {
	front, rear int
	written     int
}

func (f *framingInbound) ReadPacket(*buf.Buffer) (M.Socksaddr, error) { return M.Socksaddr{}, io.EOF }
func (f *framingInbound) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	buffer.ExtendHeader(f.front) // panics without the room, as the Shadowsocks writer did
	buffer.Extend(f.rear)
	f.written++
	return nil
}
func (f *framingInbound) FrontHeadroom() int               { return f.front }
func (f *framingInbound) RearHeadroom() int                { return f.rear }
func (f *framingInbound) Close() error                     { return nil }
func (f *framingInbound) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *framingInbound) SetDeadline(time.Time) error      { return nil }
func (f *framingInbound) SetReadDeadline(time.Time) error  { return nil }
func (f *framingInbound) SetWriteDeadline(time.Time) error { return nil }

// UDP replies reach a client through its tracked, policed connection with the header and tag
// room its writer needs. Without that room the Shadowsocks writer overflowed its buffer on the
// first reply, and the panic stopped the whole server.
func TestUDPRepliesKeepTheWritersHeadroom(t *testing.T) {
	for _, limit := range []int64{0, 1_000_000} {
		m := NewMonitor()
		if limit > 0 {
			m.SetSpeedLimits(map[string]int64{"u1": limit})
		}
		inbound := &framingInbound{front: 55, rear: 16}
		conn := m.RoutedPacketConnection(context.Background(), inbound, adapter.InboundContext{User: "u1", Inbound: Shadowsocks}, nil, nil)
		if _, err := bufio.CopyPacket(conn, &replies{count: 20, size: 1200}); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("limit %d: %v", limit, err)
		}
		if inbound.written != 20 {
			t.Fatalf("limit %d: %d of 20 replies reached the client", limit, inbound.written)
		}
	}
}

// burstPackets hands out count packets of size bytes as fast as they are read.
type burstPackets struct {
	N.PacketConn
	count, size int
}

func (b *burstPackets) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if b.count == 0 {
		return M.Socksaddr{}, io.EOF
	}
	b.count--
	buffer.Extend(b.size)
	return M.Socksaddr{}, nil
}

// A capped client's UDP above its rate is dropped at once, never waited for: the Shadowsocks
// inbound feeds all clients' UDP from one loop, which must not be held up.
func TestPolicedPacketConnDropsInsteadOfWaiting(t *testing.T) {
	var p pacer
	p.SetRate(100_000) // 100 KB/s: burst 64 KiB
	source := &burstPackets{count: 1000, size: 10_000}
	conn := &policedPacketConn{PacketConn: source, pace: &p}
	start := time.Now()
	delivered := 0
	for {
		buffer := buf.NewPacket()
		buffer.Resize(32, 0) // front headroom, as the copy loops reserve it
		_, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			break
		}
		if buffer.Start() != 32 || buffer.Len() != 10_000 {
			t.Fatalf("a delivered packet lost its headroom or size: start %d, len %d", buffer.Start(), buffer.Len())
		}
		delivered++
		buffer.Release()
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("reading 10 MB of UDP took %v: the policer waited", elapsed)
	}
	allowed := (64<<10 + elapsed.Seconds()*100_000) / 10_000
	if delivered < 6 || float64(delivered) > allowed+1 {
		t.Fatalf("%d of 1000 packets passed; the rate allows about %.0f", delivered, allowed)
	}
	// Unlimited clients lose nothing.
	p.SetRate(0)
	source.count = 50
	for range 50 {
		buffer := buf.NewPacket()
		if _, err := conn.ReadPacket(buffer); err != nil {
			t.Fatalf("unlimited: %v", err)
		}
		buffer.Release()
	}
}
