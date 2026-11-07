// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

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
