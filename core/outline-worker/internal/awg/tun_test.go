// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package awg

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/wireguard"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

// closingDevice stands in for the userspace stack: like it, it must never be written to after
// Close (the real one dereferences its detached packet dispatcher and crashes).
type closingDevice struct {
	wireguard.Device
	events chan wgTun.Event
	closed atomic.Bool
	writes atomic.Int64
}

func (d *closingDevice) Events() <-chan wgTun.Event { return d.events }

func (d *closingDevice) Write(bufs [][]byte, offset int) (int, error) {
	if d.closed.Load() {
		panic("write after close")
	}
	d.writes.Add(1)
	time.Sleep(50 * time.Microsecond)
	return len(bufs), nil
}

func (d *closingDevice) Close() error {
	d.closed.Store(true)
	return nil
}

// Regression: on Linux CI an AmneziaWG client crashed during graceful stop because a peer
// goroutine wrote a received packet after amneziawg-go had closed the TUN.
func TestTunAdapterRefusesWritesAfterClose(t *testing.T) {
	for round := 0; round < 50; round++ {
		device := &closingDevice{events: make(chan wgTun.Event)}
		adapter := newTunAdapter(device)
		var writers sync.WaitGroup
		for i := 0; i < 8; i++ {
			writers.Add(1)
			go func() {
				defer writers.Done()
				for {
					if _, err := adapter.Write([][]byte{{0x45}}, 0); err != nil {
						if !errors.Is(err, os.ErrClosed) {
							t.Errorf("unexpected error %v", err)
						}
						return
					}
				}
			}()
		}
		time.Sleep(time.Millisecond)
		if err := adapter.Close(); err != nil {
			t.Fatal(err)
		}
		writers.Wait()
		if device.writes.Load() == 0 {
			t.Fatal("no writes reached the device before Close")
		}
	}
}
