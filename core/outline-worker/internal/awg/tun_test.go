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

	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
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

// amneziawg-go reads the device's events until the channel closes, and nothing else stops that
// reader. The channel must close with the adapter, or each closed device stays in memory with
// its reader; the server closes one or two devices on every engine reload.
func TestTunAdapterEventsCloseWithIt(t *testing.T) {
	for name, stop := range map[string]func(*tunAdapter, *closingDevice){
		"adapter closed": func(adapter *tunAdapter, _ *closingDevice) { adapter.Close() },
		"stack closed":   func(_ *tunAdapter, device *closingDevice) { close(device.events) },
	} {
		t.Run(name, func(t *testing.T) {
			device := &closingDevice{events: make(chan wgTun.Event, 1)}
			adapter := newTunAdapter(device)
			device.events <- wgTun.EventUp
			if event := <-adapter.Events(); event != awgtun.EventUp {
				t.Fatalf("got event %v, want up", event)
			}
			stop(adapter, device)
			select {
			case _, open := <-adapter.Events():
				if open {
					t.Fatal("an event arrived after the stop")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the events channel stayed open")
			}
		})
	}
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
