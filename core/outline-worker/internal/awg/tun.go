// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package awg

import (
	"os"
	"sync"

	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/sagernet/sing-box/transport/wireguard"
)

// tunAdapter presents sing-box's userspace gVisor stack device as an amneziawg-go tun.Device.
// The method sets are identical except for the Event type, which is converted here.
type tunAdapter struct {
	wireguard.Device
	events    chan awgtun.Event
	done      chan struct{}
	closeOnce sync.Once
	// amneziawg-go closes the TUN before it stops its peers, so a peer can still deliver a packet
	// after Close. The userspace stack drops its packet dispatcher when it closes, so such a late
	// write would crash; state makes Close wait for writes in flight and refuses later ones.
	state  sync.RWMutex
	closed bool
}

func newTunAdapter(device wireguard.Device) *tunAdapter {
	adapter := &tunAdapter{
		Device: device,
		events: make(chan awgtun.Event, 4),
		done:   make(chan struct{}),
	}
	go func() {
		// amneziawg-go reads events until the channel closes, and nothing else ends that reader,
		// so close it once forwarding stops. This goroutine is the only sender.
		defer close(adapter.events)
		source := device.Events()
		for {
			select {
			case event, ok := <-source:
				if !ok {
					return
				}
				select {
				case adapter.events <- awgtun.Event(event):
				case <-adapter.done:
					return
				}
			case <-adapter.done:
				return
			}
		}
	}()
	return adapter
}

func (a *tunAdapter) Events() <-chan awgtun.Event {
	return a.events
}

func (a *tunAdapter) Write(bufs [][]byte, offset int) (int, error) {
	a.state.RLock()
	defer a.state.RUnlock()
	if a.closed {
		return 0, os.ErrClosed
	}
	return a.Device.Write(bufs, offset)
}

func (a *tunAdapter) Close() error {
	a.closeOnce.Do(func() { close(a.done) })
	a.state.Lock()
	a.closed = true
	a.state.Unlock()
	return a.Device.Close()
}
