// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package awg

import (
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
}

func newTunAdapter(device wireguard.Device) *tunAdapter {
	adapter := &tunAdapter{
		Device: device,
		events: make(chan awgtun.Event, 4),
		done:   make(chan struct{}),
	}
	go func() {
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

func (a *tunAdapter) Close() error {
	a.closeOnce.Do(func() { close(a.done) })
	return a.Device.Close()
}
