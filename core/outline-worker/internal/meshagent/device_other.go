// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build !linux

package meshagent

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Windows servers and clients are planned for a later release; the agent runs on Linux only.
var errLinuxOnly = errors.New("ghostlink-mesh runs on Linux only in this version")

type device struct{}

func openDevice(string) (*device, error)                               { return nil, errLinuxOnly }
func (d *device) configure(string, uint16, []wgtypes.PeerConfig) error { return errLinuxOnly }
func (d *device) peers() ([]wgtypes.Peer, error)                       { return nil, errLinuxOnly }
func (d *device) setAddress(string) error                              { return errLinuxOnly }
func (d *device) setRoutes([]string) error                             { return errLinuxOnly }
func (d *device) close()                                               {}
func removeInterface(string)                                           {}
func readForwarding() string                                           { return "" }
func writeForwarding(string) error                                     { return errLinuxOnly }

type pinger struct{}

func newPinger() *pinger                     { return &pinger{} }
func (p *pinger) setTargets([]string)        {}
func (p *pinger) snapshot() map[string]int64 { return map[string]int64{} }
func (p *pinger) run(<-chan struct{})        {}
