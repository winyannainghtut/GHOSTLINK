// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// listenFloor is the lowest port this process can listen on: 1 when it holds NET_BIND_SERVICE
// (the host script's container gives the server that capability), else the kernel's
// net.ipv4.ip_unprivileged_port_start, 1024 unless changed.
func listenFloor() uint16 {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) == nil && data[0].Effective&(1<<unix.CAP_NET_BIND_SERVICE) != 0 {
		return 1
	}
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		return 1024
	}
	start, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || start > 65535 {
		return 1024
	}
	return uint16(max(1, start))
}
