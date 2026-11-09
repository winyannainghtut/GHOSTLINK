// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build !linux

package server

// listenFloor: other systems (where tests and development builds run) let any port be tried.
func listenFloor() uint16 { return 1 }
