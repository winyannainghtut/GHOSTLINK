// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build unix

package main

import (
	"os/signal"
	"syscall"
)

// ignoreBrokenPipe keeps a write to a closed stderr (for example after the daemon died) from
// killing the worker with SIGPIPE before the engine's graceful Close has run.
func ignoreBrokenPipe() {
	signal.Ignore(syscall.SIGPIPE)
}
