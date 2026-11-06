// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build !unix

package main

// ignoreBrokenPipe is a no-op where broken pipes return errors instead of raising a signal.
func ignoreBrokenPipe() {}
