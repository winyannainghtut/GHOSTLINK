// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build !linux

package server

// The server runs on Linux; elsewhere (development) health readings are simply unavailable.

func diskSpace(string) (uint64, uint64, bool) { return 0, 0, false }
func cpuTimes() (uint64, uint64, bool)        { return 0, 0, false }
func memory() (uint64, uint64, bool)          { return 0, 0, false }
func loadAverage() (float64, bool)            { return 0, false }
func networkBytes() (uint64, uint64, bool)    { return 0, 0, false }
