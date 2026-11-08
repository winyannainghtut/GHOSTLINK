// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package version holds the one Ghostlink version shared by the four programs this module
// builds: the tunnel worker, the server, the mesh agent and the IPsec agent.
// scripts/release-version.mjs checks it against the Cargo workspace version.
package version

const (
	Ghostlink = "0.8.1"
	// Engines names the unmodified upstream implementations linked into the tunnel worker and
	// the server.
	Engines = "sing-box 1.14.4; amneziawg-go 3.1.20260828"
	// Worker is the exact line `ghostlink-tunnel version` prints; the Rust service requires it.
	Worker = "Ghostlink tunnel worker " + Ghostlink + "; " + Engines
	// Server is what `ghostlink-server version` prints.
	Server = "Ghostlink server " + Ghostlink + "; " + Engines
)
