// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package awg

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PeerStatus is what amneziawg-go reports for one peer.
type PeerStatus struct {
	RxBytes uint64
	TxBytes uint64
	// Endpoint is the peer's current public address (zero until it has sent a packet).
	Endpoint netip.AddrPort
	// LastHandshake is zero if the peer never completed a handshake.
	LastHandshake time.Time
}

// parsePeers extracts per-peer status from UAPI "get" output, keyed by the peer's base64
// public key.
func parsePeers(state string) map[string]PeerStatus {
	result := make(map[string]PeerStatus)
	current := ""
	var handshakeSeconds int64
	for _, line := range strings.Split(state, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if key == "public_key" {
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != 32 {
				current = ""
				continue
			}
			current = base64.StdEncoding.EncodeToString(raw)
			result[current] = PeerStatus{}
			handshakeSeconds = 0
			continue
		}
		if current == "" {
			continue
		}
		status := result[current]
		switch key {
		case "rx_bytes":
			status.RxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			status.TxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "endpoint":
			if endpoint, err := netip.ParseAddrPort(value); err == nil {
				status.Endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
			}
		case "last_handshake_time_sec":
			handshakeSeconds, _ = strconv.ParseInt(value, 10, 64)
			if handshakeSeconds > 0 {
				status.LastHandshake = time.Unix(handshakeSeconds, 0)
			}
		case "last_handshake_time_nsec":
			if nanoseconds, err := strconv.ParseInt(value, 10, 64); err == nil && handshakeSeconds > 0 {
				status.LastHandshake = time.Unix(handshakeSeconds, nanoseconds)
			}
		}
		result[current] = status
	}
	return result
}

// parseTransfer extracts rx/tx byte counters per peer, keyed by the base64 public key.
func parseTransfer(state string) map[string][2]uint64 {
	result := make(map[string][2]uint64)
	for key, status := range parsePeers(state) {
		result[key] = [2]uint64{status.RxBytes, status.TxBytes}
	}
	return result
}
