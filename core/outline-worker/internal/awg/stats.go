// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package awg

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// parseTransfer extracts rx/tx byte counters per peer from UAPI "get" output, keyed by the
// peer's base64 public key.
func parseTransfer(state string) map[string][2]uint64 {
	result := make(map[string][2]uint64)
	current := ""
	for _, line := range strings.Split(state, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "public_key":
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != 32 {
				current = ""
				continue
			}
			current = base64.StdEncoding.EncodeToString(raw)
			result[current] = [2]uint64{}
		case "rx_bytes", "tx_bytes":
			if current == "" {
				continue
			}
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			counters := result[current]
			if key == "rx_bytes" {
				counters[0] = n
			} else {
				counters[1] = n
			}
			result[current] = counters
		}
	}
	return result
}
