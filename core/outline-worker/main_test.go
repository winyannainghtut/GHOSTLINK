// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"github.com/sagernet/sing-box/option"
	"net"
	"net/netip"
	"testing"
)

func TestExistingInterfaceAndOverlappingAddressAreRejected(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Fatal("Cannot inspect local network interfaces")
	}
	if !checkInterfaceCollision(&option.TunInboundOptions{InterfaceName: interfaces[0].Name}) {
		t.Fatal("Existing interface was accepted")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		options := &option.TunInboundOptions{InterfaceName: "ghostlink-conflict-test-never-created"}
		options.Address = append(options.Address, prefix)
		if !checkInterfaceCollision(options) {
			t.Fatal("Overlapping local address was accepted")
		}
		return
	}
	t.Fatal("No local IP address available for the collision test")
}

// A wider network that only contains the TUN range, such as the /20 a Hyper-V or WSL switch takes
// from 172.16.0.0/12 at random, must not fail every connection. Only an address inside the range
// collides.
func TestOnlyAddressesInsideTheTunnelRangeCollide(t *testing.T) {
	for _, tc := range []struct {
		existing, requested string
		collides            bool
	}{
		{"172.28.80.1/20", "172.28.85.1/30", false}, // Hyper-V Default Switch or WSL
		{"172.28.0.1/16", "172.28.85.1/30", false},  // a Docker bridge
		{"192.0.2.10/24", "172.28.85.1/30", false},
		{"172.28.85.1/32", "172.28.85.1/30", true}, // the same address
		{"172.28.85.2/30", "172.28.85.1/30", true}, // another adapter in the range
		{"172.28.85.3/16", "172.28.85.1/30", true}, // inside the range, whatever its mask
		{"fdfe:85::1/32", "fdfe:85:85::1/126", false},
		{"fe80::1/64", "fdfe:85:85::1/126", false},
		{"fdfe:85:85::2/64", "fdfe:85:85::1/126", true},
	} {
		got := addressCollides(netip.MustParsePrefix(tc.existing), netip.MustParsePrefix(tc.requested))
		if got != tc.collides {
			t.Errorf("%s against %s: collides = %v, want %v", tc.existing, tc.requested, got, tc.collides)
		}
	}
}
