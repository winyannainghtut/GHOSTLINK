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
