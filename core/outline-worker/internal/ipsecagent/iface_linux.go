// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build linux

package ipsecagent

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// createInterface makes the dummy interface that holds the pool gateways. ok is false when the
// kernel has no dummy interfaces; the gateways then go on loopback.
func createInterface() (ok bool, err error) {
	err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: Interface}})
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return false, err
	}
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		return false, err
	}
	return true, netlink.LinkSetUp(link)
}

func gatewayDevice(onLoopback bool) (netlink.Link, error) {
	if onLoopback {
		return netlink.LinkByName("lo")
	}
	return netlink.LinkByName(Interface)
}

func hostAddress(ip string) (*netlink.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return nil, errors.New("gateway must be an IPv4 address")
	}
	return &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(32, 32)}}, nil
}

func addGateway(onLoopback bool, ip string) error {
	link, err := gatewayDevice(onLoopback)
	if err != nil {
		return err
	}
	addr, err := hostAddress(ip)
	if err != nil {
		return err
	}
	return netlink.AddrReplace(link, addr)
}

func removeGateway(onLoopback bool, ip string) error {
	link, err := gatewayDevice(onLoopback)
	if err != nil {
		return err
	}
	addr, err := hostAddress(ip)
	if err != nil {
		return err
	}
	return netlink.AddrDel(link, addr)
}

func deleteInterface() error {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(link)
}
