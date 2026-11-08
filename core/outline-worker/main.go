// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors
// A lifecycle adapter around unmodified sing-box libraries. No protocol or crypto changes.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	_ "github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/wireguard"
	boxjson "github.com/sagernet/sing/common/json"

	"ghostlink.local/outline-worker/internal/awg"
	"ghostlink.local/outline-worker/internal/version"
)

func engineContext() context.Context {
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)
	tun.RegisterInbound(in)
	shadowsocks.RegisterInbound(in) // Used by the isolated local interoperability tests.
	out := outbound.NewRegistry()
	shadowsocks.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	direct.RegisterOutbound(out)
	endpoints := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpoints)
	awg.Register(endpoints)
	dnsRegistry := dns.NewTransportRegistry()
	transport.RegisterHTTPS(dnsRegistry)
	transport.RegisterTCP(dnsRegistry)
	transport.RegisterUDP(dnsRegistry)
	local.RegisterTransport(dnsRegistry)
	return box.Context(context.Background(), in, out, endpoints, dnsRegistry,
		boxservice.NewRegistry(), certificate.NewRegistry())
}

// Only fixed, credential-free event codes cross the child's private stderr pipe.
func event(name, code string) {
	_ = json.NewEncoder(os.Stderr).Encode(struct {
		Event string `json:"event"`
		Code  string `json:"code,omitempty"`
	}{name, code})
}

func tunnelOptions(options option.Options) *option.TunInboundOptions {
	for _, inbound := range options.Inbounds {
		if value, ok := inbound.Options.(*option.TunInboundOptions); ok {
			return value
		}
	}
	return nil
}

// addressCollides reports whether an address this host already has lies inside a requested TUN
// range, so that the TUN would take it over. A wider network that only contains the range is not
// a collision: a Hyper-V or WSL switch can get a /20 from 172.16.0.0/12 at random, and Docker
// bridges use 172.16.0.0/12 too. The TUN's more specific route wins for its own few addresses and
// the rest of that network keeps working, while refusing it would fail every connection.
func addressCollides(existing, requested netip.Prefix) bool {
	return requested.Contains(existing.Addr())
}

func checkInterfaceCollision(tunnel *option.TunInboundOptions) bool {
	if tunnel == nil {
		return false
	}
	if _, err := net.InterfaceByName(tunnel.InterfaceName); err == nil {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, address := range addresses {
		existing, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		for _, requested := range tunnel.Address {
			if addressCollides(existing, requested) {
				return true
			}
		}
	}
	return false
}

func startedEvent(tunnel *option.TunInboundOptions) bool {
	ip := ""
	if tunnel != nil {
		device, err := net.InterfaceByName(tunnel.InterfaceName)
		if err != nil {
			return false
		}
		addresses, err := device.Addrs()
		if err != nil {
			return false
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() {
				ip = prefix.Addr().String()
				break
			}
		}
		if ip == "" {
			return false
		}
	}
	_ = json.NewEncoder(os.Stderr).Encode(struct {
		Event string `json:"event"`
		VPNIP string `json:"vpn_ip,omitempty"`
	}{"started", ip})
	return true
}

func closeEngine(instance *box.Box) string {
	closed := make(chan error, 1)
	go func() { closed <- instance.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			return "engine_close_failed"
		}
		return ""
	case <-time.After(10 * time.Second):
		return "engine_close_timeout"
	}
}

func main() {
	ignoreBrokenPipe()
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version.Worker)
		return
	}
	if len(os.Args) != 4 || (os.Args[1] != "check" && os.Args[1] != "run") || os.Args[2] != "-c" {
		event("failed", "invalid_arguments")
		os.Exit(2)
	}
	if code := run(os.Args[1], os.Args[3], os.Stdin); code != "" {
		event("failed", code)
		os.Exit(1)
	}
}

func run(operation, path string, input io.Reader) string {
	ctx, cancel := context.WithCancel(engineContext())
	defer cancel()
	var stopOnce sync.Once
	stop := make(chan struct{})
	requestStop := func() { stopOnce.Do(func() { close(stop); cancel() }) }
	if operation == "run" {
		// EOF means the parent died or deliberately closed its private control pipe.
		go func() {
			reader := bufio.NewReader(io.LimitReader(input, 4097))
			line, err := reader.ReadBytes('\n')
			if err == nil && len(line) <= 4096 {
				var message struct {
					Command string `json:"command"`
				}
				_ = json.Unmarshal(line, &message)
			}
			// Any input, including malformed input, can only stop this process.
			requestStop()
		}()
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)
		go func() {
			select {
			case <-signals:
				requestStop()
			case <-stop:
			}
		}()
	}
	file, err := os.Open(path)
	if err != nil {
		return "configuration_unreadable"
	}
	data, err := io.ReadAll(io.LimitReader(file, 1048577))
	_ = file.Close()
	if err != nil || len(data) > 1048576 {
		return "configuration_unreadable"
	}
	options, err := boxjson.UnmarshalExtendedContext[option.Options](ctx, data)
	clear(data)
	if err != nil {
		return "configuration_invalid"
	}
	tunnel := tunnelOptions(options)
	if operation == "run" && checkInterfaceCollision(tunnel) {
		return "tunnel_interface_or_address_conflict"
	}
	// Upstream logs can contain addresses or configuration values. Emit our events only.
	options.Log = &option.LogOptions{Disabled: true}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return "engine_initialization_failed"
	}
	if operation == "check" {
		return closeEngine(instance)
	}
	started := make(chan error, 1)
	go func() { started <- instance.Start() }()
	select {
	case err = <-started:
		if err != nil {
			cancel()
			if code := closeEngine(instance); code != "" {
				return code
			}
			return "engine_start_failed_check_permissions"
		}
	case <-stop:
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			return "engine_start_cancel_timeout"
		}
	}
	select {
	case <-stop:
	default:
		if !startedEvent(tunnel) {
			cancel()
			if code := closeEngine(instance); code != "" {
				return code
			}
			return "tunnel_interface_not_observed"
		}
		<-stop
	}
	cancel()
	if code := closeEngine(instance); code != "" {
		return code
	}
	event("closed", "")
	return ""
}
