// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors
// Adapted from sing-box v1.14.4 protocol/wireguard/endpoint.go and
// transport/wireguard/endpoint.go (GPL-3.0-or-later, Copyright (C) 2022 nekohasekai).
// The protocol device is unmodified amneziawg-go; sing-box supplies the userspace network
// stack, the interface-bound dialer and the router.

package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"go4.org/netipx"
)

// Register adds the "amneziawg" endpoint type to a sing-box endpoint registry.
func Register(registry *endpoint.Registry) {
	endpoint.Register[Options](registry, Type, NewEndpoint)
}

// Endpoint is a client (one peer, no listen port) or a server (listen port, many peers).
type Endpoint struct {
	endpoint.Adapter
	ctx            context.Context
	router         adapter.Router
	dnsRouter      adapter.DNSRouter
	logger         logger.ContextLogger
	options        Options
	localAddresses []netip.Prefix
	dialer         N.Dialer
	tunDevice      wireguard.Device
	tun            *tunAdapter
	users          map[netip.Addr]string
	stateAccess    sync.Mutex
	device         *device.Device
	started        atomic.Bool
}

var _ adapter.Endpoint = (*Endpoint)(nil)
var _ tun.Handler = (*Endpoint)(nil)

func (e *Endpoint) isClient() bool { return e.options.ListenPort == 0 }

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Endpoint, error) {
	if options.ListenPort == 0 && len(options.Peers) != 1 {
		return nil, E.New("an AmneziaWG client needs exactly one peer")
	}
	if options.ListenPort != 0 && options.Detour != "" {
		return nil, E.New("`listen_port` conflicts with `detour`")
	}
	if _, err := options.deviceConfig(); err != nil {
		return nil, err
	}
	users := make(map[netip.Addr]string)
	var allowedBuilder netipx.IPSetBuilder
	for index, peer := range options.Peers {
		if _, err := peer.peerConfig(netip.AddrPort{}); err != nil {
			return nil, E.Cause(err, "peer ", index)
		}
		for _, prefix := range peer.AllowedIPs {
			allowedBuilder.AddPrefix(prefix)
			if peer.User != "" && prefix.IsSingleIP() {
				users[prefix.Addr()] = peer.User
			}
		}
	}
	allowedSet, err := allowedBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	ep := &Endpoint{
		Adapter:        endpoint.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:            ctx,
		router:         router,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		logger:         logger,
		options:        options,
		localAddresses: options.Address,
		users:          users,
	}
	remoteIsDomain := options.ListenPort == 0 && !M.ParseAddr(options.Peers[0].Address).IsValid()
	ep.dialer, err = dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   remoteIsDomain,
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1376
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	ep.tunDevice, err = wireguard.NewDevice(wireguard.DeviceOptions{
		Context:         ctx,
		Logger:          logger,
		System:          false,
		Handler:         ep,
		UDPTimeout:      udpTimeout,
		ICMPTimeout:     C.ICMPTimeout,
		InterfaceFinder: networkManager.InterfaceFinder(),
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: interfaceName},
			}))
		},
		Name:           options.Name,
		MTU:            mtu,
		Address:        options.Address,
		AllowedAddress: allowedSet.Prefixes(),
	})
	if err != nil {
		return nil, E.Cause(err, "create AmneziaWG network stack")
	}
	return ep, nil
}

func (e *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	// A client whose peer is a hostname resolves it after DNS has started.
	resolveLater := e.isClient() && !M.ParseAddr(e.options.Peers[0].Address).IsValid()
	switch stage {
	case adapter.StartStateInitialize:
		scope.Add(e.close)
	case adapter.StartStateStart:
		if !resolveLater {
			return e.start()
		}
	case adapter.StartStatePostStart:
		if resolveLater {
			if err := e.start(); err != nil {
				return err
			}
		}
		e.started.Store(true)
		scope.Add(func() error {
			e.started.Store(false)
			return nil
		})
	}
	return nil
}

func (e *Endpoint) start() error {
	config, err := e.options.deviceConfig()
	if err != nil {
		return err
	}
	var bind awgconn.Bind
	if e.isClient() {
		peer := e.options.Peers[0]
		address, err := e.resolvePeer(peer)
		if err != nil {
			return E.Cause(err, "resolve AmneziaWG server")
		}
		lines, err := peer.peerConfig(address)
		if err != nil {
			return err
		}
		config += lines
		bind = newClientBind(e.ctx, e.logger, e.dialer, address)
	} else {
		for _, peer := range e.options.Peers {
			lines, err := peer.peerConfig(netip.AddrPort{})
			if err != nil {
				return err
			}
			config += lines
		}
		bind = awgconn.NewStdNetBind()
	}
	if err := e.tunDevice.Start(); err != nil {
		return err
	}
	e.tun = newTunAdapter(e.tunDevice)
	awgDevice := device.NewDevice(e.tun, bind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	})
	if err := awgDevice.IpcSet(config); err != nil {
		awgDevice.Close()
		// The rejected configuration contains keys; never echo it.
		return E.Cause(err, "configure AmneziaWG")
	}
	if err := awgDevice.Up(); err != nil {
		awgDevice.Close()
		return E.Cause(err, "start AmneziaWG")
	}
	e.stateAccess.Lock()
	e.device = awgDevice
	e.stateAccess.Unlock()
	return nil
}

func (e *Endpoint) resolvePeer(peer Peer) (netip.AddrPort, error) {
	if address := M.ParseAddr(peer.Address); address.IsValid() {
		return netip.AddrPortFrom(address, peer.Port), nil
	}
	resolver, isResolver := e.dialer.(dialer.ResolveDialer)
	queryOptions := adapter.DNSQueryOptions{}
	if isResolver {
		queryOptions = resolver.QueryOptions()
	}
	addresses, err := e.dnsRouter.Lookup(e.ctx, peer.Address, queryOptions)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addresses) == 0 {
		return netip.AddrPort{}, E.New("no address for ", peer.Address)
	}
	return netip.AddrPortFrom(addresses[0], peer.Port), nil
}

func (e *Endpoint) close() error {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	if e.device != nil {
		e.device.Close()
		e.device = nil
		return nil
	}
	return e.tunDevice.Close()
}

// PeerTransfer returns received and sent bytes per peer public key (base64) from UAPI.
func (e *Endpoint) PeerTransfer() (map[string][2]uint64, error) {
	e.stateAccess.Lock()
	awgDevice := e.device
	e.stateAccess.Unlock()
	if awgDevice == nil {
		return nil, E.New("AmneziaWG is not running")
	}
	state, err := awgDevice.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseTransfer(state), nil
}

// InterfaceUpdated re-binds sockets after a network change.
func (e *Endpoint) InterfaceUpdated(context.Context) {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	if e.device != nil {
		if err := e.device.BindUpdate(); err != nil {
			e.logger.Error(E.Cause(err, "update AmneziaWG bind"))
		}
	}
}

func (e *Endpoint) userFor(source M.Socksaddr) string {
	return e.users[source.Addr.Unmap()]
}

func (e *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	for _, localPrefix := range e.localAddresses {
		if localPrefix.Contains(destination.Addr()) {
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
	}
	return adapter.JudgeFlow(e.router, e.Tag(), e.Type(), network, source, destination, firstPacket)
}

func (e *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(e.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	metadata.User = e.userFor(source)
	e.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	metadata.User = e.userFor(source)
	for _, localPrefix := range e.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	e.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	metadata.Destination = destination
	metadata.User = e.userFor(source)
	for _, localPrefix := range e.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !e.started.Load() {
		return nil, E.New("AmneziaWG is not ready yet")
	}
	if destination.IsDomain() {
		addresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, e.tunDevice, network, destination, addresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !e.started.Load() {
		return nil, E.New("AmneziaWG is not ready yet")
	}
	if destination.IsDomain() {
		addresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, address, err := N.ListenSerial(ctx, e.tunDevice, destination, addresses)
		if err != nil {
			return nil, err
		}
		return bufio.NewNATPacketConn(bufio.NewPacketConn(iponly.NewPacketConn(e.logger, packetConn)), M.SocksaddrFrom(address, destination.Port), destination), nil
	}
	packetConn, err := e.tunDevice.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return iponly.NewPacketConn(e.logger, packetConn), nil
}
