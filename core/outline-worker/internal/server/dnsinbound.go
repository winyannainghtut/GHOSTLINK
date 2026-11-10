// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"golang.org/x/net/ipv4"
)

// ipsecDNSType is the inbound that answers the DNS of IKEv2/IPsec clients.
//
// The IPsec agent redirects every client's DNS (port 53, any resolver) to the client's pool
// gateway on one port. The reply must leave from the address the request arrived at, because
// that is what the kernel's reverse NAT matches to turn it back into an answer from the resolver
// the client asked. A plain wildcard UDP socket (sing-box's direct inbound) lets the routing
// table choose the source of its replies, and strongSwan's route to the client prefers the
// server's own address, so the answer came from there instead and a phone, which ignores
// answers from anywhere but the server it asked, never saw any (v0.8.5: connected, but no website
// opened). This inbound reads the destination of each request (IP_PKTINFO) and answers from it.
// TCP needs none of this: an accepted connection keeps the address it was made to.
const ipsecDNSType = "ghostlink-dns"

// ipsecDNSUDPTimeout is how long a client's UDP source port keeps its session. Clients use a new
// port for most queries, so this only bounds the sessions left behind.
const ipsecDNSUDPTimeout = 30 * time.Second

type dnsInboundOptions struct {
	option.ListenOptions
}

func registerDNSInbound(registry *inbound.Registry) {
	inbound.Register[dnsInboundOptions](registry, ipsecDNSType, newDNSInbound)
}

type dnsInbound struct {
	inbound.Adapter
	ctx    context.Context
	router adapter.ConnectionRouterEx
	logger log.ContextLogger
	listen option.ListenOptions
	tcp    *listener.Listener
	udp    *dnsUDP
	udpNat *udpnat.Service
}

func newDNSInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options dnsInboundOptions) (adapter.Inbound, error) {
	i := &dnsInbound{
		Adapter: inbound.NewAdapter(ipsecDNSType, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		listen:  options.ListenOptions,
	}
	i.udpNat = udpnat.New(i, i.preparePacketConnection, ipsecDNSUDPTimeout, false)
	i.tcp = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: i,
	})
	return i, nil
}

func (i *dnsInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	// The pools are IPv4 only, so UDP listens on IPv4 (the wildcard or, in tests, loopback).
	address := i.listen.Listen.Build(netip.IPv4Unspecified())
	if !address.Is4() {
		if !address.IsUnspecified() {
			return E.New("the IPsec DNS listens on IPv4 addresses only, not ", address)
		}
		address = netip.IPv4Unspecified()
	}
	if err := i.tcp.Start(); err != nil {
		return err
	}
	scope.Add(i.tcp.Close)
	udp, err := listenDNSUDP(netip.AddrPortFrom(address, i.listen.ListenPort))
	if err != nil {
		return E.Errors(err, i.tcp.Close())
	}
	i.udp = udp
	scope.Add(udp.Close)
	i.logger.Info("udp server started at ", udp.conn.LocalAddr())
	go i.loopUDP()
	return nil
}

func (i *dnsInbound) InterfaceUpdated(ctx context.Context) {
	i.udpNat.Purge()
}

func (i *dnsInbound) loopUDP() {
	buffer := make([]byte, 65535)
	for {
		n, destination, source, err := i.udp.read(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			i.logger.Error("read DNS packet: ", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		i.udpNat.NewPacket([][]byte{buffer[:n]}, M.SocksaddrFromNetIP(source), M.SocksaddrFrom(destination, i.udp.port), nil)
	}
}

func (i *dnsInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = metadata.OriginDestination
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *dnsInbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Source = source
	metadata.Destination = destination
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// preparePacketConnection starts a client's session: the answer goes back to the client, from the
// address its first request was sent to.
func (i *dnsInbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return true, log.ContextWithNewID(i.ctx), &dnsPacketWriter{udp: i.udp, client: source.AddrPort(), from: destination.Addr}, nil
}

type dnsPacketWriter struct {
	udp    *dnsUDP
	client netip.AddrPort
	from   netip.Addr
}

func (w *dnsPacketWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	return w.udp.write(buffer.Bytes(), w.from, w.client)
}

// dnsUDP is the inbound's UDP socket. Where the system can say which address a packet was sent to
// (Linux and the other Unix systems), it does, and replies use that address as their source;
// where it cannot (Windows, where only tests run) replies leave from whatever the system picks.
type dnsUDP struct {
	conn *net.UDPConn
	pc   *ipv4.PacketConn
	// pktinfo is whether requests carry the address they were sent to.
	pktinfo bool
	port    uint16
}

func listenDNSUDP(address netip.AddrPort) (*dnsUDP, error) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(conn)
	return &dnsUDP{
		conn:    conn,
		pc:      pc,
		pktinfo: pc.SetControlMessage(ipv4.FlagDst, true) == nil,
		port:    uint16(conn.LocalAddr().(*net.UDPAddr).Port),
	}, nil
}

func (u *dnsUDP) Close() error { return u.conn.Close() }

// read returns a request, the address it was sent to (invalid where the system does not say) and
// the client's address.
func (u *dnsUDP) read(b []byte) (n int, destination netip.Addr, source netip.AddrPort, err error) {
	n, cm, from, err := u.pc.ReadFrom(b)
	if err != nil {
		return 0, netip.Addr{}, netip.AddrPort{}, err
	}
	if udp, ok := from.(*net.UDPAddr); ok {
		source = udp.AddrPort()
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	}
	if cm != nil {
		if address, ok := netip.AddrFromSlice(cm.Dst); ok {
			destination = address.Unmap()
		}
	}
	return n, destination, source, nil
}

// write sends a reply to the client from the given address: the one the request was sent to.
func (u *dnsUDP) write(b []byte, from netip.Addr, client netip.AddrPort) error {
	var cm *ipv4.ControlMessage
	if u.pktinfo && from.Is4() {
		source := from.As4()
		cm = &ipv4.ControlMessage{Src: source[:]}
	}
	_, err := u.pc.WriteTo(b, cm, net.UDPAddrFromAddrPort(client))
	return err
}
