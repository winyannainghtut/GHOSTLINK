// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors
// Adapted from sing-box v1.14.4 transport/wireguard/client_bind.go (GPL-3.0-or-later,
// Copyright (C) 2022 nekohasekai). Unlike the original it never rewrites packet bytes: the
// WARP "reserved" handling overwrote bytes 1-3, which carry AmneziaWG's obfuscated headers.

package awg

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ conn.Bind = (*clientBind)(nil)

// clientBind sends the client's UDP through a sing-box dialer, which binds sockets to the
// physical interface so tunnel traffic never loops back into the TUN.
type clientBind struct {
	ctx         context.Context
	logger      logger.Logger
	dialer      N.Dialer
	connectAddr netip.AddrPort
	bindCtx     context.Context
	bindDone    context.CancelFunc
	connAccess  sync.Mutex
	conn        *wireConn
	done        chan struct{}
}

func newClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, connectAddr netip.AddrPort) *clientBind {
	return &clientBind{ctx: ctx, logger: logger, dialer: dialer, connectAddr: connectAddr, done: make(chan struct{})}
}

func (c *clientBind) connect() (*wireConn, error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	if c.conn != nil {
		select {
		case <-c.conn.done:
			c.conn = nil
		default:
			return c.conn, nil
		}
	}
	udpConn, err := c.dialer.DialContext(c.bindCtx, N.NetworkUDP, M.SocksaddrFromNetIP(c.connectAddr))
	if err != nil {
		return nil, err
	}
	c.conn = &wireConn{PacketConn: bufio.NewUnbindPacketConn(udpConn), done: make(chan struct{})}
	return c.conn, nil
}

func (c *clientBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *clientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	udpConn, err := c.connect()
	if err != nil {
		select {
		case <-c.done:
			return 0, net.ErrClosed
		default:
		}
		c.logger.Error(E.Cause(err, "connect to server"))
		select {
		case <-c.done:
		case <-time.After(time.Second):
		}
		return 0, nil
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		udpConn.Close()
		select {
		case <-c.done:
			return 0, net.ErrClosed
		default:
			c.logger.Error(E.Cause(err, "read packet"))
			return 0, nil
		}
	}
	sizes[0] = n
	eps[0] = remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort())
	return 1, nil
}

func (c *clientBind) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

func (c *clientBind) SetMark(uint32) error { return nil }

func (c *clientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	udpConn, err := c.connect()
	if err != nil {
		time.Sleep(time.Second)
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if _, err = udpConn.WriteToUDPAddrPort(buf, destination); err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

func (c *clientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint(ap), nil
}

func (c *clientBind) BatchSize() int { return 1 }

type wireConn struct {
	net.PacketConn
	access sync.Mutex
	done   chan struct{}
}

func (w *wireConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return w.PacketConn.WriteTo(b, M.SocksaddrFromNetIP(addr).UDPAddr())
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	w.PacketConn.Close()
	close(w.done)
	return nil
}

var _ conn.Endpoint = remoteEndpoint{}

type remoteEndpoint netip.AddrPort

func (e remoteEndpoint) ClearSrc()           {}
func (e remoteEndpoint) SrcToString() string { return "" }
func (e remoteEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
func (e remoteEndpoint) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e remoteEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
