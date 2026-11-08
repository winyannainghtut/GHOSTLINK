// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// udpEcho answers every datagram on loopback with the same bytes.
func udpEcho(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			conn.WriteTo(buffer[:n], from)
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// socksUDP is a SOCKS5 UDP association through a test client's local proxy, to one loopback port.
type socksUDP struct {
	control net.Conn
	relay   *net.UDPConn
	header  []byte
}

func openSocksUDP(t *testing.T, proxyPort, target uint16) *socksUDP {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 25; attempt++ {
		association, err := associate(proxyPort, target)
		if err == nil {
			t.Cleanup(func() { association.control.Close(); association.relay.Close() })
			return association
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("SOCKS5 UDP associate: %v", lastErr)
	return nil
}

func associate(proxyPort, target uint16) (*socksUDP, error) {
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 3*time.Second)
	if err != nil {
		return nil, err
	}
	control.SetDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 10)
	if _, err = control.Write([]byte{5, 1, 0}); err == nil {
		_, err = io.ReadFull(control, reply[:2])
	}
	if err == nil && reply[1] != 0 {
		err = fmt.Errorf("authentication method %d", reply[1])
	}
	if err == nil {
		_, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) // UDP ASSOCIATE, any address
	}
	if err == nil {
		_, err = io.ReadFull(control, reply)
	}
	if err == nil && (reply[1] != 0 || reply[3] != 1) {
		err = fmt.Errorf("associate reply %v", reply)
	}
	if err != nil {
		control.Close()
		return nil, err
	}
	control.SetDeadline(time.Time{})
	relayAddress := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	if relayAddress.IP.IsUnspecified() {
		relayAddress.IP = net.IPv4(127, 0, 0, 1)
	}
	relay, err := net.DialUDP("udp4", nil, relayAddress)
	if err != nil {
		control.Close()
		return nil, err
	}
	return &socksUDP{control: control, relay: relay, header: []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(target >> 8), byte(target)}}, nil
}

func (s *socksUDP) send(t *testing.T, payload []byte) {
	t.Helper()
	if _, err := s.relay.Write(append(append([]byte{}, s.header...), payload...)); err != nil {
		t.Fatal(err)
	}
}

// receive counts the replies that arrive until none comes for quiet, checking each one.
func (s *socksUDP) receive(t *testing.T, want []byte, quiet time.Duration) int {
	t.Helper()
	buffer := make([]byte, 65535)
	count := 0
	for {
		s.relay.SetReadDeadline(time.Now().Add(quiet))
		n, err := s.relay.Read(buffer)
		if err != nil {
			return count
		}
		if n < 4 {
			t.Fatalf("a %d-byte SOCKS5 reply", n)
		}
		offset := 10 // IPv4: RSV RSV FRAG ATYP, 4 address bytes, port
		switch buffer[3] {
		case 3:
			offset = 4 + 1 + int(buffer[4]) + 2
		case 4:
			offset = 22
		}
		if n < offset || !bytes.Equal(buffer[offset:n], want) {
			t.Fatalf("a UDP reply came back changed (%d bytes)", n)
		}
		count++
	}
}

// Shadowsocks UDP through the real server. Replies reach both an uncapped and a capped client
// (an earlier 0.8.1 build crashed the whole server on the first reply), and a capped client's
// UDP above its rate is dropped.
func TestShadowsocksUDPThroughTheServer(t *testing.T) {
	echo := udpEcho(t)
	testInternalPort = echo
	t.Cleanup(func() { testInternalPort = 0 })
	server := newTestServer(t, nil)
	free := server.user(t, map[string]any{"name": "Free"})
	capped := server.user(t, map[string]any{"name": "Capped", "speed_limit_bps": 100_000})
	freeProxy, cappedProxy := freeTCPPort(t), freeTCPPort(t)
	startClient(t, clientConfig(t, server.key(t, free, Shadowsocks), freeProxy))
	startClient(t, clientConfig(t, server.key(t, capped, Shadowsocks), cappedProxy))

	small := bytes.Repeat([]byte("g"), 1200)
	udp := openSocksUDP(t, freeProxy, echo)
	for range 20 {
		udp.send(t, small)
		time.Sleep(5 * time.Millisecond)
	}
	if got := udp.receive(t, small, 1500*time.Millisecond); got < 15 {
		t.Fatalf("uncapped: %d of 20 UDP replies came back", got)
	}

	// 100 KB/s allows a burst of 64 KiB and then the rate: of 1 MB sent at once, little passes.
	big := bytes.Repeat([]byte("c"), 10_000)
	udp = openSocksUDP(t, cappedProxy, echo)
	udp.send(t, big)
	if got := udp.receive(t, big, 1500*time.Millisecond); got != 1 {
		t.Fatalf("capped: the first datagram's reply did not come back (%d)", got)
	}
	time.Sleep(time.Second) // let the bucket refill
	for range 100 {
		udp.send(t, big)
	}
	got := udp.receive(t, big, 1500*time.Millisecond)
	if got < 2 || got > 30 {
		t.Fatalf("capped at 100 KB/s: %d of 100 10 KB datagrams came back; the rate allows about 7", got)
	}
	server.must(t, http.StatusOK, "GET", "/live", nil, nil)
}
