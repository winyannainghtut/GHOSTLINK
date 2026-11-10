// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These tests need Linux: a request sent to 127.0.0.2 or 127.0.0.3 reaches a socket bound to the
// wildcard, and the client at 127.0.0.1 stands in for a phone whose DNS was redirected to its
// pool gateway. The kernel picks 127.0.0.1 as the source of a plain socket's reply (the way it
// picked the server's own address on the failing server), so a client that connected to
// 127.0.0.2 never sees it.

// echoFrom answers every datagram the way the DNS inbound answers a query, from sendFrom's choice
// of source.
func echoFrom(t *testing.T, udp *dnsUDP, fromAsked bool) {
	t.Helper()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, asked, client, err := udp.read(buffer)
			if err != nil {
				return
			}
			from := netip.Addr{}
			if fromAsked {
				from = asked
			}
			_ = udp.write(buffer[:n], from, client)
		}
	}()
}

// roundTrip sends "ping" from a connected client socket to asked:port and reports whether the
// echo came back (a datagram from any other source address is dropped by the kernel).
func roundTrip(t *testing.T, asked string, port uint16) bool {
	t.Helper()
	// Called from several goroutines, so it reports with Error, not Fatal.
	conn, err := net.Dial("udp4", net.JoinHostPort(asked, strconv.Itoa(int(port))))
	if err != nil {
		t.Error(err)
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Error(err)
		return false
	}
	reply := make([]byte, 16)
	n, err := conn.Read(reply)
	return err == nil && string(reply[:n]) == "ping"
}

// The inbound's socket answers from the address each request was sent to, whichever one of the
// host's addresses that is. (This is what made websites open on the iPhone without the manual
// route.)
func TestDNSUDPAnswersFromTheAddressAsked(t *testing.T) {
	udp, err := listenDNSUDP(netip.MustParseAddrPort("0.0.0.0:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if !udp.pktinfo {
		t.Fatal("this system does not say which address a request was sent to")
	}
	echoFrom(t, udp, true)
	for _, asked := range []string{"127.0.0.2", "127.0.0.3", "127.0.0.1"} {
		if !roundTrip(t, asked, udp.port) {
			t.Errorf("no answer from %s, the address that was asked", asked)
		}
	}
	// Many clients at once, each asking the gateway of its own pool, each answered from it.
	var group sync.WaitGroup
	var wrong atomic.Int32
	for client := 0; client < 16; client++ {
		group.Add(1)
		go func(asked string) {
			defer group.Done()
			for query := 0; query < 20; query++ {
				if !roundTrip(t, asked, udp.port) {
					wrong.Add(1)
				}
			}
		}([]string{"127.0.0.2", "127.0.0.3"}[client%2])
	}
	group.Wait()
	if n := wrong.Load(); n != 0 {
		t.Errorf("%d of 320 concurrent queries were not answered from the address asked", n)
	}
}

// The failure itself, on a plain wildcard socket (what sing-box's direct inbound uses): the
// answer leaves from the address the routing table prefers, so a client that asked another
// address never sees it. If this host answers correctly anyway, the test above proves nothing
// here, and this test says so.
func TestAPlainWildcardSocketAnswersFromTheWrongAddress(t *testing.T) {
	udp, err := listenDNSUDP(netip.MustParseAddrPort("0.0.0.0:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	echoFrom(t, udp, false)
	if roundTrip(t, "127.0.0.2", udp.port) {
		t.Skip("this host answers a wildcard socket's request from the address asked; the failure cannot be shown here")
	}
}

// Through the real engine: with the listener on every address, as it is in production, the IPsec
// DNS answers a query from the address it was sent to, over UDP, for the pool gateways of both
// IKEv2 and IKEv1/IPsec (two different addresses here), and over TCP.
func TestIPsecDNSAnswersFromTheAddressAsked(t *testing.T) {
	saved := listenAddress
	listenAddress = "0.0.0.0"
	defer func() { listenAddress = saved }()
	_, port := ipsecDNSServer(t)
	for _, gateway := range []string{"127.0.0.2", "127.0.0.3"} {
		address := net.JoinHostPort(gateway, strconv.Itoa(int(port)))
		for _, network := range []string{"udp", "tcp"} {
			for name, kind := range map[string]dnsmessage.Type{"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "HTTPS": dnsmessage.Type(65)} {
				header, _, err := askUntilItAnswers(network, address, "www.blocked.example.", kind)
				if err != nil || header.RCode != dnsmessage.RCodeNameError {
					t.Errorf("%s %s query sent to %s: rcode %v, %v (an answer from another address is dropped, like a phone does)", network, name, address, header.RCode, err)
				}
			}
		}
	}
}
