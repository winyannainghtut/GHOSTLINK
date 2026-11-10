// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// askDNS sends one query to address and returns the response. UDP uses a connected socket, like
// a phone's resolver: an answer that comes from any other address than the one asked is
// dropped, so it shows up here as a timeout. TCP uses the two-byte length framing.
func askDNS(network, address, name string, kind dnsmessage.Type) (dnsmessage.Header, int, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, RecursionDesired: true})
	_ = builder.StartQuestions()
	_ = builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET})
	packet, err := builder.Finish()
	if err != nil {
		return dnsmessage.Header{}, 0, err
	}
	conn, err := net.DialTimeout(network, address, 1500*time.Millisecond)
	if err != nil {
		return dnsmessage.Header{}, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	var reply []byte
	if network == "tcp" {
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
		if _, err := conn.Write(append(framed, packet...)); err != nil {
			return dnsmessage.Header{}, 0, err
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return dnsmessage.Header{}, 0, err
		}
		reply = make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return dnsmessage.Header{}, 0, err
		}
	} else {
		if _, err := conn.Write(packet); err != nil {
			return dnsmessage.Header{}, 0, err
		}
		reply = make([]byte, 1500)
		n, err := conn.Read(reply)
		if err != nil {
			return dnsmessage.Header{}, 0, err
		}
		reply = reply[:n]
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(reply)
	if err != nil {
		return header, 0, err
	}
	if header.ID != 4242 {
		return header, 0, fmt.Errorf("answer to another query (ID %d)", header.ID)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return header, 0, err
	}
	answers, err := parser.AllAnswers()
	return header, len(answers), err
}

// ipsecDNSServer is a test server with IKEv2 on, so its IPsec DNS listener runs, and one blocked
// site. Its sources are loopback, as the tests' clients are.
func ipsecDNSServer(t *testing.T) (*testServer, uint16) {
	t.Helper()
	previous := ipsecDNSSources
	ipsecDNSSources = append(append([]string{}, previous...), "127.0.0.1/32")
	t.Cleanup(func() { ipsecDNSSources = previous })
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PUT", "/rules", map[string]any{"blocked_domains": []string{"blocked.example"}}, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	var port uint16
	server.service.Read(func(s *State) { port = s.IPsec.DNSPort })
	return server, port
}

// askUntilItAnswers retries while the engine is still starting.
func askUntilItAnswers(network, address, name string, kind dnsmessage.Type) (dnsmessage.Header, int, error) {
	var header dnsmessage.Header
	var answers int
	var err error
	for i := 0; i < 10; i++ {
		if header, answers, err = askDNS(network, address, name, kind); err == nil {
			break
		}
	}
	return header, answers, err
}

// Every kind of query a phone sends, over UDP and over TCP, gets its answer through the server's
// DNS rules; A, AAAA and HTTPS/SVCB queries for a blocked site all get NXDOMAIN. (An AAAA
// answer is a DNS test, not IPv6 support: the tunnel is IPv4 only.)
func TestIPsecDNSAnswersEveryKindOfQueryOverUDPAndTCP(t *testing.T) {
	_, port := ipsecDNSServer(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for _, network := range []string{"udp", "tcp"} {
		for name, kind := range map[string]dnsmessage.Type{"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "HTTPS": dnsmessage.Type(65), "SVCB": dnsmessage.Type(64)} {
			header, answers, err := askUntilItAnswers(network, address, "www.blocked.example.", kind)
			if err != nil || header.RCode != dnsmessage.RCodeNameError || answers != 0 {
				t.Errorf("%s %s query for a blocked name: rcode %v, %d answers, %v", network, name, header.RCode, answers, err)
			}
		}
	}
}

// Only the pools may ask: a source outside them gets nothing, over TCP as over UDP.
func TestIPsecDNSRefusesSourcesOutsideThePools(t *testing.T) {
	server, port := ipsecDNSServer(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	if _, _, err := askUntilItAnswers("tcp", address, "www.blocked.example.", dnsmessage.TypeA); err != nil {
		t.Fatalf("a pool source over TCP: %v", err)
	}
	ipsecDNSSources = ipsecDNSSources[:len(ipsecDNSSources)-1]
	// A rule change reloads the engine, now without loopback among the sources.
	server.must(t, http.StatusOK, "PUT", "/rules", map[string]any{"blocked_domains": []string{"blocked.example", "other.example"}}, nil)
	for _, network := range []string{"udp", "tcp"} {
		if header, _, err := askDNS(network, address, "www.blocked.example.", dnsmessage.TypeA); err == nil {
			t.Errorf("a source outside the pools got a %s answer (%v)", network, header.RCode)
		}
	}
}
