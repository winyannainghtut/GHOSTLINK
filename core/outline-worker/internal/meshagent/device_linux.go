// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build linux

package meshagent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// routeProtocol marks the routes the agent adds, so it only ever removes its own.
const routeProtocol = netlink.RouteProtocol(77)

const meshMTU = 1420

// device is the kernel WireGuard interface.
type device struct {
	name string
	wg   *wgctrl.Client
}

func openDevice(name string) (*device, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.MTU = name, meshMTU
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil && !errors.Is(err, unix.EEXIST) {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || strings.Contains(err.Error(), "not supported") {
			return nil, errors.New("this kernel has no WireGuard support (Linux 5.6 or newer, or the wireguard module, is needed)")
		}
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if link.Type() != "wireguard" {
		return nil, fmt.Errorf("%s exists but is not a WireGuard interface; choose another name with --interface", name)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &device{name: name, wg: wg}, nil
}

func (d *device) configure(privateKey string, port uint16, peers []wgtypes.PeerConfig) error {
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return err
	}
	listen := int(port)
	return d.wg.ConfigureDevice(d.name, wgtypes.Config{PrivateKey: &key, ListenPort: &listen, Peers: peers})
}

func (d *device) peers() ([]wgtypes.Peer, error) {
	dev, err := d.wg.Device(d.name)
	if err != nil {
		return nil, err
	}
	return dev.Peers, nil
}

func (d *device) link() (netlink.Link, error) { return netlink.LinkByName(d.name) }

// setAddress gives the interface exactly one IPv4 address.
func (d *device) setAddress(prefix string) error {
	link, err := d.link()
	if err != nil {
		return err
	}
	want, err := netlink.ParseAddr(prefix)
	if err != nil {
		return err
	}
	current, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	for _, a := range current {
		if a.IPNet.String() != want.IPNet.String() {
			_ = netlink.AddrDel(link, &a)
		}
	}
	return netlink.AddrReplace(link, want)
}

// setRoutes keeps exactly the wanted subnets routed into the mesh.
func (d *device) setRoutes(routes []string) error {
	link, err := d.link()
	if err != nil {
		return err
	}
	current, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}
	for _, r := range current {
		if r.Protocol == routeProtocol && r.Dst != nil && !slices.Contains(routes, r.Dst.String()) {
			_ = netlink.RouteDel(&r)
		}
	}
	for _, text := range routes {
		_, dst, err := net.ParseCIDR(text)
		if err != nil {
			return err
		}
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Protocol: routeProtocol, Scope: netlink.SCOPE_LINK}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("route %s: %w", text, err)
		}
	}
	return nil
}

func (d *device) close() {
	if d.wg != nil {
		_ = d.wg.Close()
	}
}

// removeInterface deletes the interface (its routes go with it).
func removeInterface(name string) {
	if link, err := netlink.LinkByName(name); err == nil && link.Type() == "wireguard" {
		_ = netlink.LinkDel(link)
	}
}

const forwardingPath = "/proc/sys/net/ipv4/ip_forward"

func readForwarding() string {
	data, err := os.ReadFile(forwardingPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeForwarding(value string) error {
	return os.WriteFile(forwardingPath, []byte(value+"\n"), 0o644)
}

// pinger measures the round trip to every other node's mesh address every 15 seconds.
type pinger struct {
	mu      sync.Mutex
	targets []string
	results map[string]int64
}

func newPinger() *pinger { return &pinger{results: map[string]int64{}} }

func (p *pinger) setTargets(targets []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = append([]string{}, targets...)
}

func (p *pinger) snapshot() map[string]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]int64{}
	for k, v := range p.results {
		out[k] = v
	}
	return out
}

func (p *pinger) run(stop <-chan struct{}) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return // latency is optional; links still work
	}
	defer conn.Close()
	id := os.Getpid() & 0xffff
	seq := 0
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		targets := append([]string{}, p.targets...)
		p.mu.Unlock()
		sent := map[int]string{}
		started := map[int]time.Time{}
		for _, target := range targets {
			addr, err := netip.ParseAddr(target)
			if err != nil {
				continue
			}
			seq = (seq + 1) & 0xffff
			msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("ghostlink-mesh")}}
			data, _ := msg.Marshal(nil)
			if _, err := conn.WriteTo(data, &net.IPAddr{IP: addr.AsSlice()}); err == nil {
				sent[seq], started[seq] = target, time.Now()
			}
		}
		results := map[string]int64{}
		for _, target := range targets {
			results[target] = 0
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		for len(sent) > 0 {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok || echo.ID != id {
				continue
			}
			if target, ok := sent[echo.Seq]; ok {
				results[target] = max(1, time.Since(started[echo.Seq]).Microseconds())
				delete(sent, echo.Seq)
			}
		}
		p.mu.Lock()
		p.results = results
		p.mu.Unlock()
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}
