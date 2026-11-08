// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Command ghostlink-mesh joins this Linux machine to a Ghostlink mesh: a private network of
// servers coordinated by a Ghostlink server. It runs as a systemd service that keeps a kernel
// WireGuard interface (glmesh0) configured.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"ghostlink.local/outline-worker/internal/hostfw"
	"ghostlink.local/outline-worker/internal/meshagent"
	"ghostlink.local/outline-worker/internal/meshproto"
	"ghostlink.local/outline-worker/internal/version"
)

const usage = `usage: ghostlink-mesh <command> [flags]

  join      join a mesh. The invite (glmesh1:...) is read from GHOSTLINK_MESH_INVITE or the
            first line of standard input. Flags:
              --name NAME                 node name (default: this machine's host name)
              --port N                    WireGuard UDP port (default 51820)
              --endpoint IP:PORT          public address, when it can't be detected
              --advertise-routes CIDR,..  offer subnets behind this machine (the administrator
                                          approves them; allows forwarding)
              --relay                     allow this machine to relay for nodes behind NAT
              --no-hosts                  do not add <node>.mesh names to /etc/hosts
  serve     run the agent (the ghostlink-mesh systemd service does this)
  status    show this node, its peers and latency [--json]
  allow-forwarding
            allow this node to relay or share subnets (then restart the service)
  leave     leave the mesh and remove everything the agent set up
  version   print the version

Common flags: --state DIR (default /var/lib/ghostlink-mesh), --interface NAME (join only,
default glmesh0), --iptables auto|nft|legacy (serve and leave).
`

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ghostlink-mesh: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command, args := os.Args[1], os.Args[2:]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	dir := flags.String("state", meshagent.DefaultDir, "")
	backend := flags.String("iptables", "auto", "")
	switch command {
	case "version":
		fmt.Println("Ghostlink mesh agent " + version.Ghostlink)
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "join":
		join(flags, dir, args)
	case "serve":
		_ = flags.Parse(args)
		serve(*dir, *backend)
	case "status":
		asJSON := flags.Bool("json", false, "")
		_ = flags.Parse(args)
		status(*dir, *asJSON)
	case "allow-forwarding":
		_ = flags.Parse(args)
		node, err := meshagent.LoadNode(*dir)
		if err != nil {
			fail("%v", err)
		}
		node.Forwarding = true
		if err := node.Save(*dir); err != nil {
			fail("%v", err)
		}
		fmt.Println("Forwarding is allowed on this node. Apply it with: sudo systemctl restart ghostlink-mesh")
	case "leave":
		_ = flags.Parse(args)
		if err := meshagent.Leave(*dir, firewall(*backend)); err != nil {
			fail("%v", err)
		}
		fmt.Println("Left the mesh; the interface, firewall chains and /etc/hosts entries are removed.")
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func firewall(backend string) *hostfw.Firewall {
	switch backend {
	case "auto":
		backend = hostfw.DetectHost(context.Background())
	case "nft", "legacy":
	default:
		fail("--iptables must be auto, nft or legacy")
	}
	return &hostfw.Firewall{Backend: backend}
}

// hostName turns the machine's host name into a node name.
func hostName() string {
	name, _ := os.Hostname()
	name, _, _ = strings.Cut(strings.ToLower(name), ".")
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 32 {
		out = strings.Trim(out[:32], "-")
	}
	if out == "" {
		out = "node"
	}
	return out
}

func join(flags *flag.FlagSet, dir *string, args []string) {
	name := flags.String("name", hostName(), "")
	port := flags.Uint("port", meshproto.DefaultPort, "")
	endpoint := flags.String("endpoint", "", "")
	routes := flags.String("advertise-routes", "", "")
	relay := flags.Bool("relay", false, "")
	noHosts := flags.Bool("no-hosts", false, "")
	iface := flags.String("interface", meshagent.DefaultInterface, "")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 && *dir == meshagent.DefaultDir {
		fail("run as root: sudo ghostlink-mesh join")
	}
	if _, err := meshagent.LoadNode(*dir); err == nil {
		fail("this machine is already in a mesh; leave first: sudo ghostlink-mesh leave")
	}
	if !meshproto.ValidName(*name) {
		fail("--name: use lower-case letters, digits and hyphens (at most 32)")
	}
	if *port == 0 || *port > 65535 {
		fail("--port must be 1-65535")
	}
	if *endpoint != "" {
		if err := meshproto.ValidEndpoint(*endpoint); err != nil {
			fail("--endpoint: %v", err)
		}
	}
	if !meshagent.ValidInterface(*iface) {
		fail("--interface: use a short lower-case name such as glmesh0")
	}
	var advertised []string
	for _, r := range strings.Split(*routes, ",") {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		if err := meshproto.ValidRoute(r); err != nil {
			fail("--advertise-routes: %v", err)
		}
		advertised = append(advertised, r)
	}
	text := os.Getenv("GHOSTLINK_MESH_INVITE")
	if text == "" {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		text = strings.TrimSpace(line)
	}
	invite, err := meshproto.DecodeInvite(text)
	if err != nil {
		fail("%v", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fail("%v", err)
	}
	listen := uint16(*port)
	response, err := meshagent.NewClient(invite.URL, invite.Pin).Join(meshproto.JoinRequest{
		Protocol: meshproto.Version, Token: invite.Token, Name: *name, PublicKey: key.PublicKey().String(), ListenPort: listen,
		Endpoints: meshagent.LocalEndpoints(*endpoint, listen, *iface), AdvertiseRoutes: advertised,
		OS: runtime.GOOS, Version: version.Ghostlink,
	})
	if err != nil {
		fail("%v", err)
	}
	node := &meshagent.Node{URL: invite.URL, Pin: invite.Pin, NodeID: response.NodeID, Secret: response.Secret,
		PrivateKey: key.String(), Name: *name, Address: response.Address, Interface: *iface, ListenPort: listen,
		Endpoint: *endpoint, AdvertiseRoutes: advertised, Forwarding: *relay || len(advertised) > 0, Hosts: !*noHosts}
	if node.AdvertiseRoutes == nil {
		node.AdvertiseRoutes = []string{}
	}
	if err := node.Save(*dir); err != nil {
		fail("joined, but could not save the node identity: %v", err)
	}
	state := "connected"
	if response.Status == meshproto.StatusPending {
		state = "waiting for the administrator to approve it"
	}
	fmt.Printf("Joined the mesh as %s (%s), %s.\n", node.Name, node.Address, state)
	if len(advertised) > 0 {
		fmt.Printf("Offered subnets %s; the administrator approves them in the Ghostlink app.\n", strings.Join(advertised, ", "))
	}
}

func serve(dir, backend string) {
	logger := log.New(os.Stderr, "ghostlink-mesh: ", 0)
	node, err := meshagent.LoadNode(dir)
	if err != nil {
		fail("%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agent := &meshagent.Agent{Dir: dir, Node: node, Log: logger, FW: firewall(backend), Version: version.Ghostlink}
	logger.Printf("starting %s (%s) for %s", node.Name, node.Address, node.URL)
	if err := agent.Serve(ctx); err != nil {
		fail("%v", err)
	}
}

func status(dir string, asJSON bool) {
	node, err := meshagent.LoadNode(dir)
	if err != nil {
		fail("%v", err)
	}
	s, err := meshagent.ReadStatus(dir)
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"node": map[string]any{"name": node.Name, "address": node.Address,
			"coordinator": node.URL, "interface": node.Interface, "listen_port": node.ListenPort, "forwarding": node.Forwarding}, "status": s})
		return
	}
	fmt.Printf("%s  %s  on %s (UDP %d), coordinator %s\n", node.Name, node.Address, node.Interface, node.ListenPort, node.URL)
	if err != nil {
		fmt.Println("The agent has not reported yet. Is it running? sudo systemctl status ghostlink-mesh")
		return
	}
	age := time.Since(time.Unix(s.UpdatedUnix, 0)).Round(time.Second)
	fmt.Printf("State: %s (updated %s ago)", s.State, age)
	if s.Relay {
		fmt.Print(", relay")
	}
	if len(s.Shared) > 0 {
		fmt.Printf(", sharing %s", strings.Join(s.Shared, ", "))
	}
	fmt.Println()
	if s.Error != "" {
		fmt.Println("Problem: " + s.Error)
	}
	if len(s.Peers) == 0 {
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nPEER\tADDRESSES\tENDPOINT\tHANDSHAKE\tLATENCY\tRECEIVED\tSENT")
	for _, p := range s.Peers {
		handshake := "never"
		if p.LastHandshake > 0 {
			handshake = time.Since(time.Unix(p.LastHandshake, 0)).Round(time.Second).String() + " ago"
		}
		latency := "-"
		for _, a := range p.AllowedIPs {
			if us := s.Pings[strings.TrimSuffix(a, "/32")]; us > 0 {
				latency = fmt.Sprintf("%.1f ms", float64(us)/1000)
				break
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d B\t%d B\n", p.Name, strings.Join(p.AllowedIPs, ","), p.Endpoint, handshake, latency, p.RxBytes, p.TxBytes)
	}
	w.Flush()
}
