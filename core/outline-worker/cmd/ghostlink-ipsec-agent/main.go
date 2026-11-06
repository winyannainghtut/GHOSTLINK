// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Command ghostlink-ipsec-agent runs strongSwan for the Ghostlink server's IKEv2 and IPsec
// (iPhone, iPad and Mac) users. It runs in its own container with only the network
// capabilities IPsec needs, applies the settings the unprivileged server writes to
// <dir>/desired.json after validating them, and reports back in <dir>/status.json.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ghostlink.local/outline-worker/internal/ipsecagent"
	"ghostlink.local/outline-worker/internal/version"
)

const usage = `usage: ghostlink-ipsec-agent [serve] [flags] | version

  serve      run strongSwan and apply the Ghostlink server's IPsec settings (default)
  version    print the version

flags:
  --dir DIR          directory shared with the server (default /var/lib/ghostlink-server/ipsec)
  --run DIR          private runtime directory (default /run/ghostlink-ipsec)
  --iptables MODE    nft, legacy or auto: the iptables backend the host uses (default auto)
`

func main() {
	args := os.Args[1:]
	command := "serve"
	if len(args) > 0 && (args[0] == "serve" || args[0] == "version" || args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		command, args = args[0], args[1:]
	}
	switch command {
	case "version":
		fmt.Println("Ghostlink IPsec agent " + version.Ghostlink)
		return
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	}
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	dir := flags.String("dir", "/var/lib/ghostlink-server/ipsec", "")
	runDir := flags.String("run", "/run/ghostlink-ipsec", "")
	backend := flags.String("iptables", "auto", "")
	_ = flags.Parse(args)
	logger := log.New(os.Stderr, "ghostlink-ipsec-agent: ", 0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mode := *backend
	switch mode {
	case "auto":
		mode = ipsecagent.DetectBackend(ctx)
	case "nft", "legacy":
	default:
		logger.Fatalf("--iptables must be nft, legacy or auto")
	}
	agent := &ipsecagent.Agent{
		Dir: *dir, Run: *runDir, Log: logger, FW: &ipsecagent.Firewall{Backend: mode},
		Charon: "/usr/lib/strongswan/charon", Swanctl: "/usr/sbin/swanctl",
	}
	logger.Printf("starting (Ghostlink %s)", version.Ghostlink)
	if err := agent.Serve(ctx); err != nil {
		logger.Fatalf("%v", err)
	}
}
