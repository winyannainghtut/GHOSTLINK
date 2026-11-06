// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Command ghostlink-server runs a Ghostlink VPN server: Shadowsocks, VLESS-REALITY, WireGuard
// and AmneziaWG on unmodified sing-box and amneziawg-go, managed through an HTTPS API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ghostlink.local/outline-worker/internal/server"
	"ghostlink.local/outline-worker/internal/version"
)

const defaultState = "/var/lib/ghostlink-server"

const usage = `usage: ghostlink-server <command> [flags]

commands:
  init      create the server on first run (or update --hostname) and print the management key
  serve     run the VPN engine and the management API
  show-key  print the management key
  check     validate the stored configuration without opening ports
  version   print the version

flags:
  --state DIR      state directory (default /var/lib/ghostlink-server)
  --hostname HOST  public IP or DNS name clients use (init; detected when omitted)
  --name NAME      server display name (init)
  --log-level L    engine log level: error, warn, info, debug (serve; default warn)
`

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ghostlink-server: "+format+"\n", args...)
	os.Exit(1)
}

// detectPublicAddress asks public "what is my IP" services (documented in the server guide).
func detectPublicAddress() (string, error) {
	client := &http.Client{Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var errs []error
	for _, service := range []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"} {
		response, err := client.Get(service)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 64))
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("%s answered %d", service, response.StatusCode))
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		if err != nil || addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
			errs = append(errs, fmt.Errorf("%s gave no usable public address", service))
			continue
		}
		return addr.String(), nil
	}
	return "", errors.Join(errs...)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	state := flags.String("state", defaultState, "")
	hostname := flags.String("hostname", "", "")
	name := flags.String("name", "", "")
	logLevel := flags.String("log-level", "warn", "")
	_ = flags.Parse(os.Args[2:])
	if flags.NArg() != 0 {
		fail("unexpected argument %q", flags.Arg(0))
	}
	switch command {
	case "version":
		fmt.Println(version.Server)
	case "init":
		store, created, err := server.Initialize(*state, server.InitOptions{
			Name: *name, Hostname: *hostname, DetectHostname: detectPublicAddress,
		})
		if err != nil {
			fail("%v", err)
		}
		if created {
			fmt.Fprintln(os.Stderr, "ghostlink-server: created a new server")
		}
		printKey(store.Dir())
	case "show-key":
		printKey(*state)
	case "check":
		store, err := server.Load(*state)
		if err != nil {
			fail("%v", err)
		}
		if err := server.Check(store.State); err != nil {
			fail("configuration is invalid: %v", err)
		}
		fmt.Println("configuration ok")
	case "serve":
		serve(*state, *logLevel)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func printKey(dir string) {
	data, err := os.ReadFile(filepath.Join(dir, server.ManagementKeyFile))
	if err != nil {
		fail("no management key yet; run init first (%v)", err)
	}
	os.Stdout.Write(data)
}

func serve(dir, logLevel string) {
	switch logLevel {
	case "error", "warn", "info", "debug":
	default:
		fail("unknown log level %q", logLevel)
	}
	store, err := server.Load(dir)
	if err != nil {
		fail("%v (run init first)", err)
	}
	usage := server.NewUsage()
	service := server.NewService(store, server.NewEngine(usage, logLevel), usage)
	if err := service.Start(); err != nil {
		fail("could not start the VPN engine: %v", err)
	}
	api := server.NewAPI(service, version.Ghostlink)
	httpServer, listener, err := api.Listen()
	if err != nil {
		service.Close()
		fail("could not start the management API: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- httpServer.ServeTLS(listener, "", "") }()
	accounted := make(chan struct{})
	go func() {
		service.RunAccounting(ctx, 30*time.Second, func(err error) {
			fmt.Fprintf(os.Stderr, "ghostlink-server: usage accounting: %v\n", err)
		})
		close(accounted)
	}()
	fmt.Fprintf(os.Stderr, "ghostlink-server: running (%s)\n", version.Server)
	exit := 0
	select {
	case <-ctx.Done():
	case err := <-served:
		fmt.Fprintf(os.Stderr, "ghostlink-server: management API stopped: %v\n", err)
		exit = 1
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = httpServer.Shutdown(shutdown)
	cancel()
	<-accounted
	if err := service.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "ghostlink-server: engine close: %v\n", err)
	}
	fmt.Fprintln(os.Stderr, "ghostlink-server: stopped")
	os.Exit(exit)
}
