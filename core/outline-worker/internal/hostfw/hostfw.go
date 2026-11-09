// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package hostfw manages a Ghostlink agent's own iptables chains on a host. An agent renders its
// chains as iptables-restore input; Restore replaces exactly those chains (atomically per table,
// with --noflush), EnsureJumps keeps one jump to each from its built-in chain (and from Docker's
// DOCKER-USER for forwarded traffic), and Remove takes everything away again. Rules from other
// software are never touched. It uses the iptables backend the host already uses (nft or
// legacy), because a packet must pass both backends.
package hostfw

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// Jump is a rule in a built-in chain that sends matching packets to an agent chain.
type Jump struct {
	Table  string
	Chain  string
	Match  []string
	Target string
	// Docker: a filter FORWARD jump also kept first in Docker's DOCKER-USER (see dockerChain).
	// Only for a chain that ends every packet it sees with ACCEPT or DROP, or that does nothing
	// but accept, since a packet can pass it twice: once from DOCKER-USER, once from FORWARD.
	Docker bool
}

func (j Jump) args(op string, position ...string) []string {
	args := append([]string{"-t", j.Table, op, j.Chain}, position...)
	args = append(args, j.Match...)
	return append(args, "-j", j.Target)
}

// Firewall applies rules with one backend.
type Firewall struct {
	Backend string // "nft" or "legacy"
}

// Run executes a command with a timeout, feeding it stdin.
func Run(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Detect picks the backend with more rules in it (as Kubernetes' iptables wrapper does); a fresh
// host with neither picks nft.
func Detect(ctx context.Context) string {
	count := func(backend string) int {
		out, err := Run(ctx, "", "iptables-"+backend+"-save")
		if err != nil {
			return -1
		}
		return strings.Count(out, "\n-A ")
	}
	if count("legacy") > count("nft") {
		return "legacy"
	}
	return "nft"
}

// DetectHost is Detect for an agent running on the host itself (not in a container): it uses
// the backend the host's iptables command points to, as Docker, ufw and firewalld do. That is
// known even at boot, before any of them added rules to count.
func DetectHost(ctx context.Context) string {
	out, _ := Run(ctx, "", "iptables", "-V")
	if backend := backendOf(out); backend != "" {
		return backend
	}
	return Detect(ctx)
}

// backendOf reads the backend from `iptables -V` ("iptables v1.8.7 (nf_tables)"); versions
// before 1.8 do not say.
func backendOf(version string) string {
	switch {
	case strings.Contains(version, "(nf_tables)"):
		return "nft"
	case strings.Contains(version, "(legacy)"):
		return "legacy"
	}
	return ""
}

func (f *Firewall) iptables(ctx context.Context, args ...string) error {
	_, err := Run(ctx, "", "iptables-"+f.Backend, append([]string{"-w", "5"}, args...)...)
	return err
}

// Restore replaces the chains declared in each table's iptables-restore input.
func (f *Firewall) Restore(ctx context.Context, tables map[string]string) error {
	if f.Backend != "nft" && f.Backend != "legacy" {
		return errors.New("unknown iptables backend")
	}
	for _, table := range []string{"filter", "nat", "mangle"} {
		if tables[table] == "" {
			continue
		}
		if _, err := Run(ctx, tables[table], "iptables-"+f.Backend+"-restore", "--noflush", "-w", "5"); err != nil {
			return err
		}
	}
	return nil
}

// dockerChain is where Docker lets other software filter forwarded traffic. Docker keeps its
// jump to DOCKER-USER first in FORWARD, ahead of the rules that accept traffic to its containers'
// published ports, and never changes what is in it. A jump that is first in FORWARD does not
// stay first: Docker puts its own rules ahead of it when it starts later. So a filter FORWARD
// jump marked Docker is also kept first in DOCKER-USER while that chain exists, and the agent's
// rules run before Docker's accept rules, without competing with Docker for the first place in
// FORWARD (code review 2026-11-09, F1).
const dockerChain = "DOCKER-USER"

// withDocker adds the DOCKER-USER copies of the jumps marked Docker, when the host has that chain.
func (f *Firewall) withDocker(ctx context.Context, jumps []Jump) []Jump {
	if f.iptables(ctx, "-t", "filter", "-S", dockerChain) != nil {
		return jumps
	}
	return append(slices.Clone(jumps), dockerCopies(jumps)...)
}

// dockerCopies are the DOCKER-USER copies of the filter FORWARD jumps marked Docker.
func dockerCopies(jumps []Jump) []Jump {
	var copies []Jump
	for _, j := range jumps {
		if j.Docker && j.Table == "filter" && j.Chain == "FORWARD" {
			j.Chain = dockerChain
			copies = append(copies, j)
		}
	}
	return copies
}

// EnsureJumps puts back a jump someone removed (for example a firewall reload), first in its
// chain, and adds the DOCKER-USER copies once Docker made that chain.
func (f *Firewall) EnsureJumps(ctx context.Context, jumps []Jump) error {
	for _, j := range f.withDocker(ctx, jumps) {
		if f.iptables(ctx, j.args("-C")...) == nil {
			continue
		}
		if err := f.iptables(ctx, j.args("-I", "1")...); err != nil {
			return err
		}
	}
	return nil
}

// HasJumps reports whether every jump is in place, the DOCKER-USER copies included.
func (f *Firewall) HasJumps(ctx context.Context, jumps []Jump) bool {
	for _, j := range f.withDocker(ctx, jumps) {
		if f.iptables(ctx, j.args("-C")...) != nil {
			return false
		}
	}
	return true
}

// Remove deletes the jumps (also from DOCKER-USER), then flushes and deletes the chains
// (table -> chains).
func (f *Firewall) Remove(ctx context.Context, jumps []Jump, chains map[string][]string) {
	for _, j := range append(slices.Clone(jumps), dockerCopies(jumps)...) {
		for i := 0; i < 8 && f.iptables(ctx, j.args("-D")...) == nil; i++ {
		}
	}
	for _, table := range []string{"filter", "nat", "mangle"} {
		for _, chain := range chains[table] {
			_ = f.iptables(ctx, "-t", table, "-F", chain)
		}
		for _, chain := range chains[table] {
			_ = f.iptables(ctx, "-t", table, "-X", chain)
		}
	}
}
