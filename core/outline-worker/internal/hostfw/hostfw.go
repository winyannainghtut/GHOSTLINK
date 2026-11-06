// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package hostfw manages a Ghostlink agent's own iptables chains on a host. An agent renders its
// chains as iptables-restore input; Restore replaces exactly those chains (atomically per table,
// with --noflush), EnsureJumps keeps one jump to each from its built-in chain, and Remove takes
// everything away again. Rules from other software are never touched. It uses the iptables
// backend the host already uses (nft or legacy), because a packet must pass both backends.
package hostfw

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Jump is a rule in a built-in chain that sends matching packets to an agent chain.
type Jump struct {
	Table  string
	Chain  string
	Match  []string
	Target string
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

// EnsureJumps puts back a jump someone removed (for example a firewall reload), first in its
// chain.
func (f *Firewall) EnsureJumps(ctx context.Context, jumps []Jump) error {
	for _, j := range jumps {
		if f.iptables(ctx, j.args("-C")...) == nil {
			continue
		}
		if err := f.iptables(ctx, j.args("-I", "1")...); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes the jumps, then flushes and deletes the chains (table -> chains).
func (f *Firewall) Remove(ctx context.Context, jumps []Jump, chains map[string][]string) {
	for _, j := range jumps {
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
