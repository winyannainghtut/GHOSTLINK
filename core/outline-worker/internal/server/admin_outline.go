// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Outline's files in its persisted-state directory.
const (
	outlineKeysFile   = "shadowbox_config.json"
	outlineServerFile = "shadowbox_server_config.json"
)

// importOutlineCommand reads Outline's two files from a directory and imports them. It only
// reads: the host command makes private copies for it and deletes them afterwards.
func (c *AdminClient) importOutlineCommand(args []string, out io.Writer, print func(any, func()) error) error {
	flags := flag.NewFlagSet("import-outline", flag.ContinueOnError)
	dir := flags.String("dir", "", "")
	check := flags.Bool("check", false, "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dir == "" || flags.NArg() > 0 {
		return errors.New("usage: import-outline --dir DIR [--check]")
	}
	read := func(name string, required bool) (json.RawMessage, error) {
		data, err := os.ReadFile(filepath.Join(*dir, name))
		switch {
		case errors.Is(err, os.ErrNotExist) && !required:
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("cannot read Outline's %s: %w", name, err)
		case len(data) > maxOutlineBytes:
			return nil, fmt.Errorf("Outline's %s is larger than %d MB", name, maxOutlineBytes>>20)
		case !json.Valid(data):
			return nil, fmt.Errorf("Outline's %s is not valid JSON", name)
		}
		return data, nil
	}
	keys, err := read(outlineKeysFile, true)
	if err != nil {
		return err
	}
	server, err := read(outlineServerFile, false)
	if err != nil {
		return err
	}
	var report outlineReport
	body := map[string]any{"access_keys": keys, "server": server, "dry_run": *check}
	if err := c.Do(http.MethodPost, "/import/outline", body, &report); err != nil {
		return err
	}
	return print(report, func() { writeOutlineReport(out, report) })
}

func writeOutlineReport(out io.Writer, r outlineReport) {
	if r.DryRun {
		fmt.Fprintln(out, "Check only: nothing has changed yet. The import would do this:")
	} else {
		fmt.Fprintln(out, "Imported from Outline:")
	}
	fmt.Fprintf(out, "  %d clients, one per Outline access key; %d keep their Outline key as it is.\n", r.Clients, r.Kept)
	ports := strconv.Itoa(int(r.Port))
	if len(r.ExtraPorts) > 0 {
		extra := []string{}
		for _, p := range r.ExtraPorts {
			extra = append(extra, strconv.Itoa(int(p)))
		}
		ports += ", plus " + strings.Join(extra, ", ") + " for keys on other ports"
	}
	fmt.Fprintf(out, "  Shadowsocks: port %s (cipher %s).\n", ports, r.Method)
	fmt.Fprintf(out, "  Server: %s, address in keys %s.\n", r.Name, r.Hostname)
	for _, m := range r.Moved {
		fmt.Fprintf(out, "  %s moves from port %d to %d to make way for Outline's.\n", m.Service, m.From, m.To)
	}
	if len(r.Disabled) > 0 {
		fmt.Fprintf(out, "  Turned off, as in Outline (a data limit of 0): %s.\n", strings.Join(r.Disabled, ", "))
	}
	if len(r.NewKeys) > 0 {
		fmt.Fprintln(out, "  These clients get a new key, which you need to send them:")
		for _, k := range r.NewKeys {
			fmt.Fprintf(out, "    %s: %s\n", k.Client, k.Reason)
		}
	}
	for _, note := range r.Notes {
		fmt.Fprintf(out, "  Note: %s\n", note)
	}
	if !r.DryRun {
		if r.HostnameChanged {
			fmt.Fprintln(out, "The server now uses Outline's address, so the management key changed: sudo ghostlink-server show-key")
		}
		if len(r.NewKeys) > 0 {
			fmt.Fprintln(out, "Show a new key with: sudo ghostlink-server keys NAME --show")
		}
	}
}
