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
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"ghostlink.local/outline-worker/internal/mesh"
)

const meshUsage = `Mesh: a private network between your Linux servers (run with sudo):

  mesh                                 status, nodes and links
  mesh enable [--cidr 100.96.0.0/16]   turn the mesh on (this server coordinates it)
  mesh disable                         turn it off (nodes disconnect, nothing is deleted)
  mesh invite [--tags web,db] [--uses 1] [--hours 24] [--relay] [--approval]
                                       print the one-line command that joins a server
  mesh invites | mesh revoke ID        open invites
  mesh nodes                           nodes, addresses, tags and status
  mesh approve NAME [--routes CIDR,...]
                                       let a waiting node in, and share the subnets it offers
  mesh node NAME [--name N] [--tags a,b] [--relay on|off] [--masquerade on|off]
                [--routes CIDR,...|none] [--disable|--enable]
  mesh remove NAME
  mesh rules                           access rules (no rules: every node reaches every node)
  mesh rules add --from tag:web --to tag:db --proto tcp --ports 5432
  mesh rules remove N | mesh rules clear
  mesh map                             links: direct or relayed, latency, traffic`

func splitList(text string) []string {
	var out []string
	for _, part := range strings.Split(text, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func onOff(text, what string) (bool, error) {
	switch text {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("%s is on or off", what)
}

func (c *AdminClient) meshTopology() (mesh.Topology, error) {
	var t mesh.Topology
	return t, c.Do(http.MethodGet, "/mesh/topology", nil, &t)
}

func (c *AdminClient) findMeshNode(ref string) (mesh.NodeView, error) {
	t, err := c.meshTopology()
	if err != nil {
		return mesh.NodeView{}, err
	}
	for _, n := range t.Nodes {
		if n.Name == ref || n.ID == ref {
			return n, nil
		}
	}
	return mesh.NodeView{}, fmt.Errorf("no mesh node called %q (see: sudo ghostlink-server mesh nodes)", ref)
}

func (c *AdminClient) meshCommand(args []string, out io.Writer, asJSON bool) error {
	action, rest := "status", args
	if len(args) > 0 {
		action, rest = args[0], args[1:]
	}
	print := func(v any, text func()) error {
		if asJSON {
			encoder := json.NewEncoder(out)
			encoder.SetIndent("", "  ")
			return encoder.Encode(v)
		}
		text()
		return nil
	}
	table := func(header string, rows [][]string) {
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, header)
		for _, row := range rows {
			fmt.Fprintln(w, strings.Join(row, "\t"))
		}
		w.Flush()
	}
	nodeRows := func(t mesh.Topology) [][]string {
		var rows [][]string
		for _, n := range t.Nodes {
			state := n.Status
			if n.Status == "active" {
				state = "offline"
				if n.Online {
					state = "online"
				}
			}
			role := "-"
			switch {
			case n.RelayInUse:
				role = "relay"
			case n.Relay:
				role = "relay (standby)"
			}
			routes := strings.Join(n.ApprovedRoutes, ",")
			if waiting := len(n.AdvertisedRoutes) - len(n.ApprovedRoutes); waiting > 0 {
				routes = strings.TrimPrefix(routes+fmt.Sprintf(",%d waiting", waiting), ",")
			}
			rows = append(rows, []string{n.Name, n.Address, state, strings.Join(n.Tags, ","), role, routes, n.Endpoint})
		}
		return rows
	}
	names := func(t mesh.Topology) map[string]string {
		out := map[string]string{}
		for _, n := range t.Nodes {
			out[n.ID] = n.Name
		}
		return out
	}

	switch action {
	case "help", "-h", "--help":
		fmt.Fprintln(out, meshUsage)
		return nil
	case "status", "nodes":
		var info meshInfo
		if err := c.Do(http.MethodGet, "/mesh", nil, &info); err != nil {
			return err
		}
		if !info.Enabled {
			return print(info, func() {
				fmt.Fprintln(out, "The mesh is off. Turn it on with: sudo ghostlink-server mesh enable")
			})
		}
		t, err := c.meshTopology()
		if err != nil {
			return err
		}
		return print(t, func() {
			if action == "status" {
				fmt.Fprintf(out, "%s: %s, agents connect to %s\n", info.Name, info.CIDR, info.URL)
				fmt.Fprintf(out, "%d nodes, %d waiting for approval, %d rules, %d open invites\n\n", info.Nodes, info.Pending, info.Rules, len(info.Invites))
			}
			if len(t.Nodes) == 0 {
				fmt.Fprintln(out, "No nodes yet. Add one: sudo ghostlink-server mesh invite")
				return
			}
			table("NAME\tADDRESS\tSTATE\tTAGS\tROLE\tSUBNETS\tENDPOINT", nodeRows(t))
		})
	case "enable":
		flags := flag.NewFlagSet("mesh enable", flag.ContinueOnError)
		cidr := flags.String("cidr", "", "")
		if err := parseFlags(flags, rest); err != nil {
			return err
		}
		patch := map[string]any{"enabled": true}
		if *cidr != "" {
			patch["cidr"] = *cidr
		}
		var info meshInfo
		if err := c.Do(http.MethodPatch, "/mesh", patch, &info); err != nil {
			return err
		}
		return print(info, func() {
			fmt.Fprintf(out, "The mesh is on: %s. Agents connect to %s (allow TCP %d in your firewall and cloud security group).\n", info.CIDR, info.URL, info.Port)
			fmt.Fprintln(out, "Add a server: sudo ghostlink-server mesh invite --tags NAME")
		})
	case "disable":
		if err := c.Do(http.MethodPatch, "/mesh", map[string]any{"enabled": false}, nil); err != nil {
			return err
		}
		fmt.Fprintln(out, "The mesh is off; nodes disconnect within seconds. Turn it on again with: sudo ghostlink-server mesh enable")
		return nil
	case "invite":
		flags := flag.NewFlagSet("mesh invite", flag.ContinueOnError)
		tags := flags.String("tags", "", "")
		uses := flags.Int("uses", 1, "")
		hours := flags.Int("hours", mesh.DefaultInviteHours, "")
		relay := flags.Bool("relay", false, "")
		approval := flags.Bool("approval", false, "")
		local := flags.Bool("local", false, "")
		note := flags.String("note", "", "")
		if err := parseFlags(flags, rest); err != nil {
			return err
		}
		request := map[string]any{"tags": splitList(*tags), "uses": *uses, "expires_hours": *hours, "relay": *relay,
			"approval": *approval, "local": *local, "note": *note}
		var created inviteCreated
		if err := c.Do(http.MethodPost, "/mesh/invites", request, &created); err != nil {
			return err
		}
		return print(created, func() {
			fmt.Fprintf(out, "Run this on the server to add (works %d time(s), until %s):\n\n  %s\n\n", created.UsesLeft,
				time.Unix(created.ExpiresUnix, 0).UTC().Format("2 Jan 15:04 UTC"), created.Command)
			fmt.Fprintln(out, "Options after --join: --name NAME, --advertise-routes 10.0.0.0/24 (share a subnet; approve it here),")
			fmt.Fprintln(out, "--port N (WireGuard UDP port, default 51820). Keep the command private until it is used.")
		})
	case "invites":
		var invites []inviteView
		if err := c.Do(http.MethodGet, "/mesh/invites", nil, &invites); err != nil {
			return err
		}
		return print(invites, func() {
			if len(invites) == 0 {
				fmt.Fprintln(out, "No open invites.")
				return
			}
			var rows [][]string
			for _, i := range invites {
				rows = append(rows, []string{i.ID, strings.Join(i.Tags, ","), strconv.Itoa(i.UsesLeft), time.Unix(i.ExpiresUnix, 0).UTC().Format("2 Jan 15:04 UTC"), fmt.Sprint(i.Relay), fmt.Sprint(i.Approval)})
			}
			table("ID\tTAGS\tUSES LEFT\tEXPIRES\tRELAY\tAPPROVAL", rows)
		})
	case "revoke":
		if len(rest) != 1 {
			return errors.New("usage: mesh revoke INVITE-ID (see: mesh invites)")
		}
		if err := c.Do(http.MethodDelete, "/mesh/invites/"+rest[0], nil, nil); err != nil {
			return err
		}
		fmt.Fprintln(out, "Invite revoked.")
		return nil
	case "approve", "node":
		if len(rest) < 1 {
			return fmt.Errorf("usage: mesh %s NAME ...", action)
		}
		node, err := c.findMeshNode(rest[0])
		if err != nil {
			return err
		}
		flags := flag.NewFlagSet("mesh "+action, flag.ContinueOnError)
		name := flags.String("name", "", "")
		tags := flags.String("tags", "", "")
		relay := flags.String("relay", "", "")
		masquerade := flags.String("masquerade", "", "")
		routes := flags.String("routes", "", "")
		disable := flags.Bool("disable", false, "")
		enable := flags.Bool("enable", false, "")
		if err := parseFlags(flags, rest[1:]); err != nil {
			return err
		}
		change := map[string]any{}
		if action == "approve" {
			change["status"] = "active"
			change["approved_routes"] = node.AdvertisedRoutes
		}
		if *name != "" {
			change["name"] = *name
		}
		if *tags != "" {
			change["tags"] = splitList(*tags)
		}
		for field, value := range map[string]string{"relay": *relay, "masquerade": *masquerade} {
			if value != "" {
				on, err := onOff(value, "--"+field)
				if err != nil {
					return err
				}
				change[field] = on
			}
		}
		switch {
		case *routes == "none":
			change["approved_routes"] = []string{}
		case *routes == "all":
			change["approved_routes"] = node.AdvertisedRoutes
		case *routes != "":
			change["approved_routes"] = splitList(*routes)
		}
		if *disable {
			change["status"] = "disabled"
		}
		if *enable {
			change["status"] = "active"
		}
		if len(change) == 0 {
			return errors.New("nothing to change; see: sudo ghostlink-server mesh help")
		}
		var updated mesh.NodeView
		if err := c.Do(http.MethodPatch, "/mesh/nodes/"+node.ID, change, &updated); err != nil {
			return err
		}
		return print(updated, func() {
			fmt.Fprintf(out, "Updated %s (%s, %s). Nodes pick it up within seconds.\n", updated.Name, updated.Address, updated.Status)
		})
	case "remove":
		if len(rest) != 1 {
			return errors.New("usage: mesh remove NAME")
		}
		node, err := c.findMeshNode(rest[0])
		if err != nil {
			return err
		}
		if err := c.Do(http.MethodDelete, "/mesh/nodes/"+node.ID, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed %s; the other nodes drop it within seconds.\n", node.Name)
		return nil
	case "rules":
		return c.meshRules(rest, out, print, table)
	case "map", "links":
		t, err := c.meshTopology()
		if err != nil {
			return err
		}
		return print(t.Links, func() {
			if len(t.Links) == 0 {
				fmt.Fprintln(out, "No links yet (a link needs two active nodes).")
				return
			}
			byID := names(t)
			var rows [][]string
			for _, l := range t.Links {
				path := l.Path
				if l.Path == "relay" {
					path = "via " + byID[l.Via]
				}
				latency := "-"
				if l.RTTMillis > 0 {
					latency = fmt.Sprintf("%.1f ms", l.RTTMillis)
				}
				rows = append(rows, []string{byID[l.A] + " <-> " + byID[l.B], path, latency, rate(int64(l.RxBps + l.TxBps))})
			}
			table("LINK\tPATH\tLATENCY\tTRAFFIC", rows)
		})
	}
	return fmt.Errorf("unknown mesh command %q\n\n%s", action, meshUsage)
}

func (c *AdminClient) meshRules(args []string, out io.Writer, print func(any, func()) error, table func(string, [][]string)) error {
	var current struct {
		Rules []mesh.Rule `json:"rules"`
	}
	if err := c.Do(http.MethodGet, "/mesh/rules", nil, &current); err != nil {
		return err
	}
	save := func(rules []mesh.Rule) error {
		if rules == nil {
			rules = []mesh.Rule{}
		}
		if err := c.Do(http.MethodPut, "/mesh/rules", map[string]any{"rules": rules}, nil); err != nil {
			return err
		}
		if len(rules) == 0 {
			fmt.Fprintln(out, "No rules: every node can reach every other node.")
		} else {
			fmt.Fprintf(out, "Saved %d rule(s). Everything else between nodes is blocked.\n", len(rules))
		}
		return nil
	}
	if len(args) == 0 {
		return print(current.Rules, func() {
			if len(current.Rules) == 0 {
				fmt.Fprintln(out, "No rules: every node can reach every other node. Add one: sudo ghostlink-server mesh rules add --from tag:web --to tag:db --proto tcp --ports 5432")
				return
			}
			var rows [][]string
			for i, r := range current.Rules {
				ports := strings.Join(r.Ports, ",")
				if ports == "" {
					ports = "all"
				}
				rows = append(rows, []string{strconv.Itoa(i + 1), r.From, r.To, r.Protocol, ports})
			}
			table("#\tFROM\tTO\tPROTOCOL\tPORTS", rows)
			fmt.Fprintln(out, "\nEverything not allowed above is blocked between nodes (replies and, unless turned off, ping always pass).")
		})
	}
	switch args[0] {
	case "add":
		flags := flag.NewFlagSet("mesh rules add", flag.ContinueOnError)
		from := flags.String("from", "*", "")
		to := flags.String("to", "*", "")
		proto := flags.String("proto", "any", "")
		ports := flags.String("ports", "", "")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		rule := mesh.Rule{From: *from, To: *to, Protocol: *proto, Ports: splitList(*ports)}
		return save(append(current.Rules, rule))
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: mesh rules remove N (see: mesh rules)")
		}
		i, err := strconv.Atoi(args[1])
		if err != nil || i < 1 || i > len(current.Rules) {
			return fmt.Errorf("there is no rule %s", args[1])
		}
		return save(append(current.Rules[:i-1], current.Rules[i:]...))
	case "clear":
		return save(nil)
	}
	return fmt.Errorf("unknown mesh rules command %q", args[0])
}
