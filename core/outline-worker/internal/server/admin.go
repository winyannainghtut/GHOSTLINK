// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// AdminClient manages the local server through its management API on loopback, with the same
// certificate pin as any other client, so changes apply live and are validated the same way.
type AdminClient struct {
	base   string
	client *http.Client
	pin    string
}

func NewAdminClient(dir string) (*AdminClient, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManagementKeyFile))
	if err != nil {
		return nil, fmt.Errorf("no management key in %s (is the server set up?)", dir)
	}
	var key ManagementKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(key.APIURL)
	if err != nil {
		return nil, err
	}
	pin := strings.ToUpper(key.CertSHA256)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if strings.ToUpper(hex.EncodeToString(sum[:])) != pin {
				return errors.New("the local API certificate does not match the management key")
			}
			return nil
		},
	}, Proxy: nil}
	return &AdminClient{
		base:   fmt.Sprintf("https://127.0.0.1:%s%s", parsed.Port(), parsed.Path),
		client: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		pin:    pin,
	}, nil
}

func (c *AdminClient) request(method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("the server is not answering (is it running? try: sudo ghostlink-server status): %w", err)
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&failure)
		if failure.Error == "" {
			failure.Error = response.Status
		}
		return nil, errors.New(failure.Error)
	}
	return response, nil
}

func (c *AdminClient) Do(method, path string, body, out any) error {
	response, err := c.request(method, path, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if out == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func (c *AdminClient) Text(path string) (string, error) {
	response, err := c.request(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return string(data), err
}

// --- formatting helpers ---

func dataSize(n uint64) string {
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%.2f TB", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.0f KB", float64(n)/1e3)
	}
	return fmt.Sprintf("%d B", n)
}

func rate(bytesPerSecond int64) string {
	bits := float64(bytesPerSecond) * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.0f kbit/s", bits/1e3)
	}
	return fmt.Sprintf("%.0f bit/s", bits)
}

func since(unix int64) string {
	if unix == 0 {
		return "never"
	}
	d := time.Since(time.Unix(unix, 0))
	switch {
	case d < 90*time.Second:
		return "just now"
	case d < 90*time.Minute:
		return fmt.Sprintf("%.0f min ago", d.Minutes())
	case d < 36*time.Hour:
		return fmt.Sprintf("%.0f h ago", d.Hours())
	}
	return fmt.Sprintf("%.0f days ago", d.Hours()/24)
}

// parseLimit reads "50GB", "500MB", "1TB", "0" or "none" as decimal bytes.
func parseLimit(text string) (uint64, error) {
	t := strings.ToUpper(strings.TrimSpace(text))
	if t == "NONE" || t == "0" || t == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		scale  float64
	}{{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"G", 1e9}, {"M", 1e6}, {"T", 1e12}}
	for _, unit := range units {
		if strings.HasSuffix(t, unit.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(t, unit.suffix)), 64)
			if err != nil || n < 0 {
				break
			}
			return uint64(n * unit.scale), nil
		}
	}
	return 0, fmt.Errorf("data limits look like 50GB, 500MB, 1TB or none (got %q)", text)
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// adminUser is the subset of a user view the commands need.
type adminUser struct {
	ID                    string       `json:"id"`
	Name                  string       `json:"name"`
	Enabled               bool         `json:"enabled"`
	DataLimitBytes        uint64       `json:"data_limit_bytes"`
	UsageBytes            uint64       `json:"usage_bytes"`
	OverLimit             bool         `json:"over_limit"`
	ExemptFromGlobalRules bool         `json:"exempt_from_global_rules"`
	Rules                 Rules        `json:"rules"`
	Keys                  []keySummary `json:"keys"`
}

func (c *AdminClient) users() ([]adminUser, error) {
	var users []adminUser
	return users, c.Do(http.MethodGet, "/users", nil, &users)
}

// findUser accepts a user's ID or name (any case).
func (c *AdminClient) findUser(ref string) (adminUser, error) {
	users, err := c.users()
	if err != nil {
		return adminUser{}, err
	}
	for _, u := range users {
		if u.ID == ref || strings.EqualFold(u.Name, ref) {
			return u, nil
		}
	}
	return adminUser{}, fmt.Errorf("no user called %q (see: sudo ghostlink-server users)", ref)
}

const adminUsage = `Manage this Ghostlink server (run with sudo):

  users                                list users, usage and status
  user add NAME [--limit 50GB] [--exempt]
  user enable|disable|remove|reset NAME
  user rename NAME NEW-NAME
  user limit NAME 50GB|none
  user exempt NAME on|off              skip the rules for everyone
  key add NAME PROTOCOL [--no-qr]      amneziawg, wireguard, vless or shadowsocks
  key add NAME ikev2|ipsec [--auth eap|certificate|psk] [--address HOST]
          [--remote-id ID] [--local-id ID]
                                       built-in VPN of iPhone, iPad and Mac (needs the
                                       IPsec component: sudo ghostlink-server ipsec enable)
  profile NAME ID [--output FILE] [--prompt-password] [--on-demand]
                                       Apple profile (.mobileconfig) of an IKEv2/IPsec key
  keys NAME [--show]                   list keys (key text only with --show)
  key qr NAME ID [--content key|conf]  show a key's QR code again
  key remove NAME ID
  kit NAME [--output FILE]             HTML page with all of NAME's keys, QR codes and app help
  rules [--user NAME]
  rules set [--user NAME] [--block-site S]... [--block-ip CIDR]... [--block-port P]...
            [--block-bittorrent] [--block-smtp]
  usage                                data used per user
  stats [NAME] [--range 24h|7d|30d|90d]
  clients [NAME]                       addresses users connected from
  top [--once]                         live speed per user (Ctrl+C to quit)
  settings
  set [--name N] [--hostname H] [--reality-site S] [--enable P] [--disable P] [--port P=N]
      [--history-days N] [--site-days N] [--history-max-mb N] [--rotate-ipsec-psk]
  site-stats on|off                    record top sites per user (off deletes them)
  dashboard [--port N] [--public|--private] [--reset-token]

Add --json before the command for machine-readable output.`

// RunAdmin executes one admin command against the server whose state is in dir.
func RunAdmin(dir string, args []string, out io.Writer) error {
	asJSON := false
	if len(args) > 0 && args[0] == "--json" {
		asJSON, args = true, args[1:]
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, adminUsage)
		return nil
	}
	c, err := NewAdminClient(dir)
	if err != nil {
		return err
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
	command, rest := args[0], args[1:]
	switch command {
	case "users":
		users, err := c.users()
		if err != nil {
			return err
		}
		return print(users, func() {
			if len(users) == 0 {
				fmt.Fprintln(out, "No users yet. Add one: sudo ghostlink-server user add NAME")
				return
			}
			var rows [][]string
			for _, u := range users {
				status := "active"
				if u.OverLimit {
					status = "limit reached"
				} else if !u.Enabled {
					status = "paused"
				}
				limit := "no limit"
				if u.DataLimitBytes > 0 {
					limit = dataSize(u.DataLimitBytes)
				}
				rows = append(rows, []string{u.ID, u.Name, status, dataSize(u.UsageBytes), limit, strconv.Itoa(len(u.Keys))})
			}
			table("ID\tNAME\tSTATUS\tUSED\tLIMIT\tKEYS", rows)
		})
	case "user":
		return c.userCommand(rest, out, print)
	case "key":
		return c.keyCommand(rest, out, asJSON)
	case "keys":
		flags := flag.NewFlagSet("keys", flag.ContinueOnError)
		show := flags.Bool("show", false, "")
		if len(rest) == 0 {
			return errors.New("usage: keys NAME [--show]")
		}
		if err := flags.Parse(rest[1:]); err != nil {
			return err
		}
		u, err := c.findUser(rest[0])
		if err != nil {
			return err
		}
		var keys []keyView
		if err := c.Do(http.MethodGet, "/users/"+u.ID+"/keys", nil, &keys); err != nil {
			return err
		}
		if !*show {
			for i := range keys {
				keys[i].AccessKey, keys[i].Config, keys[i].CertificatePassword = "", "", ""
			}
		}
		return print(keys, func() {
			if len(keys) == 0 {
				fmt.Fprintf(out, "%s has no keys. Create one: sudo ghostlink-server key add %s amneziawg\n", u.Name, u.Name)
				return
			}
			for _, k := range keys {
				title := protocolTitles[k.Protocol]
				if k.Auth != "" {
					title += " · " + k.Auth
				}
				fmt.Fprintf(out, "%s  %-34s created %s\n", k.ID, title, time.Unix(k.CreatedUnix, 0).Format("2006-01-02"))
				if k.Identity != "" {
					fmt.Fprintf(out, "    identity %s; profile: sudo ghostlink-server profile %s %s --output %s.mobileconfig\n", k.Identity, u.Name, k.ID, strings.ToLower(identityLabel(u.Name)))
				}
				if *show {
					fmt.Fprintf(out, "    %s\n", k.AccessKey)
				}
			}
			if !*show {
				fmt.Fprintln(out, "Add --show to print the key text.")
			}
		})
	case "kit":
		flags := flag.NewFlagSet("kit", flag.ContinueOnError)
		_ = flags.String("output", "", "") // the host command turns --output into a redirect
		if len(rest) == 0 {
			return errors.New("usage: kit NAME [--output FILE]")
		}
		u, err := c.findUser(rest[0])
		if err != nil {
			return err
		}
		page, err := c.Text("/users/" + u.ID + "/kit")
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, page)
		return err
	case "profile":
		flags := flag.NewFlagSet("profile", flag.ContinueOnError)
		_ = flags.String("output", "", "") // the host command turns --output into a redirect
		prompt := flags.Bool("prompt-password", false, "")
		onDemand := flags.Bool("on-demand", false, "")
		if len(rest) < 2 {
			return errors.New("usage: profile NAME ID [--output FILE] [--prompt-password] [--on-demand]")
		}
		if err := flags.Parse(rest[2:]); err != nil {
			return err
		}
		u, err := c.findUser(rest[0])
		if err != nil {
			return err
		}
		query := url.Values{}
		if *prompt {
			query.Set("prompt_password", "1")
		}
		if *onDemand {
			query.Set("on_demand", "1")
		}
		profile, err := c.Text("/users/" + u.ID + "/keys/" + url.PathEscape(rest[1]) + "/profile?" + query.Encode())
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, profile)
		return err
	case "rules":
		return c.rulesCommand(rest, out, print)
	case "usage":
		var metrics struct {
			Users []userUsage `json:"users"`
			Total uint64      `json:"total_bytes"`
		}
		if err := c.Do(http.MethodGet, "/metrics", nil, &metrics); err != nil {
			return err
		}
		return print(metrics, func() {
			var rows [][]string
			for _, u := range metrics.Users {
				limit := "no limit"
				if u.DataLimitBytes > 0 {
					limit = dataSize(u.DataLimitBytes)
				}
				rows = append(rows, []string{u.Name, dataSize(u.UsageBytes), limit})
			}
			table("NAME\tUSED\tLIMIT", rows)
			fmt.Fprintf(out, "Total: %s\n", dataSize(metrics.Total))
		})
	case "stats":
		return c.statsCommand(rest, out, print)
	case "clients":
		path := "/clients"
		if len(rest) > 0 {
			u, err := c.findUser(rest[0])
			if err != nil {
				return err
			}
			path += "?user=" + u.ID
		}
		var result struct {
			Clients []clientView `json:"clients"`
		}
		if err := c.Do(http.MethodGet, path, nil, &result); err != nil {
			return err
		}
		return print(result, func() {
			if len(result.Clients) == 0 {
				fmt.Fprintln(out, "No connections recorded in the last 30 days.")
				return
			}
			var rows [][]string
			for _, cl := range result.Clients {
				rows = append(rows, []string{cl.Name, cl.IP, protocolTitles[cl.Protocol], time.Unix(cl.First, 0).Format("2006-01-02 15:04"), since(cl.Last)})
			}
			table("USER\tADDRESS\tPROTOCOL\tFIRST SEEN\tLAST SEEN", rows)
		})
	case "top":
		flags := flag.NewFlagSet("top", flag.ContinueOnError)
		once := flags.Bool("once", false, "")
		if err := flags.Parse(rest); err != nil {
			return err
		}
		return c.top(out, *once)
	case "settings":
		var info serverInfo
		if err := c.Do(http.MethodGet, "/server", nil, &info); err != nil {
			return err
		}
		return print(info, func() {
			fmt.Fprintf(out, "%s (version %s)\nAddress in keys: %s\nREALITY site: %s\n\n", info.Name, info.Version, info.Hostname, info.VLESSHandshake)
			var rows [][]string
			for _, p := range Protocols {
				v := info.Protocols[p]
				state := "on"
				if !v.Enabled {
					state = "off"
				}
				rows = append(rows, []string{protocolTitles[p], state, strconv.Itoa(int(v.Port))})
			}
			for _, p := range AppleProtocols {
				state := "off"
				if info.Protocols[p].Enabled {
					state = "on"
				}
				rows = append(rows, []string{protocolTitles[p], state, "UDP 500, 4500"})
			}
			rows = append(rows, []string{"Management API", "on", strconv.Itoa(int(info.APIPort))})
			mode := "private (SSH tunnel)"
			if info.DashboardPublic {
				mode = "public (HTTPS)"
			}
			rows = append(rows, []string{"Dashboard", mode, strconv.Itoa(int(info.DashboardPort))})
			table("SERVICE\tSTATE\tPORT", rows)
			component := info.IPsecComponent
			switch {
			case component.Running && component.Error != "":
				fmt.Fprintf(out, "\nIPsec component: running, with a problem: %s\n", component.Error)
			case component.Running:
				fmt.Fprintf(out, "\nIPsec component: running, %d connected\n", component.Online)
			default:
				fmt.Fprintln(out, "\nIPsec component (IKEv2/IPsec for iPhone, iPad, Mac): not running; start it with: sudo ghostlink-server ipsec enable")
			}
			sites := "off"
			if info.SiteStats {
				sites = "on"
			}
			fmt.Fprintf(out, "\nTop sites per user: %s. History kept %d days (sites %d days), at most %d MB.\n", sites, info.HistoryDays, info.SiteDays, info.HistoryMaxMB)
		})
	case "set":
		return c.setCommand(rest, out)
	case "site-stats":
		if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") {
			return errors.New("usage: site-stats on|off")
		}
		on := rest[0] == "on"
		if err := c.Do(http.MethodPatch, "/server", map[string]any{"site_stats": on}, nil); err != nil {
			return err
		}
		if on {
			fmt.Fprintln(out, "Top sites per user are now recorded (totals only, kept for the site retention).")
		} else {
			fmt.Fprintln(out, "Top sites are off, and every recorded site has been deleted.")
		}
		return nil
	case "dashboard":
		return c.dashboardCommand(rest, out)
	}
	return fmt.Errorf("unknown command %q\n\n%s", command, adminUsage)
}

func (c *AdminClient) userCommand(args []string, out io.Writer, print func(any, func()) error) error {
	if len(args) < 2 {
		return errors.New("usage: user add|enable|disable|remove|reset|rename|limit|exempt NAME ...")
	}
	action, ref, rest := args[0], args[1], args[2:]
	if action == "add" {
		flags := flag.NewFlagSet("user add", flag.ContinueOnError)
		limit := flags.String("limit", "", "")
		exempt := flags.Bool("exempt", false, "")
		if err := flags.Parse(rest); err != nil {
			return err
		}
		change := map[string]any{"name": ref, "exempt_from_global_rules": *exempt}
		if *limit != "" {
			bytes, err := parseLimit(*limit)
			if err != nil {
				return err
			}
			change["data_limit_bytes"] = bytes
		}
		var created adminUser
		if err := c.Do(http.MethodPost, "/users", change, &created); err != nil {
			return err
		}
		return print(created, func() {
			fmt.Fprintf(out, "Added %s (id %s). Next: sudo ghostlink-server key add %s amneziawg\n", created.Name, created.ID, created.Name)
		})
	}
	u, err := c.findUser(ref)
	if err != nil {
		return err
	}
	change := map[string]any{}
	switch action {
	case "enable", "disable":
		change["enabled"] = action == "enable"
	case "reset":
		change["reset_usage"] = true
	case "rename":
		if len(rest) != 1 {
			return errors.New("usage: user rename NAME NEW-NAME")
		}
		change["name"] = rest[0]
	case "limit":
		if len(rest) != 1 {
			return errors.New("usage: user limit NAME 50GB|none")
		}
		bytes, err := parseLimit(rest[0])
		if err != nil {
			return err
		}
		change["data_limit_bytes"] = bytes
	case "exempt":
		if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") {
			return errors.New("usage: user exempt NAME on|off")
		}
		change["exempt_from_global_rules"] = rest[0] == "on"
	case "remove":
		if err := c.Do(http.MethodDelete, "/users/"+u.ID, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed %s. Their keys no longer work.\n", u.Name)
		return nil
	default:
		return fmt.Errorf("unknown user action %q", action)
	}
	var updated adminUser
	if err := c.Do(http.MethodPatch, "/users/"+u.ID, change, &updated); err != nil {
		return err
	}
	return print(updated, func() { fmt.Fprintf(out, "Updated %s.\n", updated.Name) })
}

func (c *AdminClient) keyCommand(args []string, out io.Writer, asJSON bool) error {
	if len(args) < 2 {
		return errors.New("usage: key add NAME PROTOCOL | key qr NAME ID | key remove NAME ID")
	}
	action, ref, rest := args[0], args[1], args[2:]
	u, err := c.findUser(ref)
	if err != nil {
		return err
	}
	switch action {
	case "add":
		if len(rest) < 1 {
			return errors.New("usage: key add NAME amneziawg|wireguard|vless|shadowsocks|ikev2|ipsec [--no-qr]")
		}
		flags := flag.NewFlagSet("key add", flag.ContinueOnError)
		noQR := flags.Bool("no-qr", false, "")
		auth := flags.String("auth", "", "")
		address := flags.String("address", "", "")
		remoteID := flags.String("remote-id", "", "")
		localID := flags.String("local-id", "", "")
		if err := flags.Parse(rest[1:]); err != nil {
			return err
		}
		request := map[string]string{"protocol": rest[0]}
		for field, value := range map[string]string{"auth": *auth, "server_address": *address, "remote_identifier": *remoteID, "local_identifier": *localID} {
			if value != "" {
				request[field] = value
			}
		}
		var key keyView
		if err := c.Do(http.MethodPost, "/users/"+u.ID+"/keys", request, &key); err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(out).Encode(key)
		}
		if key.Protocol == IKEv2 || key.Protocol == IPsec {
			file := strings.ToLower(identityLabel(u.Name)) + ".mobileconfig"
			fmt.Fprintf(out, "%s key for %s (id %s), %s authentication\n  server address  %s\n", protocolTitles[key.Protocol], u.Name, key.ID, key.Auth, key.Address)
			if key.RemoteID != "" {
				fmt.Fprintf(out, "  remote id       %s\n", key.RemoteID)
			}
			fmt.Fprintf(out, "  identity        %s\n", key.Identity)
			if key.CertificatePassword != "" {
				fmt.Fprintf(out, "  cert password   %s (asked only by profiles saved with --prompt-password)\n", key.CertificatePassword)
			}
			if key.Warning != "" {
				fmt.Fprintf(out, "\nWarning: %s\n", key.Warning)
			}
			fmt.Fprintf(out, "\nSave the iPhone/iPad/Mac profile and send it privately to %s (AirDrop, Mail or Files):\n  sudo ghostlink-server profile %s %s --output %s\n", u.Name, u.Name, key.ID, file)
			return nil
		}
		fmt.Fprintf(out, "%s key for %s (id %s):\n\n%s\n", protocolTitles[key.Protocol], u.Name, key.ID, key.AccessKey)
		if key.Config != "" {
			fmt.Fprintf(out, "\n.conf for the WireGuard/AmneziaWG app:\n\n%s", key.Config)
		}
		if !*noQR {
			c.printQR(out, u.ID, key.ID, "auto", key.Protocol, key.Config != "")
		}
		fmt.Fprintf(out, "\nShare it only with %s. All keys and app help in one page: sudo ghostlink-server kit %s --output %s.html\n", u.Name, u.Name, strings.ToLower(u.Name))
		return nil
	case "qr":
		if len(rest) < 1 {
			return errors.New("usage: key qr NAME ID [--content key|conf]")
		}
		flags := flag.NewFlagSet("key qr", flag.ContinueOnError)
		content := flags.String("content", "auto", "")
		if err := flags.Parse(rest[1:]); err != nil {
			return err
		}
		c.printQR(out, u.ID, rest[0], *content, "", false)
		return nil
	case "remove":
		if len(rest) != 1 {
			return errors.New("usage: key remove NAME ID")
		}
		if err := c.Do(http.MethodDelete, "/users/"+u.ID+"/keys/"+rest[0], nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed key %s of %s.\n", rest[0], u.Name)
		return nil
	}
	return fmt.Errorf("unknown key action %q", action)
}

func (c *AdminClient) printQR(out io.Writer, user, key, content, protocol string, conf bool) {
	text, err := c.Text("/users/" + user + "/keys/" + key + "/qr?format=text&content=" + url.QueryEscape(content))
	if err != nil {
		fmt.Fprintf(out, "\n(No QR code: %v)\n", err)
		return
	}
	switch {
	case conf:
		fmt.Fprintln(out, "\nQR code (WireGuard/AmneziaWG app: + then Scan from QR code):")
	case protocol == Shadowsocks:
		fmt.Fprintln(out, "\nQR code (Outline, Shadowrocket, v2rayNG):")
	case protocol == VLESS:
		fmt.Fprintln(out, "\nQR code (v2rayNG, Hiddify, Streisand, Shadowrocket):")
	default:
		fmt.Fprintln(out, "\nQR code:")
	}
	fmt.Fprint(out, text)
}

func (c *AdminClient) rulesCommand(args []string, out io.Writer, print func(any, func()) error) error {
	setting := len(args) > 0 && args[0] == "set"
	if setting {
		args = args[1:]
	}
	flags := flag.NewFlagSet("rules", flag.ContinueOnError)
	userRef := flags.String("user", "", "")
	var sites, ips, ports stringList
	flags.Var(&sites, "block-site", "")
	flags.Var(&ips, "block-ip", "")
	flags.Var(&ports, "block-port", "")
	torrent := flags.Bool("block-bittorrent", false, "")
	smtp := flags.Bool("block-smtp", false, "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	show := func(rules Rules, scope string) error {
		return print(rules, func() {
			fmt.Fprintf(out, "Rules %s:\n", scope)
			list := func(label string, items []string) {
				if len(items) == 0 {
					items = []string{"none"}
				}
				fmt.Fprintf(out, "  %-18s %s\n", label, strings.Join(items, ", "))
			}
			list("Blocked sites", rules.BlockedDomains)
			list("Blocked IPs", rules.BlockedIPs)
			list("Blocked ports", rules.BlockedPorts)
			fmt.Fprintf(out, "  %-18s %v\n  %-18s %v\n", "Block BitTorrent", rules.BlockBitTorrent, "Block mail (25)", rules.BlockSMTP)
		})
	}
	rules := Rules{BlockedDomains: sites, BlockedIPs: ips, BlockedPorts: ports, BlockBitTorrent: *torrent, BlockSMTP: *smtp}
	if *userRef != "" {
		u, err := c.findUser(*userRef)
		if err != nil {
			return err
		}
		if !setting {
			return show(u.Rules, "only for "+u.Name)
		}
		var updated adminUser
		if err := c.Do(http.MethodPatch, "/users/"+u.ID, map[string]any{"rules": rules}, &updated); err != nil {
			return err
		}
		return show(updated.Rules, "only for "+updated.Name)
	}
	if !setting {
		var current Rules
		if err := c.Do(http.MethodGet, "/rules", nil, &current); err != nil {
			return err
		}
		return show(current, "for everyone")
	}
	var saved Rules
	if err := c.Do(http.MethodPut, "/rules", rules, &saved); err != nil {
		return err
	}
	return show(saved, "for everyone")
}

func (c *AdminClient) statsCommand(args []string, out io.Writer, print func(any, func()) error) error {
	ref := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		ref, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("stats", flag.ContinueOnError)
	rangeName := flags.String("range", "7d", "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	path := "/stats?range=" + url.QueryEscape(*rangeName)
	scope := "all users"
	if ref != "" {
		u, err := c.findUser(ref)
		if err != nil {
			return err
		}
		path += "&user=" + u.ID
		scope = u.Name
	}
	var stats StatsResult
	if err := c.Do(http.MethodGet, path, nil, &stats); err != nil {
		return err
	}
	return print(stats, func() {
		var up, down uint64
		for _, b := range stats.Series {
			up, down = up+b.Up, down+b.Down
		}
		fmt.Fprintf(out, "Traffic for %s, last %s: %s down, %s up\n", scope, stats.Range, dataSize(down), dataSize(up))
		section := func(title string, items []labelBytes, empty string) {
			fmt.Fprintf(out, "\n%s\n", title)
			if len(items) == 0 {
				fmt.Fprintf(out, "  %s\n", empty)
				return
			}
			var total uint64
			for _, item := range items {
				total += item.Bytes
			}
			for _, item := range items {
				label := item.Label
				if title, ok := protocolTitles[label]; ok {
					label = title
				}
				fmt.Fprintf(out, "  %-24s %10s  %3.0f%%\n", label, dataSize(item.Bytes), float64(item.Bytes)*100/float64(max(total, 1)))
			}
		}
		section("Traffic types", stats.Types, "nothing recorded yet")
		section("Protocols used", stats.Protocols, "nothing recorded yet")
		if stats.SiteStats {
			section("Top services", stats.Sites, "nothing recorded yet")
		} else {
			fmt.Fprintln(out, "\nTop services: off (turn on with: sudo ghostlink-server site-stats on)")
		}
		if len(stats.Users) > 0 {
			fmt.Fprintln(out, "\nBy user")
			for _, u := range stats.Users {
				fmt.Fprintf(out, "  %-24s %10s down %10s up\n", u.Name, dataSize(u.Down), dataSize(u.Up))
			}
		}
	})
}

type liveResult struct {
	UpBps   int64      `json:"up_bps"`
	DownBps int64      `json:"down_bps"`
	Active  int64      `json:"active"`
	Online  int        `json:"online_users"`
	Users   []liveUser `json:"users"`
	Health  Health     `json:"health"`
}

func (c *AdminClient) top(out io.Writer, once bool) error {
	for {
		var live liveResult
		if err := c.Do(http.MethodGet, "/live", nil, &live); err != nil {
			return err
		}
		if !once {
			fmt.Fprint(out, "\x1b[H\x1b[2J")
		}
		fmt.Fprintf(out, "Ghostlink server  %s   ↓ %s  ↑ %s   %d/%d online   %d connections\n",
			time.Now().Format("15:04:05"), rate(live.DownBps), rate(live.UpBps), live.Online, len(live.Users), live.Active)
		h := live.Health
		line := []string{}
		if h.CPUPercent != nil {
			line = append(line, fmt.Sprintf("CPU %.0f%%", *h.CPUPercent))
		}
		if h.MemoryTotal != nil {
			line = append(line, fmt.Sprintf("memory %s/%s", dataSize(*h.MemoryUsed), dataSize(*h.MemoryTotal)))
		}
		if h.DiskFree != nil {
			line = append(line, "disk free "+dataSize(*h.DiskFree))
		}
		if h.DetailPaused {
			line = append(line, "DETAIL RECORDING PAUSED (disk nearly full)")
		}
		if len(line) > 0 {
			fmt.Fprintln(out, strings.Join(line, "   "))
		}
		fmt.Fprintln(out)
		users := live.Users
		sort.SliceStable(users, func(i, j int) bool {
			return users[i].UpBps+users[i].DownBps > users[j].UpBps+users[j].DownBps
		})
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USER\tSTATE\tDOWN\tUP\tCONNS\tLAST ACTIVE")
		for _, u := range users {
			state := "offline"
			if u.Online {
				state = "online"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", u.Name, state, rate(u.DownBps), rate(u.UpBps), u.Active, since(u.LastActive))
		}
		w.Flush()
		if once {
			return nil
		}
		fmt.Fprintln(out, "\nCtrl+C to quit")
		time.Sleep(time.Second)
	}
}

func (c *AdminClient) setCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("set", flag.ContinueOnError)
	name := flags.String("name", "", "")
	hostname := flags.String("hostname", "", "")
	reality := flags.String("reality-site", "", "")
	var enable, disable, ports stringList
	flags.Var(&enable, "enable", "")
	flags.Var(&disable, "disable", "")
	flags.Var(&ports, "port", "")
	historyDays := flags.Int("history-days", 0, "")
	siteDays := flags.Int("site-days", 0, "")
	historyMB := flags.Int("history-max-mb", 0, "")
	rotatePSK := flags.Bool("rotate-ipsec-psk", false, "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	patch := map[string]any{}
	if *rotatePSK {
		patch["rotate_ipsec_psk"] = true
	}
	for key, value := range map[string]string{"name": *name, "hostname": *hostname, "vless_handshake": *reality} {
		if value != "" {
			patch[key] = value
		}
	}
	for key, value := range map[string]int{"history_days": *historyDays, "site_days": *siteDays, "history_max_mb": *historyMB} {
		if value != 0 {
			patch[key] = value
		}
	}
	protocols := map[string]map[string]any{}
	entry := func(p string) map[string]any {
		if protocols[p] == nil {
			protocols[p] = map[string]any{}
		}
		return protocols[p]
	}
	for _, p := range enable {
		entry(p)["enabled"] = true
	}
	for _, p := range disable {
		entry(p)["enabled"] = false
	}
	for _, spec := range ports {
		p, n, ok := strings.Cut(spec, "=")
		port, err := strconv.Atoi(n)
		if !ok || err != nil {
			return errors.New("use --port PROTOCOL=PORT, for example --port vless=8443")
		}
		entry(p)["port"] = port
	}
	if len(protocols) > 0 {
		patch["protocols"] = protocols
	}
	if len(patch) == 0 {
		return errors.New("nothing to change; see: sudo ghostlink-server help")
	}
	if err := c.Do(http.MethodPatch, "/server", patch, nil); err != nil {
		return err
	}
	fmt.Fprintln(out, "Saved. Users reconnect automatically.")
	if *rotatePSK {
		fmt.Fprintln(out, "The IPsec group key changed: export and reinstall every IPsec PSK profile (sudo ghostlink-server profile NAME ID --output FILE).")
	}
	if *hostname != "" {
		fmt.Fprintln(out, "New keys use the new address; keys you already shared keep the old one. The management key changed: sudo ghostlink-server show-key")
	}
	return nil
}

func (c *AdminClient) dashboardCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	port := flags.Int("port", 0, "")
	public := flags.Bool("public", false, "")
	private := flags.Bool("private", false, "")
	reset := flags.Bool("reset-token", false, "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *public && *private {
		return errors.New("choose --public or --private, not both")
	}
	patch := map[string]any{}
	if *port != 0 {
		if *port < 1024 || *port > 65535 || *port == 443 {
			return ErrDashboardPort
		}
		patch["dashboard_port"] = *port
	}
	if *public {
		patch["dashboard_public"] = true
	}
	if *private {
		patch["dashboard_public"] = false
	}
	if *reset {
		patch["reset_dashboard_token"] = true
	}
	if len(patch) > 0 {
		if err := c.Do(http.MethodPatch, "/server", patch, nil); err != nil {
			return err
		}
	}
	var info struct {
		Port     uint16 `json:"port"`
		Public   bool   `json:"public"`
		Token    string `json:"token"`
		Hostname string `json:"hostname"`
	}
	if err := c.Do(http.MethodGet, "/dashboard", nil, &info); err != nil {
		return err
	}
	if *reset {
		fmt.Fprintln(out, "New login link created; everyone signed in before is signed out.")
	}
	if info.Public {
		fmt.Fprintf(out, "Dashboard: public HTTPS on port %d.\n\nOpen this link in your browser:\n  https://%s:%d/#t=%s\n\n", info.Port, endpointHost(info.Hostname), info.Port, info.Token)
		fmt.Fprintf(out, "Your browser warns about the certificate because it is self-signed. Before continuing, check that it\nshows this SHA-256 fingerprint:\n  %s\n\n", c.pin)
		fmt.Fprintf(out, "Allow port %d only from your own address in the firewall if you can. Go back to tunnel-only:\n  sudo ghostlink-server dashboard --private\n", info.Port)
	} else {
		fmt.Fprintf(out, "Dashboard: private (reachable only through an SSH tunnel), port %d.\n\n", info.Port)
		fmt.Fprintf(out, "1. On your computer, open a tunnel (keep it running):\n     ssh -N -L 8080:127.0.0.1:%d YOUR-USER@%s\n", info.Port, info.Hostname)
		fmt.Fprintf(out, "2. Open this link in your browser:\n     http://127.0.0.1:8080/#t=%s\n\n", info.Token)
	}
	fmt.Fprintln(out, "Keep the link private: it signs you in as the administrator. Revoke it with --reset-token.")
	return nil
}
