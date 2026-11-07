// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package ipsecagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/strongswan/govici/vici"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// closedChild is a CHILD_SA that ended, kept for a minute in the status.
type closedChild struct {
	sa ipsecproto.SA
	at time.Time
}

// Interface holds the pool gateways, so DNS sent to them is delivered to this host.
const Interface = "glipsec0"

// Agent supervises charon and keeps it, the firewall and the status file in line with the
// server's desired state.
type Agent struct {
	Dir     string // shared with the server: desired.json is read, status.json written
	Run     string // private runtime directory (tmpfs)
	Charon  string
	Swanctl string
	Log     *log.Logger
	FW      *Firewall

	charon     *exec.Cmd
	charonDone chan error
	session    *vici.Session
	applied    int64
	allowed    map[string]bool
	conns      map[string]bool
	plugins    []string
	problem    string // why the last settings were not applied
	listing    string // why sessions could not be listed
	stamp      string // modification time and size of the settings last read
	failedAt   time.Time
	events     chan vici.Event
	closed     map[string]closedChild // by CHILD_SA unique ID
	conf       string
	gateways   []string
	onLoopback bool
	lastJumps  time.Time
	// desired is the configuration last applied; limits are the speed limit rules in force,
	// rendered again whenever the connected sessions change.
	desired ipsecproto.Desired
	sas     []ipsecproto.SA
	limits  string
}

func (a *Agent) swanctlDir() string { return filepath.Join(a.Run, "swanctl") }
func (a *Agent) confPath() string   { return filepath.Join(a.Run, "strongswan.conf") }

func (a *Agent) env() []string {
	return append(os.Environ(), "STRONGSWAN_CONF="+a.confPath(), "SWANCTL_DIR="+a.swanctlDir())
}

func writePrivate(path, data string, mode os.FileMode) error {
	temporary := path + ".pending"
	if err := os.WriteFile(temporary, []byte(data), mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Serve runs until ctx ends or charon exits; it always tries to leave the host clean.
func (a *Agent) Serve(ctx context.Context) error {
	for _, sub := range []string{"x509", "x509ca", "pkcs8", "x509crl"} {
		if err := os.MkdirAll(filepath.Join(a.swanctlDir(), sub), 0o700); err != nil {
			return err
		}
	}
	if err := checkForwarding(); err != nil {
		a.writeStatus(false, err.Error())
		return err
	}
	a.conf = StrongswanConf(false)
	if err := writePrivate(a.confPath(), a.conf, 0o600); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(a.swanctlDir(), "swanctl.conf"), "", 0o600); err != nil {
		return err
	}
	defer a.cleanup()
	if err := a.startCharon(ctx); err != nil {
		a.writeStatus(false, err.Error())
		return err
	}
	if err := a.setupInterface(); err != nil {
		a.writeStatus(false, err.Error())
		return err
	}
	a.Log.Printf("running: charon started, firewall backend iptables-%s", a.FW.Backend)
	// Settings are picked up within a second of the server writing them; sessions are
	// listed and the status written every 5 seconds.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	a.stamp = "unread"
	for ticks := 0; ; ticks++ {
		a.cycle(ctx, ticks%5 == 0)
		select {
		case <-ctx.Done():
			return nil
		case err := <-a.charonDone:
			a.charonDone = nil
			return fmt.Errorf("charon stopped: %v", err)
		case event, ok := <-a.events:
			if !ok {
				a.events = nil
				continue
			}
			a.recordClosed(event)
			continue
		case <-ticker.C:
		}
	}
}

func checkForwarding() error {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(data)) != "1" {
		return errors.New("IPv4 forwarding is off on this host; run: sudo ghostlink-server ipsec enable")
	}
	return nil
}

func (a *Agent) startCharon(ctx context.Context) error {
	cmd := exec.Command(a.Charon)
	cmd.Env = a.env()
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	a.charon, a.charonDone = cmd, make(chan error, 1)
	go func() { a.charonDone <- cmd.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		session, err := vici.NewSession()
		if err == nil {
			a.session = session
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("charon did not open its control socket: %w", err)
		}
		select {
		case err := <-a.charonDone:
			a.charonDone = nil
			return fmt.Errorf("charon exited at start (is IPsec supported by this kernel?): %v", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	// Session-down and rekey events carry final byte counts.
	a.events, a.closed = make(chan vici.Event, 512), map[string]closedChild{}
	if err := a.session.Subscribe("ike-updown", "child-updown", "child-rekey"); err != nil {
		return fmt.Errorf("charon events: %w", err)
	}
	a.session.NotifyEvents(a.events)
	stats, err := a.session.Call(ctx, "stats", nil)
	if err != nil {
		return fmt.Errorf("charon stats: %w", err)
	}
	a.plugins, _ = stats.Get("plugins").([]string)
	var missing []string
	for _, p := range requiredPlugins {
		if !slices.Contains(a.plugins, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("strongSwan is missing plugins: %s", strings.Join(missing, ", "))
	}
	return nil
}

// setupInterface creates the dummy interface for the gateways (or uses loopback when the dummy
// module is unavailable).
func (a *Agent) setupInterface() error {
	ok, err := createInterface()
	if !ok {
		a.onLoopback = true
		a.Log.Printf("no dummy interface (%v); using loopback for the gateways", err)
		return nil
	}
	return err
}

func (a *Agent) setGateways(gateways []string) error {
	for _, gw := range a.gateways {
		if !slices.Contains(gateways, gw) {
			_ = removeGateway(a.onLoopback, gw)
		}
	}
	for _, gw := range gateways {
		if err := addGateway(a.onLoopback, gw); err != nil {
			return fmt.Errorf("gateway %s: %w", gw, err)
		}
	}
	a.gateways = gateways
	return nil
}

func (a *Agent) readDesired() (ipsecproto.Desired, error) {
	var d ipsecproto.Desired
	data, err := os.ReadFile(filepath.Join(a.Dir, ipsecproto.DesiredFile))
	if errors.Is(err, os.ErrNotExist) {
		return d, errors.New("waiting for the Ghostlink server to write its IPsec settings")
	}
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return d, fmt.Errorf("unreadable IPsec settings: %w", err)
	}
	if err := d.Validate(); err != nil {
		return d, fmt.Errorf("refused IPsec settings: %w", err)
	}
	return d, nil
}

// apply loads a new desired state into charon, the interface and the firewall.
func (a *Agent) apply(ctx context.Context, d ipsecproto.Desired) error {
	files, err := Render(d)
	if err != nil {
		return err
	}
	for name, content := range files {
		if err := writePrivate(filepath.Join(a.swanctlDir(), name), content, 0o600); err != nil {
			return err
		}
	}
	if conf := StrongswanConf(d.IKEv1 != nil && d.IKEv1.PSK != ""); conf != a.conf {
		if err := writePrivate(a.confPath(), conf, 0o600); err != nil {
			return err
		}
		if _, err := a.session.Call(ctx, "reload-settings", nil); err != nil {
			return fmt.Errorf("reload settings: %w", err)
		}
		a.conf = conf
	}
	var gateways []string
	for _, p := range pools(d) {
		gateways = append(gateways, p.gateway)
	}
	if err := a.setGateways(gateways); err != nil {
		return err
	}
	if err := a.FW.Apply(ctx, d, a.sas); err != nil {
		return err
	}
	a.desired, a.limits = d, strings.Join(limitRules(d, a.sas), "\n")
	// End sessions that lost access before new credentials load, so none slips through.
	allowed, conns := map[string]bool{}, map[string]bool{}
	for _, id := range d.Allowed {
		allowed[strings.ToLower(id)] = true
	}
	if d.IKEv2 != nil {
		conns[ConnIKEv2Cert], conns[ConnIKEv2EAP] = true, true
	}
	if d.IKEv1 != nil {
		conns[ConnIKEv1Cert] = true
		conns[ConnIKEv1PSK] = d.IKEv1.PSK != ""
	}
	a.allowed, a.conns = allowed, conns
	a.enforce(ctx)
	cmd := exec.CommandContext(ctx, a.Swanctl, "--load-all", "--clear", "--noprompt")
	cmd.Env = a.env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("swanctl: %v: %s", err, lastLines(string(out), 4))
	}
	a.lastJumps = time.Now()
	return nil
}

func lastLines(text string, n int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "; ")
}

func (a *Agent) listSAs(ctx context.Context) ([]ipsecproto.SA, error) {
	var events []*vici.Message
	for m, err := range a.session.CallStreaming(ctx, "list-sas", "list-sa", nil) {
		if err != nil {
			return nil, err
		}
		events = append(events, m)
	}
	return ParseSAs(events), nil
}

// enforce terminates established SAs that are no longer allowed.
func (a *Agent) enforce(ctx context.Context) []ipsecproto.SA {
	sas, err := a.listSAs(ctx)
	if err != nil {
		a.listing = "cannot list connections: " + err.Error()
		return nil
	}
	if a.allowed == nil {
		return sas
	}
	ended := Disallowed(sas, a.allowed, a.conns)
	for _, id := range ended {
		m := vici.NewMessage()
		_ = m.Set("ike-id", id)
		_ = m.Set("timeout", "-1")
		if _, err := a.session.Call(ctx, "terminate", m); err != nil {
			a.Log.Printf("could not end IKE_SA %s: %v", id, err)
		}
	}
	if len(ended) == 0 {
		return sas
	}
	var kept []ipsecproto.SA
	for _, sa := range sas {
		if !slices.Contains(ended, sa.UniqueID) {
			kept = append(kept, sa)
		}
	}
	return kept
}

// settingsStamp changes whenever the server replaces its settings file.
func (a *Agent) settingsStamp() string {
	info, err := os.Stat(filepath.Join(a.Dir, ipsecproto.DesiredFile))
	if err != nil {
		return ""
	}
	return fmt.Sprint(info.ModTime().UnixNano(), "/", info.Size())
}

func (a *Agent) cycle(ctx context.Context, full bool) {
	stamp := a.settingsStamp()
	retry := !a.failedAt.IsZero() && time.Since(a.failedAt) > 30*time.Second
	if stamp != a.stamp || retry {
		a.stamp, a.failedAt, a.problem = stamp, time.Time{}, ""
		d, err := a.readDesired()
		switch {
		case err != nil:
			a.problem = err.Error()
		case d.Generation != a.applied:
			if err := a.apply(ctx, d); err != nil {
				a.problem, a.failedAt = err.Error(), time.Now()
				a.Log.Printf("could not apply settings: %v", err)
			} else {
				a.applied = d.Generation
				a.Log.Printf("applied settings %d: %d identities", d.Generation, len(d.Allowed))
			}
		}
		full = true
	}
	if !full {
		return
	}
	if a.applied != 0 && time.Since(a.lastJumps) > 30*time.Second {
		if err := a.FW.EnsureJumps(ctx); err != nil {
			a.Log.Printf("could not restore firewall jumps: %v", err)
		}
		a.lastJumps = time.Now()
	}
	a.listing = ""
	sas := a.enforce(ctx)
	if a.applied != 0 && a.listing == "" {
		// New or ended sessions of capped clients: the speed limit rules follow them.
		a.sas = sas
		if limits := strings.Join(limitRules(a.desired, sas), "\n"); limits != a.limits {
			if err := a.FW.Apply(ctx, a.desired, sas); err != nil {
				a.Log.Printf("could not apply speed limits: %v", err)
			} else {
				a.limits = limits
			}
		}
	}
	problems := []string{}
	for _, p := range []string{a.problem, a.listing} {
		if p != "" {
			problems = append(problems, p)
		}
	}
	a.writeStatusWith(true, strings.Join(problems, "; "), sas)
}

// recordClosed keeps the final counters of CHILD_SAs that ended, keeping the larger counters
// when one is reported twice (for example by child-updown and then ike-updown).
func (a *Agent) recordClosed(event vici.Event) {
	if event.Message == nil {
		return
	}
	for _, sa := range ClosedChildren(event.Message) {
		c := sa.Children[0]
		if previous, ok := a.closed[c.UniqueID]; ok {
			p := previous.sa.Children[0]
			c.BytesIn, c.BytesOut = max(c.BytesIn, p.BytesIn), max(c.BytesOut, p.BytesOut)
			sa.Children[0] = c
		}
		a.closed[c.UniqueID] = closedChild{sa, time.Now()}
	}
}

func (a *Agent) writeStatus(running bool, problem string) { a.writeStatusWith(running, problem, nil) }

func (a *Agent) writeStatusWith(running bool, problem string, sas []ipsecproto.SA) {
	if sas == nil {
		sas = []ipsecproto.SA{}
	}
	status := ipsecproto.Status{
		Version: ipsecproto.Version, UpdatedUnix: time.Now().Unix(), Running: running,
		Applied: a.applied, Error: problem, Plugins: a.plugins, SAs: sas,
	}
	for id, c := range a.closed {
		if time.Since(c.at) > time.Minute {
			delete(a.closed, id)
			continue
		}
		status.Closed = append(status.Closed, c.sa)
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err == nil {
		err = writePrivate(filepath.Join(a.Dir, ipsecproto.StatusFile), string(data), 0o640)
	}
	if err != nil {
		a.Log.Printf("could not write status: %v", err)
	}
}

// cleanup stops charon (which removes its IPsec policies) and removes the firewall chains and
// the gateway addresses.
func (a *Agent) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if a.session != nil {
		_ = a.session.Close()
	}
	if a.charon != nil && a.charon.Process != nil && a.charonDone != nil {
		_ = a.charon.Process.Signal(syscall.SIGTERM)
		select {
		case <-a.charonDone:
		case <-time.After(10 * time.Second):
			_ = a.charon.Process.Kill()
		}
	}
	a.FW.Remove(ctx)
	if a.onLoopback {
		for _, gw := range a.gateways {
			_ = removeGateway(true, gw)
		}
	} else {
		_ = deleteInterface()
	}
	a.writeStatus(false, "stopped")
	a.Log.Printf("stopped; firewall chains and %s removed", Interface)
}
