// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package mesh

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"ghostlink.local/outline-worker/internal/meshproto"
)

// Timing of the live view and of path decisions.
const (
	// OnlineFor is how long a node counts as online after its last sync.
	OnlineFor = 30 * time.Second
	// handshakeFresh: WireGuard renews sessions every 2 minutes while packets flow, and every
	// peer has a keepalive, so a working link always has a handshake younger than this.
	handshakeFresh = 3 * time.Minute
	// directGrace is how long a new direct pair has to complete a handshake.
	directGrace = 90 * time.Second
	// relayFor is how long a pair stays relayed before direct is tried again.
	relayFor = 15 * time.Minute
)

// Report is the latest sync from one node.
type report struct {
	at      time.Time
	remote  netip.Addr
	applied uint64
	err     string
	peers   map[string]meshproto.PeerStatus // by public key
	pings   map[string]int64                // RTT in microseconds by mesh address
	rates   map[string][2]float64           // rx, tx bytes/s by public key
}

type pairState struct {
	relayed bool
	since   time.Time
	until   time.Time
}

// Live is the coordinator's in-memory view: what agents last reported and which pairs are
// relayed. It is rebuilt within seconds after a restart.
type Live struct {
	mu      sync.Mutex
	reports map[string]*report // by node ID
	pairs   map[[2]string]*pairState
	changed chan struct{}
}

// NewLive returns an empty live view.
func NewLive() *Live {
	return &Live{reports: map[string]*report{}, pairs: map[[2]string]*pairState{}, changed: make(chan struct{})}
}

// Changed returns a channel closed at the next change that can affect configurations.
func (l *Live) Changed() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.changed
}

// Notify wakes every waiting sync (call after any change to the stored network).
func (l *Live) Notify() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.notifyLocked()
}

func (l *Live) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

// Record stores a node's sync report, and wakes waiting syncs when something peers'
// configurations depend on changed (the address the node is seen from, or it coming online).
func (l *Live) Record(nodeID string, remote netip.Addr, r *meshproto.SyncRequest, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	previous := l.reports[nodeID]
	next := &report{at: now, remote: remote, applied: r.Applied, err: r.Error,
		peers: map[string]meshproto.PeerStatus{}, pings: map[string]int64{}, rates: map[string][2]float64{}}
	for _, p := range r.Peers {
		next.peers[p.PublicKey] = p
		if previous != nil {
			if old, ok := previous.peers[p.PublicKey]; ok && now.After(previous.at) {
				seconds := now.Sub(previous.at).Seconds()
				var rx, tx float64
				if p.RxBytes >= old.RxBytes {
					rx = float64(p.RxBytes-old.RxBytes) / seconds
				}
				if p.TxBytes >= old.TxBytes {
					tx = float64(p.TxBytes-old.TxBytes) / seconds
				}
				next.rates[p.PublicKey] = [2]float64{rx, tx}
			}
		}
	}
	for _, p := range r.Pings {
		next.pings[p.Address] = p.RTTMicros
	}
	l.reports[nodeID] = next
	if previous == nil || previous.remote != remote || now.Sub(previous.at) > OnlineFor {
		l.notifyLocked()
	}
}

// Forget drops a removed node's live data.
func (l *Live) Forget(nodeID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.reports, nodeID)
	for key := range l.pairs {
		if key[0] == nodeID || key[1] == nodeID {
			delete(l.pairs, key)
		}
	}
}

func pairKey(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

func (l *Live) online(id string, now time.Time) bool {
	r := l.reports[id]
	return r != nil && now.Sub(r.at) <= OnlineFor
}

// handshake is the newest handshake either node reports with the other.
func (l *Live) handshake(a, b *Node) time.Time {
	var newest time.Time
	for _, pair := range [][2]*Node{{a, b}, {b, a}} {
		if r := l.reports[pair[0].ID]; r != nil {
			if p, ok := r.peers[pair[1].PublicKey]; ok && p.LastHandshake > 0 {
				if t := time.Unix(p.LastHandshake, 0); t.After(newest) {
					newest = t
				}
			}
		}
	}
	return newest
}

func isPublic(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// endpoint picks the address viewer should send to for target, or "" when target can only be
// reached by it connecting out (it is behind NAT).
func (l *Live) endpoint(viewer, target *Node) string {
	var viewerRemote, targetRemote netip.Addr
	if r := l.reports[viewer.ID]; r != nil {
		viewerRemote = r.remote
	}
	if r := l.reports[target.ID]; r != nil {
		targetRemote = r.remote
	}
	var private, public []string
	for _, e := range target.Endpoints {
		ap, err := netip.ParseAddrPort(e)
		if err != nil {
			continue
		}
		if isPublic(ap.Addr()) {
			public = append(public, e)
		} else {
			private = append(private, e)
		}
	}
	// Behind the same public address (same NAT, VPC or host), private addresses work.
	if viewerRemote.IsValid() && viewerRemote == targetRemote && len(private) > 0 {
		return private[0]
	}
	if len(public) > 0 {
		return public[0]
	}
	if isPublic(targetRemote) {
		return netip.AddrPortFrom(targetRemote, target.ListenPort).String()
	}
	// Private networks without a public side (for example nodes all on one LAN).
	if !isPublic(viewerRemote) && len(private) > 0 {
		return private[0]
	}
	return ""
}

// relay is the relay node in use: the first relay that is active and online, else the first
// active relay.
func (l *Live) relay(n *Network, now time.Time) *Node {
	var fallback *Node
	for _, node := range n.Nodes {
		if node.Relay && node.Status == meshproto.StatusActive {
			if l.online(node.ID, now) {
				return node
			}
			if fallback == nil {
				fallback = node
			}
		}
	}
	return fallback
}

// Tick re-decides which pairs are relayed. It returns true if any pair changed.
func (l *Live) Tick(n *Network, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	relay := l.relay(n, now)
	active := activeNodes(n)
	changed := false
	seen := map[[2]string]bool{}
	for i, a := range active {
		for _, b := range active[i+1:] {
			key := pairKey(a.ID, b.ID)
			seen[key] = true
			st := l.pairs[key]
			if st == nil {
				st = &pairState{since: now}
				l.pairs[key] = st
			}
			wasRelayed := st.relayed
			switch {
			case relay == nil || a == relay || b == relay:
				*st = pairState{since: st.since}
				if wasRelayed {
					st.since = now
				}
			case st.relayed:
				if now.After(st.until) {
					*st = pairState{since: now}
				}
			case l.endpoint(a, b) == "" && l.endpoint(b, a) == "":
				// Neither can reach the other directly.
				*st = pairState{relayed: true, since: now, until: now.Add(relayFor)}
			case !l.online(a.ID, now) || !l.online(b.ID, now):
				// Can't judge a pair while a side is offline.
			case now.Sub(st.since) > directGrace && now.Sub(l.handshake(a, b)) > handshakeFresh:
				*st = pairState{relayed: true, since: now, until: now.Add(relayFor)}
			}
			if st.relayed != wasRelayed {
				changed = true
			}
		}
	}
	for key := range l.pairs {
		if !seen[key] {
			delete(l.pairs, key)
		}
	}
	if changed {
		l.notifyLocked()
	}
	return changed
}

func (l *Live) relayed(a, b *Node) bool {
	st := l.pairs[pairKey(a.ID, b.ID)]
	return st != nil && st.relayed
}

func activeNodes(n *Network) []*Node {
	var out []*Node
	for _, node := range n.Nodes {
		if node.Status == meshproto.StatusActive {
			out = append(out, node)
		}
	}
	return out
}

// NodeView is a node as the map shows it.
type NodeView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Address          string   `json:"address"`
	Tags             []string `json:"tags"`
	Status           string   `json:"status"`
	Relay            bool     `json:"relay"`
	RelayInUse       bool     `json:"relay_in_use"`
	Online           bool     `json:"online"`
	LastSeenUnix     int64    `json:"last_seen_unix"`
	Endpoint         string   `json:"endpoint"`
	SeenFrom         string   `json:"seen_from"`
	ListenPort       uint16   `json:"listen_port"`
	AdvertisedRoutes []string `json:"advertised_routes"`
	ApprovedRoutes   []string `json:"approved_routes"`
	Masquerade       bool     `json:"masquerade"`
	Version          string   `json:"version"`
	OS               string   `json:"os"`
	Error            string   `json:"error,omitempty"`
	InSync           bool     `json:"in_sync"`
	RxBps            float64  `json:"rx_bps"`
	TxBps            float64  `json:"tx_bps"`
	CreatedUnix      int64    `json:"created_unix"`
}

// LinkView is the connection between two active nodes.
type LinkView struct {
	A string `json:"a"`
	B string `json:"b"`
	// Path is direct, relay or down.
	Path            string  `json:"path"`
	Via             string  `json:"via,omitempty"`
	RTTMillis       float64 `json:"rtt_ms"`
	HandshakeAgeSec int64   `json:"handshake_age_s"`
	RxBps           float64 `json:"rx_bps"`
	TxBps           float64 `json:"tx_bps"`
}

// Topology is everything the map draws.
type Topology struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	CIDR        string     `json:"cidr"`
	Enabled     bool       `json:"enabled"`
	Nodes       []NodeView `json:"nodes"`
	Links       []LinkView `json:"links"`
	RuleCount   int        `json:"rule_count"`
	UpdatedUnix int64      `json:"updated_unix"`
}

// Topology describes the mesh for the app and dashboard.
func (l *Live) Topology(n *Network, now time.Time) Topology {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := Topology{ID: n.ID, Name: n.Name, CIDR: n.CIDR, Enabled: n.Enabled, Nodes: []NodeView{}, Links: []LinkView{},
		RuleCount: len(n.Rules), UpdatedUnix: now.Unix()}
	relay := l.relay(n, now)
	for _, node := range n.Nodes {
		v := NodeView{
			ID: node.ID, Name: node.Name, Address: node.Address, Tags: node.Tags, Status: node.Status, Relay: node.Relay,
			RelayInUse: node == relay, ListenPort: node.ListenPort, AdvertisedRoutes: node.AdvertisedRoutes,
			ApprovedRoutes: node.ApprovedRoutes, Masquerade: node.Masquerade, Version: node.Version, OS: node.OS,
			CreatedUnix: node.CreatedUnix,
		}
		if r := l.reports[node.ID]; r != nil {
			v.LastSeenUnix, v.Error = r.at.Unix(), r.err
			v.Online = now.Sub(r.at) <= OnlineFor
			if r.remote.IsValid() {
				v.SeenFrom = r.remote.String()
			}
			for _, rate := range r.rates {
				v.RxBps += rate[0]
				v.TxBps += rate[1]
			}
			v.InSync = node.Status != meshproto.StatusActive
			if c, err := l.config(n, node, now); err == nil {
				v.InSync = r.applied == c.Generation
			}
		}
		for _, other := range n.Nodes {
			if other != node {
				if e := l.endpoint(other, node); e != "" {
					v.Endpoint = e
					break
				}
			}
		}
		t.Nodes = append(t.Nodes, v)
	}
	active := activeNodes(n)
	for i, a := range active {
		for _, b := range active[i+1:] {
			link := LinkView{A: a.ID, B: b.ID, Path: "direct"}
			if l.relayed(a, b) && relay != nil {
				link.Path, link.Via = "relay", relay.ID
			}
			var rtts []float64
			for _, pair := range [][2]*Node{{a, b}, {b, a}} {
				r := l.reports[pair[0].ID]
				if r == nil || now.Sub(r.at) > OnlineFor {
					continue
				}
				if us := r.pings[pair[1].Address]; us > 0 {
					rtts = append(rtts, float64(us)/1000)
				}
				if link.Path == "direct" {
					rate := r.rates[pair[1].PublicKey]
					link.RxBps += rate[0]
					link.TxBps += rate[1]
				}
			}
			if len(rtts) > 0 {
				sort.Float64s(rtts)
				link.RTTMillis = rtts[0]
			}
			up := false
			if link.Path == "direct" {
				if hs := l.handshake(a, b); !hs.IsZero() {
					link.HandshakeAgeSec = int64(now.Sub(hs).Seconds())
					up = now.Sub(hs) <= handshakeFresh
				}
			} else {
				up = !l.handshake(a, relay).IsZero() && now.Sub(l.handshake(a, relay)) <= handshakeFresh &&
					!l.handshake(b, relay).IsZero() && now.Sub(l.handshake(b, relay)) <= handshakeFresh
			}
			// A ping answered recently proves the link too (for example right after start-up).
			if len(rtts) > 0 {
				up = true
			}
			if !up || !l.online(a.ID, now) || !l.online(b.ID, now) {
				link.Path = "down"
			}
			t.Links = append(t.Links, link)
		}
	}
	return t
}
