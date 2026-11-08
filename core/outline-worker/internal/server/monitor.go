// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/publicsuffix"

	"ghostlink.local/outline-worker/internal/awg"
)

// Monitor is the router's connection tracker. It counts every routed connection and flow per
// user: bytes in each direction, open connections, traffic type, protocol used and (only when
// site statistics are on) the site or service. One Monitor outlives engine reloads.
type Monitor struct {
	mu      sync.Mutex
	users   map[string]*userCounters
	detail  map[detailKey]*atomic.Int64
	sites   map[string]map[string]bool // user -> site labels counted today (bounded)
	clients map[string]map[string]clientSeen

	siteStats    atomic.Bool
	detailPaused atomic.Bool

	samples []rateSample // server totals, one per second, newest last
	// minutes are per-minute averages for the last hour; minute accumulates the current one.
	minutes     []rateSample
	minute      rateSample
	minuteCount int64
	lastUp      map[string]int64
	lastDown    map[string]int64
	rates       map[string][2]int64
	sampleDay   int64
	historyMu   sync.Mutex
	history     *History
	flushedUp   map[string]int64
	flushedDn   map[string]int64
	flushedDet  map[detailKey]int64
	// siteMark is each site counter's value at the last daily check (see pruneSites).
	siteMark map[detailKey]int64
	// speedLimits are the clients' caps in bytes per second (absent: none), applied to their
	// pacers, also for clients whose counters are created later.
	speedLimits map[string]int64
	// peerRx is each WireGuard/AmneziaWG peer's receive counter at the last poll, by
	// "protocol/public key".
	peerRx map[string]uint64
}

type userCounters struct {
	up, down atomic.Int64 // totals since start
	pending  atomic.Int64 // both directions since the last Drain
	active   atomic.Int64 // open connections
	// lastSeen is when the client last sent something (unix seconds): see isOnline.
	lastSeen atomic.Int64
	// upPace and downPace hold the client to its speed limit, across all its connections.
	upPace, downPace pacer
}

// seen moves lastSeen forward to t (unix seconds); it never moves back.
func (u *userCounters) seen(t int64) {
	for {
		last := u.lastSeen.Load()
		if t <= last || u.lastSeen.CompareAndSwap(last, t) {
			return
		}
	}
}

type detailKey struct{ user, kind, label string }

type clientSeen struct {
	Protocol string
	First    time.Time
	Last     time.Time
}

type rateSample struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

const (
	maxSitesPerUserDay = 500
	rateSamples        = 120
	// minuteSamples keeps an hour of per-minute averages for the live chart's 1 h view.
	minuteSamples = 60
	// onlineSeconds is how recently a client must have been seen to count as online. The
	// WireGuard and AmneziaWG configurations the server issues send a keepalive every 25 s, so
	// a connected client is seen within it even when it is idle.
	onlineSeconds = 60
	// liveDownload is the download within one second (bytes) that shows the client is still
	// there. A bulk transfer to a client that has gone stalls within seconds, because nothing
	// acknowledges it, while the small keepalives that remote services keep sending to its
	// leftover connections stay far below this.
	liveDownload = 16_000
)

// isOnline reports whether a client last seen at lastSeen (unix seconds) is online at now:
// it sent something within the last minute. Open connections alone do not count, because a
// client that leaves without closing them (WireGuard switched off, a phone out of range) can
// leave them open on the server for many minutes.
func isOnline(lastSeen, now int64) bool {
	return lastSeen > 0 && now-lastSeen <= onlineSeconds
}

var _ adapter.ConnectionTracker = (*Monitor)(nil)

func NewMonitor() *Monitor {
	return &Monitor{
		users:      map[string]*userCounters{},
		detail:     map[detailKey]*atomic.Int64{},
		sites:      map[string]map[string]bool{},
		clients:    map[string]map[string]clientSeen{},
		lastUp:     map[string]int64{},
		lastDown:   map[string]int64{},
		rates:      map[string][2]int64{},
		history:    newHistory(),
		flushedUp:  map[string]int64{},
		flushedDn:  map[string]int64{},
		flushedDet: map[detailKey]int64{},
		siteMark:   map[detailKey]int64{},
		peerRx:     map[string]uint64{},
	}
}

func (m *Monitor) user(tag string) *userCounters {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[tag]
	if !ok {
		u = &userCounters{}
		if limit := m.speedLimits[tag]; limit > 0 {
			u.upPace.SetRate(limit)
			u.downPace.SetRate(limit)
		}
		m.users[tag] = u
	}
	return u
}

// SetSpeedLimits sets each client's cap in bytes per second, in both directions (clients not in
// limits are unlimited). It applies at once, also to open connections; nothing reloads.
func (m *Monitor) SetSpeedLimits(limits map[string]int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.speedLimits = limits
	for tag, u := range m.users {
		u.upPace.SetRate(limits[tag])
		u.downPace.SetRate(limits[tag])
	}
}

// inboundProtocol folds the extra Shadowsocks inbounds of imported Outline keys
// (shadowsocks-<port>) into shadowsocks.
func inboundProtocol(tag string) string {
	if strings.HasPrefix(tag, Shadowsocks+"-") {
		return Shadowsocks
	}
	return tag
}

func (m *Monitor) detailCounter(key detailKey) *atomic.Int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key.kind == "site" {
		seen := m.sites[key.user]
		if seen == nil {
			seen = map[string]bool{}
			m.sites[key.user] = seen
		}
		if !seen[key.label] && len(seen) >= maxSitesPerUserDay {
			key.label = otherSites
		}
		seen[key.label] = true
	}
	c, ok := m.detail[key]
	if !ok {
		c = new(atomic.Int64)
		m.detail[key] = c
	}
	return c
}

// trafficType names the sniffed protocol of a connection in plain words.
func trafficType(metadata adapter.InboundContext) string {
	switch metadata.Protocol {
	case "tls":
		return "Web (HTTPS)"
	case "http":
		return "Web (HTTP)"
	case "quic":
		return "QUIC (video, Google)"
	case "dns":
		return "DNS"
	case "bittorrent":
		return "BitTorrent"
	case "ssh":
		return "SSH"
	case "rdp":
		return "Remote desktop"
	case "stun", "dtls":
		return "Calls"
	case "ntp":
		return "Time (NTP)"
	}
	if metadata.Network == N.NetworkUDP {
		return "Other UDP"
	}
	return "Other TCP"
}

// counters returns the read (upload) and write (download) counters for a connection.
func (m *Monitor) counters(metadata adapter.InboundContext) (*userCounters, []*atomic.Int64, []*atomic.Int64) {
	u := m.user(metadata.User)
	// Every routed connection or flow is opened by the client.
	u.seen(time.Now().Unix())
	up := []*atomic.Int64{&u.up, &u.pending}
	down := []*atomic.Int64{&u.down, &u.pending}
	if !m.detailPaused.Load() {
		shared := []*atomic.Int64{
			m.detailCounter(detailKey{metadata.User, "type", trafficType(metadata)}),
			m.detailCounter(detailKey{metadata.User, "protocol", inboundProtocol(metadata.Inbound)}),
		}
		if m.siteStats.Load() {
			if label := siteLabel(metadata); label != "" {
				shared = append(shared, m.detailCounter(detailKey{metadata.User, "site", label}))
			}
		}
		up = append(up, shared...)
		down = append(down, shared...)
		if protocol := inboundProtocol(metadata.Inbound); protocol == Shadowsocks || protocol == VLESS {
			m.sawClient(metadata.User, metadata.Source.Addr, protocol, time.Now())
		}
	}
	return u, up, down
}

func (m *Monitor) sawClient(user string, addr netip.Addr, protocol string, at time.Time) {
	if !addr.IsValid() {
		return
	}
	ip := addr.Unmap().String()
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := m.clients[user]
	if seen == nil {
		seen = map[string]clientSeen{}
		m.clients[user] = seen
	}
	entry, ok := seen[ip]
	if !ok {
		entry = clientSeen{Protocol: protocol, First: at}
	}
	entry.Last, entry.Protocol = at, protocol
	seen[ip] = entry
}

func (m *Monitor) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if metadata.User == "" {
		return conn
	}
	u, up, down := m.counters(metadata)
	u.active.Add(1)
	// Reading from the client is upload, writing to it download. The pacers are count functions,
	// so they also run when the copy loop unwraps the connection (see pacer).
	paced := bufio.NewCounterConn(conn, []N.CountFunc{u.upPace.Wait}, []N.CountFunc{u.downPace.Wait})
	return &trackedConn{CounterConn: bufio.NewInt64CounterConn(paced, up, down), user: u}
}

func (m *Monitor) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return m.routedPacketConnection(conn, metadata, nil)
}

// noLimit is the pacer of sessions that have no client to hold to a limit.
var noLimit pacer

// routedPacketConnection counts a UDP session and polices what the client sends in it: each
// packet to another destination than the routed one against guard (when given), and every
// packet against the client's speed limit.
func (m *Monitor) routedPacketConnection(conn N.PacketConn, metadata adapter.InboundContext, guard *udpGuard) N.PacketConn {
	routed := metadata.Destination.Unwrap()
	if metadata.User == "" {
		if guard == nil {
			return conn
		}
		// Every routed session has a user today (the IPsec DNS listener's are answered as DNS),
		// but one without would still be held to the rules.
		return &policedPacketConn{PacketConn: conn, pace: &noLimit, guard: guard, routed: routed}
	}
	u, up, down := m.counters(metadata)
	u.active.Add(1)
	// What the client sends over UDP is policed (dropped above the rate), not delayed.
	policed := &policedPacketConn{PacketConn: conn, pace: &u.upPace, guard: guard, user: metadata.User, routed: routed}
	paced := bufio.NewCounterPacketConn(policed, nil, []N.CountFunc{u.downPace.Wait})
	return &trackedPacketConn{CounterPacketConn: bufio.NewInt64CounterPacketConn(paced, up, nil, down, nil), user: u}
}

func (m *Monitor) RoutedFlow(_ context.Context, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	if metadata.User == "" {
		return nil
	}
	u, up, down := m.counters(metadata)
	u.active.Add(1)
	return &flowCounter{user: u, up: up, down: down}
}

// trackedConn counts open connections; embedding keeps the counter's upstream interfaces.
type trackedConn struct {
	*bufio.CounterConn
	user *userCounters
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.user.active.Add(-1) })
	return c.CounterConn.Close()
}

type trackedPacketConn struct {
	*bufio.CounterPacketConn
	user *userCounters
	once sync.Once
}

func (c *trackedPacketConn) Close() error {
	c.once.Do(func() { c.user.active.Add(-1) })
	return c.CounterPacketConn.Close()
}

// policedPacketConn drops the UDP packets a client sends to a destination the routing rules
// refuse (see udpGuard), and those a capped client sends above its rate. Waiting would be
// wrong here: the Shadowsocks inbound hands every client's UDP sessions their packets from one
// read loop, through a small blocking queue per session, so one session that waited would hold
// up all the others. Its reads must stay opaque to sing's unwrapping (no UpstreamReader,
// ReaderReplaceable or read waiter), so the copy loops call its ReadPacket.
type policedPacketConn struct {
	N.PacketConn
	pace *pacer
	// guard checks each packet to anywhere but routed, the destination the session was routed
	// for, which the routing rules already allowed.
	guard  *udpGuard
	user   string
	routed M.Socksaddr
}

// UpstreamWriter shows sing the writer behind it, which writes the client's downloads. sing
// sizes the buffers it writes from the header and tag room that writer needs (Shadowsocks
// puts a salt and an address in front of each packet), so hiding it made the writer overflow
// its buffer and crash the server on the first UDP reply. Writes still go through this
// connection (it is not WriterReplaceable), and reads are unaffected.
func (c *policedPacketConn) UpstreamWriter() any { return c.PacketConn }

// Upstream lets sing find what it looks up through wrappers on the connection inside: the
// WireGuard stack's handshake reports (they release the session's first packet and send ICMP
// errors) and its NAT timeout. Reads still stop here: sing follows Upstream for reads only
// through connections that are ReaderReplaceable, and this one is not.
func (c *policedPacketConn) Upstream() any { return c.PacketConn }

func (c *policedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	start := buffer.Start()
	for {
		destination, err := c.PacketConn.ReadPacket(buffer)
		if err != nil {
			return destination, err
		}
		if c.permitted(destination.Unwrap(), buffer.Bytes()) && c.pace.Allow(int64(buffer.Len())) {
			return destination, nil
		}
		buffer.Resize(start, 0)
	}
}

func (c *policedPacketConn) permitted(destination M.Socksaddr, packet []byte) bool {
	return c.guard == nil || destination == c.routed || c.guard.allows(c.user, destination, packet)
}

type flowCounter struct {
	user     *userCounters
	up, down []*atomic.Int64
	once     sync.Once
}

func (f *flowCounter) AttachFlow(tun.FlowHandle) {}
func (f *flowCounter) CountForward(n int) {
	for _, c := range f.up {
		c.Add(int64(n))
	}
}
func (f *flowCounter) CountReverse(n int) {
	for _, c := range f.down {
		c.Add(int64(n))
	}
}
func (f *flowCounter) FlowEstablished() {}
func (f *flowCounter) CloseFlow(tun.FlowCloseReason) {
	f.once.Do(func() { f.user.active.Add(-1) })
}

// Drain returns the bytes counted since the last call per user tag, for data limits.
func (m *Monitor) Drain() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := map[string]uint64{}
	for tag, u := range m.users {
		if n := u.pending.Swap(0); n > 0 {
			result[tag] = uint64(n)
		}
	}
	return result
}

// Undrain gives back what Drain returned when it could not be accounted (the change failed),
// so the next accounting counts it.
func (m *Monitor) Undrain(counted map[string]uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tag, n := range counted {
		if u, ok := m.users[tag]; ok {
			u.pending.Add(int64(n))
		}
	}
}

// Sample records one per-second rate point. Run it once a second.
func (m *Monitor) Sample(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var totalUp, totalDown int64
	for tag, u := range m.users {
		up, down := u.up.Load(), u.down.Load()
		dUp, dDown := up-m.lastUp[tag], down-m.lastDown[tag]
		m.lastUp[tag], m.lastDown[tag] = up, down
		m.rates[tag] = [2]int64{dUp, dDown}
		// What the client sends shows it is there; data written to it only when it is enough
		// to need its acknowledgements (see liveDownload).
		if dUp > 0 || dDown >= liveDownload {
			u.seen(now.Unix())
		}
		totalUp += dUp
		totalDown += dDown
	}
	m.samples = append(m.samples, rateSample{now.Unix(), totalUp, totalDown})
	if len(m.samples) > rateSamples {
		m.samples = m.samples[len(m.samples)-rateSamples:]
	}
	m.addMinute(now, totalUp, totalDown)
	if day := dayStart(now); day != m.sampleDay {
		m.sampleDay = day
		m.sites = map[string]map[string]bool{}
		m.pruneSites()
	}
}

// pruneSites forgets the site counters that counted nothing for a whole day and have nothing
// left to flush, so a server with site statistics on does not keep every site its clients ever
// visited in memory. A connection still open on a forgotten site loses only its site total.
// Called locked, once a day.
func (m *Monitor) pruneSites() {
	for key, c := range m.detail {
		if key.kind != "site" {
			continue
		}
		n := c.Load()
		if mark, marked := m.siteMark[key]; marked && n == mark && n == m.flushedDet[key] {
			delete(m.detail, key)
			delete(m.flushedDet, key)
			delete(m.siteMark, key)
		} else {
			m.siteMark[key] = n
		}
	}
}

// UserLive is one user's live state.
type UserLive struct {
	UpBps   int64 `json:"up_bps"`
	DownBps int64 `json:"down_bps"`
	Active  int64 `json:"active"`
	// LastActive is when the client was last seen sending (see isOnline).
	LastActive int64 `json:"last_active_unix"`
}

func (m *Monitor) Live() (map[string]UserLive, []rateSample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	users := map[string]UserLive{}
	for tag, u := range m.users {
		rate := m.rates[tag]
		users[tag] = UserLive{UpBps: rate[0], DownBps: rate[1], Active: u.active.Load(), LastActive: u.lastSeen.Load()}
	}
	return users, append([]rateSample(nil), m.samples...)
}

// addMinute folds a per-second sample into the current minute; a finished minute is kept as
// its average rate (bytes per second), so the last hour costs 60 points.
func (m *Monitor) addMinute(now time.Time, up, down int64) {
	minute := now.Unix() / 60 * 60
	if m.minute.T != minute {
		if m.minuteCount > 0 {
			m.minutes = append(m.minutes, rateSample{m.minute.T, m.minute.Up / m.minuteCount, m.minute.Down / m.minuteCount})
			if len(m.minutes) > minuteSamples {
				m.minutes = m.minutes[len(m.minutes)-minuteSamples:]
			}
		}
		m.minute, m.minuteCount = rateSample{T: minute}, 0
	}
	m.minute.Up += up
	m.minute.Down += down
	m.minuteCount++
}

// Minutes returns up to an hour of per-minute average rates, oldest first, ending with the
// minute in progress.
func (m *Monitor) Minutes() []rateSample {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]rateSample(nil), m.minutes...)
	if m.minuteCount > 0 {
		out = append(out, rateSample{m.minute.T, m.minute.Up / m.minuteCount, m.minute.Down / m.minuteCount})
	}
	return out
}

// SetSiteStats turns site statistics on or off; turning them off forgets every site counted.
func (m *Monitor) SetSiteStats(on bool) {
	m.siteStats.Store(on)
	if on {
		return
	}
	m.mu.Lock()
	for key := range m.detail {
		if key.kind == "site" {
			delete(m.detail, key)
			delete(m.flushedDet, key)
			delete(m.siteMark, key)
		}
	}
	m.sites = map[string]map[string]bool{}
	m.mu.Unlock()
	m.historyMu.Lock()
	m.history.clearSites()
	m.historyMu.Unlock()
}

// AddExternal records traffic counted outside sing-box (the IPsec component's SAs). It is not
// inspected, so it has no traffic type beyond "IPsec (not inspected)" and no site statistics.
// Each call also counts as the client being seen, so callers report only sessions that are up,
// or that ended after moving data since the last report (see recordIPsec).
func (m *Monitor) AddExternal(tag, protocol string, up, down uint64, remote string, at time.Time) {
	u := m.user(tag)
	u.up.Add(int64(up))
	u.down.Add(int64(down))
	u.pending.Add(int64(up + down))
	u.seen(at.Unix())
	if m.detailPaused.Load() {
		return
	}
	if up+down > 0 {
		m.detailCounter(detailKey{tag, "type", "IPsec (not inspected)"}).Add(int64(up + down))
		m.detailCounter(detailKey{tag, "protocol", protocol}).Add(int64(up + down))
	}
	if addr, err := netip.ParseAddr(remote); err == nil {
		m.sawClient(tag, addr, protocol, at)
	}
}

// PeerReport is one WireGuard/AmneziaWG peer's status from the engine, with its user's tag.
type PeerReport struct {
	User, Protocol, Key string
	Status              awg.PeerStatus
}

// PeersSeen records WireGuard/AmneziaWG peers' real addresses and handshakes. A peer whose
// receive counter grew since the previous poll sent something, so its user counts as seen now:
// the keepalive every 25 s keeps an idle but connected client seen. Counters that went back
// (the engine reloaded) or that are new give no such evidence.
func (m *Monitor) PeersSeen(reports []PeerReport, now time.Time) {
	sent := make([]bool, len(reports))
	m.mu.Lock()
	current := make(map[string]uint64, len(reports))
	for i, r := range reports {
		id := r.Protocol + "/" + r.Key
		current[id] = r.Status.RxBytes
		if before, ok := m.peerRx[id]; ok && r.Status.RxBytes > before {
			sent[i] = true
		}
	}
	m.peerRx = current
	m.mu.Unlock()
	for i, r := range reports {
		handshake := r.Status.LastHandshake
		if !sent[i] && handshake.IsZero() {
			continue
		}
		u := m.user(r.User)
		if sent[i] {
			u.seen(now.Unix())
		}
		if !handshake.IsZero() {
			u.seen(handshake.Unix())
			if r.Status.Endpoint.IsValid() && !m.detailPaused.Load() {
				m.sawClient(r.User, r.Status.Endpoint.Addr(), r.Protocol, handshake)
			}
		}
	}
}

// --- site labels ---

var services = []struct {
	label    string
	suffixes []string
}{
	{"YouTube", []string{"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtube-nocookie.com", "youtubei.googleapis.com"}},
	{"Netflix", []string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"}},
	{"TikTok", []string{"tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com", "byteoversea.com", "ibytedtos.com", "ttwstatic.com"}},
	{"Instagram", []string{"instagram.com", "cdninstagram.com"}},
	{"WhatsApp", []string{"whatsapp.com", "whatsapp.net"}},
	{"Messenger", []string{"messenger.com"}},
	{"Facebook", []string{"facebook.com", "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com"}},
	{"Telegram", []string{"telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org"}},
	{"Viber", []string{"viber.com"}},
	{"Signal", []string{"signal.org", "whispersystems.org"}},
	{"Discord", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"}},
	{"X (Twitter)", []string{"twitter.com", "x.com", "twimg.com", "t.co"}},
	{"Zoom", []string{"zoom.us", "zoom.com"}},
	{"Spotify", []string{"spotify.com", "scdn.co", "spotifycdn.com"}},
	{"Amazon", []string{"amazon.com", "primevideo.com", "amazonvideo.com", "media-amazon.com", "aiv-cdn.net"}},
	{"Steam", []string{"steampowered.com", "steamcontent.com", "steamcommunity.com", "steamstatic.com"}},
	{"Apple", []string{"apple.com", "icloud.com", "mzstatic.com", "apple-dns.net", "cdn-apple.com"}},
	{"Microsoft", []string{"microsoft.com", "live.com", "office.com", "office365.com", "windows.com", "windowsupdate.com", "msn.com", "bing.com", "skype.com", "outlook.com", "sharepoint.com", "onedrive.com"}},
	{"Google", []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com", "ggpht.com", "gvt1.com", "gvt2.com"}},
}

func siteLabel(metadata adapter.InboundContext) string {
	domain := metadata.Domain
	if domain == "" && metadata.Destination.IsFqdn() {
		domain = metadata.Destination.Fqdn
	}
	return labelFor(domain)
}

// otherSites holds what has no site label of its own: past the daily cap, or not a site name.
const otherSites = "Other sites"

func labelFor(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		return ""
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return ""
	}
	// Names come from what the client sends (TLS SNI, HTTP Host), unchecked and up to tens of
	// kilobytes long: only a real DNS name may become a label kept in memory and the history.
	if normalized, err := normalizeDomain(domain); err != nil || normalized != domain {
		return otherSites
	}
	for _, service := range services {
		for _, suffix := range service.suffixes {
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return service.label
			}
		}
	}
	if site, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return site
	}
	return domain
}
