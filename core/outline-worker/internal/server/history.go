// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sort"
	"time"
)

const HistoryFile = "history.json"

// History is the recorded traffic of every user, rotated automatically (see SaveHistory).
type History struct {
	Version int                       `json:"version"`
	Hourly  map[string][]Bucket       `json:"hourly"`
	Daily   map[string][]DayBucket    `json:"daily"`
	Clients map[string][]ClientRecord `json:"clients"`
}

type Bucket struct {
	T    int64  `json:"t"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type DayBucket struct {
	T         int64             `json:"t"`
	Up        uint64            `json:"up"`
	Down      uint64            `json:"down"`
	Types     map[string]uint64 `json:"types,omitempty"`
	Protocols map[string]uint64 `json:"protocols,omitempty"`
	Sites     map[string]uint64 `json:"sites,omitempty"`
}

type ClientRecord struct {
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	First    int64  `json:"first_unix"`
	Last     int64  `json:"last_unix"`
}

func newHistory() *History {
	return &History{Version: 1, Hourly: map[string][]Bucket{}, Daily: map[string][]DayBucket{}, Clients: map[string][]ClientRecord{}}
}

func hourStart(t time.Time) int64 { return t.UTC().Truncate(time.Hour).Unix() }
func dayStart(t time.Time) int64  { return t.UTC().Truncate(24 * time.Hour).Unix() }

func (h *History) day(user string, t int64) *DayBucket {
	days := h.Daily[user]
	if n := len(days); n > 0 && days[n-1].T == t {
		return &days[n-1]
	}
	h.Daily[user] = append(days, DayBucket{T: t})
	return &h.Daily[user][len(h.Daily[user])-1]
}

func (h *History) addTraffic(user string, at time.Time, up, down uint64) {
	if up+down == 0 {
		return
	}
	hour := hourStart(at)
	hours := h.Hourly[user]
	if n := len(hours); n > 0 && hours[n-1].T == hour {
		hours[n-1].Up += up
		hours[n-1].Down += down
	} else {
		h.Hourly[user] = append(hours, Bucket{T: hour, Up: up, Down: down})
	}
	day := h.day(user, dayStart(at))
	day.Up += up
	day.Down += down
}

func (h *History) addDetail(user string, at time.Time, kind, label string, n uint64) {
	if n == 0 || label == "" {
		return
	}
	day := h.day(user, dayStart(at))
	var target *map[string]uint64
	switch kind {
	case "type":
		target = &day.Types
	case "protocol":
		target = &day.Protocols
	case "site":
		target = &day.Sites
	default:
		return
	}
	if *target == nil {
		*target = map[string]uint64{}
	}
	(*target)[label] += n
}

func (h *History) addClient(user, ip, protocol string, first, last int64) {
	records := h.Clients[user]
	found := false
	for i := range records {
		if records[i].IP == ip {
			if last > records[i].Last {
				records[i].Last, records[i].Protocol = last, protocol
			}
			if first < records[i].First {
				records[i].First = first
			}
			found = true
		}
	}
	if !found {
		records = append(records, ClientRecord{IP: ip, Protocol: protocol, First: first, Last: last})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Last > records[j].Last })
	if len(records) > clientsPerUser {
		records = records[:clientsPerUser]
	}
	h.Clients[user] = records
}

func (h *History) clearSites() {
	for user, days := range h.Daily {
		for i := range days {
			days[i].Sites = nil
		}
		h.Daily[user] = days
	}
}

// forget removes a deleted user's history.
func (h *History) forget(user string) {
	delete(h.Hourly, user)
	delete(h.Daily, user)
	delete(h.Clients, user)
}

// prune drops everything older than its retention.
func (h *History) prune(now time.Time, settings MonitorSettings) {
	hourCut := now.Add(-hourlyDays * 24 * time.Hour).Unix()
	dayCut := now.Add(-time.Duration(settings.historyDays()) * 24 * time.Hour).Unix()
	siteCut := now.Add(-time.Duration(settings.siteDays()) * 24 * time.Hour).Unix()
	clientCut := now.Add(-clientDays * 24 * time.Hour).Unix()
	for user, hours := range h.Hourly {
		kept := hours[:0]
		for _, b := range hours {
			if b.T >= hourCut {
				kept = append(kept, b)
			}
		}
		if len(kept) == 0 {
			delete(h.Hourly, user)
		} else {
			h.Hourly[user] = kept
		}
	}
	for user, days := range h.Daily {
		kept := days[:0]
		for _, d := range days {
			if d.T < dayCut {
				continue
			}
			if d.T < siteCut {
				d.Sites = nil
			}
			kept = append(kept, d)
		}
		if len(kept) == 0 {
			delete(h.Daily, user)
		} else {
			h.Daily[user] = kept
		}
	}
	for user, records := range h.Clients {
		kept := records[:0]
		for _, r := range records {
			if r.Last >= clientCut {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(h.Clients, user)
		} else {
			h.Clients[user] = kept
		}
	}
}

// oldestDay finds the oldest day bucket that still has the detail being trimmed.
func (h *History) oldestDay(has func(*DayBucket) bool) *DayBucket {
	var oldest *DayBucket
	for user := range h.Daily {
		days := h.Daily[user]
		for i := range days {
			if has(&days[i]) && (oldest == nil || days[i].T < oldest.T) {
				oldest = &days[i]
			}
		}
	}
	return oldest
}

// trimOnce removes the least valuable data: oldest sites first, then the oldest breakdowns,
// then the oldest hourly buckets, then the oldest daily totals. It reports false when empty.
func (h *History) trimOnce() bool {
	if d := h.oldestDay(func(d *DayBucket) bool { return len(d.Sites) > 0 }); d != nil {
		d.Sites = nil
		return true
	}
	if d := h.oldestDay(func(d *DayBucket) bool { return len(d.Types)+len(d.Protocols) > 0 }); d != nil {
		d.Types, d.Protocols = nil, nil
		return true
	}
	var oldestUser string
	var oldestT int64
	for user, hours := range h.Hourly {
		if len(hours) > 0 && (oldestUser == "" || hours[0].T < oldestT) {
			oldestUser, oldestT = user, hours[0].T
		}
	}
	if oldestUser != "" {
		h.Hourly[oldestUser] = h.Hourly[oldestUser][1:]
		if len(h.Hourly[oldestUser]) == 0 {
			delete(h.Hourly, oldestUser)
		}
		return true
	}
	oldestUser = ""
	for user, days := range h.Daily {
		if len(days) > 0 && (oldestUser == "" || days[0].T < oldestT) {
			oldestUser, oldestT = user, days[0].T
		}
	}
	if oldestUser != "" {
		h.Daily[oldestUser] = h.Daily[oldestUser][1:]
		if len(h.Daily[oldestUser]) == 0 {
			delete(h.Daily, oldestUser)
		}
		return true
	}
	return false
}

// encode prunes by age and then trims until the file fits in maxBytes.
func (h *History) encode(now time.Time, settings MonitorSettings, maxBytes int) ([]byte, error) {
	h.prune(now, settings)
	for {
		data, err := json.Marshal(h)
		if err != nil {
			return nil, err
		}
		if len(data) <= maxBytes || !h.trimOnce() {
			return data, nil
		}
		// Trim in larger steps when far over the cap.
		for over := (len(data) - maxBytes) / 4096; over > 0 && h.trimOnce(); over-- {
		}
	}
}

// --- Monitor persistence ---

// Flush moves the traffic counted since the last flush into the history.
func (m *Monitor) Flush(now time.Time) {
	type delta struct{ up, down uint64 }
	traffic := map[string]delta{}
	details := map[detailKey]uint64{}
	m.mu.Lock()
	for tag, u := range m.users {
		up, down := u.up.Load(), u.down.Load()
		traffic[tag] = delta{uint64(up - m.flushedUp[tag]), uint64(down - m.flushedDn[tag])}
		m.flushedUp[tag], m.flushedDn[tag] = up, down
	}
	for key, c := range m.detail {
		n := c.Load()
		details[key] = uint64(n - m.flushedDet[key])
		m.flushedDet[key] = n
	}
	clients := m.clients
	m.clients = map[string]map[string]clientSeen{}
	m.mu.Unlock()

	m.historyMu.Lock()
	defer m.historyMu.Unlock()
	for tag, d := range traffic {
		m.history.addTraffic(tag, now, d.up, d.down)
	}
	for key, n := range details {
		if key.kind == "site" && !m.siteStats.Load() {
			continue
		}
		m.history.addDetail(key.user, now, key.kind, key.label, n)
	}
	for tag, seen := range clients {
		for ip, entry := range seen {
			m.history.addClient(tag, ip, entry.Protocol, entry.First.Unix(), entry.Last.Unix())
		}
	}
}

// LoadHistory reads a saved history; a missing file starts empty.
func (m *Monitor) LoadHistory(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	history := newHistory()
	if err := json.Unmarshal(data, history); err != nil {
		// Recorded statistics are not worth refusing to start for; begin again.
		return nil
	}
	if history.Hourly == nil {
		history.Hourly = map[string][]Bucket{}
	}
	if history.Daily == nil {
		history.Daily = map[string][]DayBucket{}
	}
	if history.Clients == nil {
		history.Clients = map[string][]ClientRecord{}
	}
	m.historyMu.Lock()
	m.history = history
	m.historyMu.Unlock()
	return nil
}

// SaveHistory rotates and writes the history, returning its size in bytes.
func (m *Monitor) SaveHistory(path string, now time.Time, settings MonitorSettings) (int, error) {
	m.historyMu.Lock()
	data, err := m.history.encode(now, settings, settings.historyMaxBytes())
	m.historyMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(data), writeFile(path, data)
}

// Forget removes a deleted user's recorded traffic.
func (m *Monitor) Forget(tag string) {
	m.historyMu.Lock()
	m.history.forget(tag)
	m.historyMu.Unlock()
}

// readHistory runs fn with the history locked.
func (m *Monitor) readHistory(fn func(*History)) {
	m.historyMu.Lock()
	defer m.historyMu.Unlock()
	fn(m.history)
}

// --- low-disk guard ---

const (
	minFreeBytes   = 500 << 20
	minFreePercent = 5
)

// diskCheck reads free and total space; tests replace it.
var diskCheck = diskSpace

// CheckDisk pauses detailed recording while the state filesystem is nearly full. It reports the
// new paused state and whether it changed.
func (m *Monitor) CheckDisk(dir string) (bool, bool) {
	free, total, ok := diskCheck(dir)
	if !ok || total == 0 {
		return m.detailPaused.Load(), false
	}
	low := free < minFreeBytes || free*100/total < minFreePercent
	return low, m.detailPaused.Swap(low) != low
}
