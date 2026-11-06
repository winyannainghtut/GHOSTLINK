// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"errors"
	"sort"
	"strings"
	"time"
)

type labelBytes struct {
	Label string `json:"label"`
	Bytes uint64 `json:"bytes"`
}

type userTotal struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// StatsResult answers GET /stats.
type StatsResult struct {
	Range     string       `json:"range"`
	Unit      string       `json:"unit"`
	Series    []Bucket     `json:"series"`
	Types     []labelBytes `json:"types"`
	Protocols []labelBytes `json:"protocols"`
	Sites     []labelBytes `json:"sites"`
	SiteStats bool         `json:"site_stats"`
	Users     []userTotal  `json:"users,omitempty"`
	Retention struct {
		HistoryDays  int `json:"history_days"`
		SiteDays     int `json:"site_days"`
		HistoryMaxMB int `json:"history_max_mb"`
	} `json:"retention"`
}

var statRanges = map[string]struct {
	span time.Duration
	unit string
}{
	"24h": {24 * time.Hour, "hour"}, "7d": {7 * 24 * time.Hour, "hour"},
	"30d": {30 * 24 * time.Hour, "day"}, "90d": {90 * 24 * time.Hour, "day"},
}

func sortedLabels(totals map[string]uint64, limit int) []labelBytes {
	out := []labelBytes{}
	for label, n := range totals {
		out = append(out, labelBytes{label, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Label < out[j].Label
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Stats summarizes recorded traffic for one user (tag) or everyone (tag "") over a range.
func (m *Monitor) Stats(state *State, rangeName, tag string, now time.Time) (StatsResult, error) {
	spec, ok := statRanges[rangeName]
	if !ok {
		return StatsResult{}, InputError{errors.New("range must be 24h, 7d, 30d or 90d")}
	}
	result := StatsResult{Range: rangeName, Unit: spec.unit, SiteStats: state.Monitor.SiteStats}
	result.Retention.HistoryDays = state.Monitor.historyDays()
	result.Retention.SiteDays = state.Monitor.siteDays()
	result.Retention.HistoryMaxMB = state.Monitor.historyMaxBytes() >> 20
	from := now.Add(-spec.span)
	include := func(user string) bool { return tag == "" || user == tag }
	series := map[int64]*Bucket{}
	types, protocols, sites := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	perUser := map[string]*userTotal{}
	m.readHistory(func(h *History) {
		if spec.unit == "hour" {
			for user, hours := range h.Hourly {
				if !include(user) {
					continue
				}
				for _, b := range hours {
					if b.T < hourStart(from) {
						continue
					}
					entry := series[b.T]
					if entry == nil {
						entry = &Bucket{T: b.T}
						series[b.T] = entry
					}
					entry.Up += b.Up
					entry.Down += b.Down
				}
			}
		}
		for user, days := range h.Daily {
			if !include(user) {
				continue
			}
			for _, d := range days {
				if d.T < dayStart(from) {
					continue
				}
				if spec.unit == "day" {
					entry := series[d.T]
					if entry == nil {
						entry = &Bucket{T: d.T}
						series[d.T] = entry
					}
					entry.Up += d.Up
					entry.Down += d.Down
				}
				for label, n := range d.Types {
					types[label] += n
				}
				for label, n := range d.Protocols {
					protocols[label] += n
				}
				if state.Monitor.SiteStats {
					for label, n := range d.Sites {
						sites[label] += n
					}
				}
				total := perUser[user]
				if total == nil {
					total = &userTotal{}
					perUser[user] = total
				}
				total.Up += d.Up
				total.Down += d.Down
			}
		}
	})
	for _, b := range series {
		result.Series = append(result.Series, *b)
	}
	sort.Slice(result.Series, func(i, j int) bool { return result.Series[i].T < result.Series[j].T })
	if result.Series == nil {
		result.Series = []Bucket{}
	}
	result.Types = sortedLabels(types, 0)
	result.Protocols = sortedLabels(protocols, 0)
	result.Sites = sortedLabels(sites, 25)
	if tag == "" {
		for _, u := range state.Users {
			total := perUser[u.Tag()]
			if total == nil {
				total = &userTotal{}
			}
			result.Users = append(result.Users, userTotal{ID: u.ID, Name: u.Name, Up: total.Up, Down: total.Down})
		}
		sort.Slice(result.Users, func(i, j int) bool {
			return result.Users[i].Up+result.Users[i].Down > result.Users[j].Up+result.Users[j].Down
		})
	}
	return result, nil
}

type clientView struct {
	User     string `json:"user"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	First    int64  `json:"first_unix"`
	Last     int64  `json:"last_unix"`
}

// Clients lists the addresses users connected from, most recent first.
func (m *Monitor) Clients(state *State, tag string) []clientView {
	names := map[string]*User{}
	for _, u := range state.Users {
		names[u.Tag()] = u
	}
	out := []clientView{}
	m.readHistory(func(h *History) {
		for user, records := range h.Clients {
			u := names[user]
			if u == nil || (tag != "" && user != tag) {
				continue
			}
			for _, r := range records {
				out = append(out, clientView{u.ID, u.Name, r.IP, r.Protocol, r.First, r.Last})
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	return out
}

func tagOf(id string) string {
	if id == "" {
		return ""
	}
	return "u" + strings.TrimSpace(id)
}
