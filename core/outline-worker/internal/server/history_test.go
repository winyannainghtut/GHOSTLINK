// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"net/http"
	"testing"
	"time"
)

// A deleted client's last counters and addresses are not written back into the history.
func TestDeletedClientsLeaveNoHistory(t *testing.T) {
	server := newTestServer(t, nil)
	user := server.user(t, map[string]any{"name": "Gone"})
	tag := "u" + user.ID
	server.service.monitor.AddExternal(tag, IKEv2, 100, 200, "198.51.100.30", time.Now())
	server.must(t, http.StatusNoContent, "DELETE", "/users/"+user.ID, nil, nil)
	server.service.Record(time.Now())
	server.service.monitor.readHistory(func(h *History) {
		if len(h.Hourly[tag])+len(h.Daily[tag])+len(h.Clients[tag]) != 0 {
			t.Fatalf("history of a deleted client: %v %v %v", h.Hourly[tag], h.Daily[tag], h.Clients[tag])
		}
	})
	if users, _ := server.service.monitor.Live(); users[tag] != (UserLive{}) {
		t.Fatalf("a deleted client still has live counters: %+v", users[tag])
	}
}

// history_days below the default site retention needs no site setting of its own, and sizes
// are in MB of 1,000,000 bytes like everywhere else.
func TestShortHistoryNeedsNoSiteSetting(t *testing.T) {
	server := newTestServer(t, nil)
	var info serverInfo
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"history_days": 14}, &info)
	if info.HistoryDays != 14 || info.SiteDays != 14 {
		t.Fatalf("history %d, sites %d", info.HistoryDays, info.SiteDays)
	}
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"history_days": 60, "site_days": 30}, &info)
	if status := server.call(t, "PATCH", "/server", map[string]any{"history_days": 14}, nil); status != http.StatusBadRequest {
		t.Fatalf("a site retention set longer than the history: status %d", status)
	}
	if got := (MonitorSettings{}).historyMaxBytes(); got != 20_000_000 || info.HistoryMaxMB != 20 {
		t.Fatalf("the default history cap is %d bytes (%d MB), want 20 MB", got, info.HistoryMaxMB)
	}
}
