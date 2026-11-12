// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A 30 GB disk is the case this was made for: recording pauses at 5% free (1.5 GB), the warning
// comes at twice that (3 GB), and on a larger disk the 500 MB floor does not matter.
func TestDiskLevels(t *testing.T) {
	const GB = 1_000_000_000
	for _, c := range []struct {
		name        string
		free, total uint64
		want        string
	}{
		{"30 GB, plenty", 20 * GB, 30 * GB, diskOK},
		{"30 GB, just above the warning", 3100 * 1_000_000, 30 * GB, diskOK},
		{"30 GB, below the warning", 2900 * 1_000_000, 30 * GB, diskLow},
		{"30 GB, just above the pause", 1600 * 1_000_000, 30 * GB, diskLow},
		{"30 GB, below the pause", 1400 * 1_000_000, 30 * GB, diskFull},
		{"30 GB, almost nothing", 20 * 1_000_000, 30 * GB, diskFull},
		{"small disk, 500 MB floor", 400 * 1_000_000, 4 * GB, diskFull},
		{"small disk, warning at 1 GB", 900 * 1_000_000, 8 * GB, diskLow},
		{"1 TB disk keeps its 5%", 40 * GB, 1000 * GB, diskFull},
	} {
		if got := diskLevelOf(c.free, c.total); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The pause and the "full" level are the same line: recording pauses exactly when the health
// report says "full".
func TestDiskLevelMatchesThePause(t *testing.T) {
	const total = 30_000_000_000
	for free := uint64(0); free <= total; free += total / 400 {
		level := diskLevelOf(free, total)
		m := NewMonitor()
		diskCheck = func(string) (uint64, uint64, bool) { return free, total, true }
		paused, _ := m.CheckDisk("x")
		diskCheck = diskSpace
		if paused != (level == diskFull) {
			t.Fatalf("free %d: level %s, paused %v", free, level, paused)
		}
	}
}

func TestDirBytesCountsFilesBelow(t *testing.T) {
	dir := t.TempDir()
	for name, size := range map[string]int{"state.json": 1000, "history.json": 250, filepath.Join("ipsec", "desired.json"): 40} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := dirBytes(dir); got != 1290 {
		t.Fatalf("dirBytes = %d, want 1290", got)
	}
	if got := dirBytes(filepath.Join(dir, "missing")); got != 0 {
		t.Fatalf("a missing directory counts %d", got)
	}
}

// What the dashboard, the app and `top` read: the level, the history cap and the size of the state
// directory, in /live, following the free space.
func TestHealthReportsTheDiskBudget(t *testing.T) {
	server := newTestServer(t, nil)
	free := uint64(20_000_000_000)
	diskCheck = func(string) (uint64, uint64, bool) { return free, 30_000_000_000, true }
	t.Cleanup(func() { diskCheck = diskSpace })

	live := func() Health {
		t.Helper()
		var out struct {
			Health Health `json:"health"`
		}
		server.must(t, 200, "GET", "/live", nil, &out)
		return out.Health
	}
	health := live()
	if health.DiskLevel != diskOK || health.DetailPaused {
		t.Fatalf("plenty of space: level %q, paused %v", health.DiskLevel, health.DetailPaused)
	}
	if health.HistoryMaxBytes != 20_000_000 {
		t.Fatalf("history cap %d, want the 20 MB default", health.HistoryMaxBytes)
	}
	if health.StateBytes <= 0 {
		t.Fatalf("state directory size %d", health.StateBytes)
	}

	// A larger history cap set by the owner is what is reported.
	server.must(t, 200, "PATCH", "/server", map[string]any{"history_max_mb": 50}, nil)
	if got := live().HistoryMaxBytes; got != 50_000_000 {
		t.Fatalf("history cap %d after setting 50 MB", got)
	}

	free = 2_500_000_000
	if got := live().DiskLevel; got != diskLow {
		t.Fatalf("2.5 GB free of 30 GB: level %q", got)
	}
	if live().DetailPaused {
		t.Fatal("recording paused at the warning level")
	}
	free = 1_000_000_000
	server.service.Record(time.Now())
	if health := live(); health.DiskLevel != diskFull || !health.DetailPaused {
		t.Fatalf("1 GB free of 30 GB: level %q, paused %v", health.DiskLevel, health.DetailPaused)
	}
}

// The count of the state directory follows what is saved: it includes the history file once saved.
func TestStateBytesFollowsTheHistory(t *testing.T) {
	server := newTestServer(t, nil)
	before := server.service.Health().StateBytes
	server.service.monitor.AddExternal("u1", IKEv2, 1000, 2000, "192.0.2.5", time.Now())
	server.service.Record(time.Now())
	server.service.SaveHistory(time.Now())
	after := server.service.Health()
	if after.HistoryBytes == 0 || after.StateBytes < before+int64(after.HistoryBytes)/2 {
		t.Fatalf("state %d -> %d with a history of %d bytes", before, after.StateBytes, after.HistoryBytes)
	}
}

// `ghostlink-server settings` says what the server keeps and how much room is left, and warns
// when the disk gets low; --json carries the same numbers.
func TestSettingsShowTheStorage(t *testing.T) {
	server := newTestServer(t, func(s *State) { s.API.Port = freeTCPPort(t) })
	free := uint64(20_000_000_000)
	diskCheck = func(string) (uint64, uint64, bool) { return free, 30_000_000_000, true }
	t.Cleanup(func() { diskCheck = diskSpace })
	run := adminCommands(t, server)

	out, err := run("settings")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Data kept by this server:", "kept under 20.0 MB", "Disk: 20.0 GB free of 30.0 GB."} {
		if !strings.Contains(out, want) {
			t.Fatalf("settings lack %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "getting low") || strings.Contains(out, "nearly full") {
		t.Fatalf("a warning with plenty of space:\n%s", out)
	}

	free = 2_500_000_000
	if out, _ = run("settings"); !strings.Contains(out, "Disk space is getting low") || !strings.Contains(out, "ghostlink-server disk") {
		t.Fatalf("no warning at 2.5 GB free of 30 GB:\n%s", out)
	}
	free = 1_000_000_000
	server.service.Record(time.Now())
	if out, _ = run("settings"); !strings.Contains(out, "recording is paused") {
		t.Fatalf("no pause notice at 1 GB free of 30 GB:\n%s", out)
	}

	out, err = run("--json", "settings")
	if err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Name    string `json:"name"`
		Storage *struct {
			DiskLevel       string `json:"disk_level"`
			HistoryMaxBytes int    `json:"history_max_bytes"`
			StateBytes      int64  `json:"state_bytes"`
		} `json:"storage"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil || shown.Name == "" || shown.Storage == nil {
		t.Fatalf("--json settings: %v\n%s", err, out)
	}
	if shown.Storage.DiskLevel != diskFull || shown.Storage.HistoryMaxBytes != 20_000_000 || shown.Storage.StateBytes <= 0 {
		t.Fatalf("storage in --json: %+v", shown.Storage)
	}
}
