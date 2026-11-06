// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build linux

package server

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func diskSpace(dir string) (free, total uint64, ok bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, 0, false
	}
	return stat.Bavail * uint64(stat.Bsize), stat.Blocks * uint64(stat.Bsize), true
}

// cpuTimes returns busy and total jiffies from /proc/stat.
func cpuTimes() (busy, total uint64, ok bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, field := range fields[1:] {
		n, _ := strconv.ParseUint(field, 10, 64)
		total += n
		if i != 3 && i != 4 { // idle and iowait
			busy += n
		}
	}
	return busy, total, true
}

func memory() (used, total uint64, ok bool) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			n, _ := strconv.ParseUint(fields[0], 10, 64)
			values[name] = n * 1024
		}
	}
	total = values["MemTotal"]
	available, has := values["MemAvailable"]
	if total == 0 || !has {
		return 0, 0, false
	}
	return total - available, total, true
}

func loadAverage() (float64, bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, false
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	return load, err == nil
}

// networkBytes sums received and sent bytes over the host's non-loopback interfaces.
func networkBytes() (rx, tx uint64, ok bool) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, found := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !found || name == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx, true
}
