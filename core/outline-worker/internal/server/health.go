// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"sync"
	"time"
)

// Health is a best-effort snapshot of the host. Fields are omitted when unavailable.
type Health struct {
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	Load1         *float64 `json:"load_1m,omitempty"`
	MemoryUsed    *uint64  `json:"memory_used_bytes,omitempty"`
	MemoryTotal   *uint64  `json:"memory_total_bytes,omitempty"`
	DiskFree      *uint64  `json:"disk_free_bytes,omitempty"`
	DiskTotal     *uint64  `json:"disk_total_bytes,omitempty"`
	NetworkRxBps  *uint64  `json:"network_rx_bps,omitempty"`
	NetworkTxBps  *uint64  `json:"network_tx_bps,omitempty"`
	UptimeSeconds int64    `json:"uptime_seconds"`
	EngineReloads int64    `json:"engine_reloads"`
	DetailPaused  bool     `json:"detail_paused"`
	HistoryBytes  int      `json:"history_bytes"`
}

// healthSampler keeps the previous CPU and network readings to turn counters into rates.
type healthSampler struct {
	mu                sync.Mutex
	started           time.Time
	cpuBusy, cpuTotal uint64
	cpuPercent        *float64
	netRx, netTx      uint64
	netAt             time.Time
	rxBps, txBps      *uint64
}

func newHealthSampler() *healthSampler { return &healthSampler{started: time.Now()} }

// Sample refreshes the CPU and network rates; call it every few seconds.
func (h *healthSampler) Sample(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if busy, total, ok := cpuTimes(); ok {
		if h.cpuTotal != 0 && total > h.cpuTotal {
			percent := float64(busy-h.cpuBusy) * 100 / float64(total-h.cpuTotal)
			h.cpuPercent = &percent
		}
		h.cpuBusy, h.cpuTotal = busy, total
	}
	if rx, tx, ok := networkBytes(); ok {
		if !h.netAt.IsZero() && rx >= h.netRx && tx >= h.netTx {
			seconds := now.Sub(h.netAt).Seconds()
			if seconds > 0 {
				r, t := uint64(float64(rx-h.netRx)/seconds), uint64(float64(tx-h.netTx)/seconds)
				h.rxBps, h.txBps = &r, &t
			}
		}
		h.netRx, h.netTx, h.netAt = rx, tx, now
	}
}

func (h *healthSampler) Snapshot(dir string) Health {
	h.mu.Lock()
	health := Health{CPUPercent: h.cpuPercent, NetworkRxBps: h.rxBps, NetworkTxBps: h.txBps, UptimeSeconds: int64(time.Since(h.started).Seconds())}
	h.mu.Unlock()
	if load, ok := loadAverage(); ok {
		health.Load1 = &load
	}
	if used, total, ok := memory(); ok {
		health.MemoryUsed, health.MemoryTotal = &used, &total
	}
	if free, total, ok := diskSpace(dir); ok {
		health.DiskFree, health.DiskTotal = &free, &total
	}
	return health
}
