// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// pacer holds one client's traffic in one direction to a rate, across all of the client's
// connections. sing's copy loops call a connection's count functions synchronously after each
// chunk they move (also on the splice path), so a count function that sleeps throttles every
// protocol without wrapping Read or Write, which those loops bypass.
//
// The bucket may go into debt: a chunk larger than the burst (splice moves up to 1 MiB) is let
// through and paid for by waiting, so the average stays at the rate.
type pacer struct {
	rate   atomic.Int64 // bytes per second; 0 means unlimited
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// maxPause bounds one wait, so a tiny cap and a huge chunk never park a copy loop for minutes;
// the remaining debt is paid by the next chunks.
const maxPause = 5 * time.Second

func burstFor(rate int64) float64 {
	return math.Max(float64(rate)/4, 64<<10)
}

// SetRate changes the rate at once, also for connections already open; 0 removes the limit.
func (p *pacer) SetRate(bytesPerSecond int64) {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	p.mu.Lock()
	if p.rate.Load() == 0 && bytesPerSecond > 0 {
		// Coming from unlimited: start with a full bucket, not with what was moved meanwhile.
		p.tokens, p.last = burstFor(bytesPerSecond), time.Time{}
	}
	p.rate.Store(bytesPerSecond)
	p.mu.Unlock()
}

// Wait accounts n bytes and sleeps as long as the rate requires.
func (p *pacer) Wait(n int64) {
	if n <= 0 || p.rate.Load() == 0 {
		return
	}
	if pause := p.take(n, time.Now()); pause > 0 {
		time.Sleep(pause)
	}
}

// take accounts n bytes at now and returns how long the caller should pause.
func (p *pacer) take(n int64, now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	rate := float64(p.rate.Load())
	if rate == 0 {
		return 0
	}
	burst := burstFor(int64(rate))
	if p.last.IsZero() {
		p.tokens = burst
	} else if elapsed := now.Sub(p.last).Seconds(); elapsed > 0 {
		p.tokens = math.Min(burst, p.tokens+elapsed*rate)
	}
	p.last = now
	p.tokens -= float64(n)
	if p.tokens >= 0 {
		return 0
	}
	return min(time.Duration(-p.tokens/rate*float64(time.Second)), maxPause)
}
