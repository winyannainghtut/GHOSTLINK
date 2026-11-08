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
// protocol without wrapping Read or Write, which those loops bypass. UDP sent by the client is
// policed with Allow instead (see policedPacketConn).
//
// The bucket may go into debt: a chunk larger than the burst (splice moves up to 1 MiB) is let
// through and paid for by waiting, and with many connections each waits for the debt of all
// of them, so the average stays at the rate whatever the number of connections.
type pacer struct {
	rate  atomic.Int64 // bytes per second; 0 means unlimited
	epoch atomic.Int64 // bumped by every change of rate, which ends waits under the old one
	// waiting counts connections pausing in Wait; while one does, its debt is paid off by
	// waiting, so UDP may run into debt too (see allow).
	waiting atomic.Int64
	mu      sync.Mutex
	tokens  float64
	last    time.Time
}

const (
	// waitStep is how often a waiting connection checks whether its limit changed.
	waitStep = time.Second
	// maxPause only guards the arithmetic; real debts are far smaller.
	maxPause = time.Hour
)

func burstFor(rate int64) float64 {
	return math.Max(float64(rate)/4, 64<<10)
}

// SetRate changes the rate at once, also for connections already open; 0 removes the limit.
// A new rate starts with a full bucket: debt run up under the old one is forgiven, and
// connections waiting it off go on at once.
func (p *pacer) SetRate(bytesPerSecond int64) {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rate.Load() == bytesPerSecond {
		return
	}
	p.tokens, p.last = burstFor(bytesPerSecond), time.Time{}
	p.rate.Store(bytesPerSecond)
	p.epoch.Add(1)
}

// Wait accounts n bytes and sleeps as long as the rate requires, or until the rate changes.
func (p *pacer) Wait(n int64) {
	if n <= 0 || p.rate.Load() == 0 {
		return
	}
	epoch := p.epoch.Load()
	pause := p.take(n, time.Now())
	if pause > 0 {
		p.waiting.Add(1)
		defer p.waiting.Add(-1)
	}
	for pause > 0 && p.epoch.Load() == epoch {
		step := min(pause, waitStep)
		time.Sleep(step)
		pause -= step
	}
}

// Allow takes n bytes if the bucket holds them and reports whether it did. It never waits.
func (p *pacer) Allow(n int64) bool {
	if n <= 0 || p.rate.Load() == 0 {
		return true
	}
	return p.allow(n, time.Now())
}

// refill adds what the rate earned since the last call, up to the burst. Called locked.
func (p *pacer) refill(rate float64, now time.Time) {
	burst := burstFor(int64(rate))
	if p.last.IsZero() {
		p.tokens = burst
	} else if elapsed := now.Sub(p.last).Seconds(); elapsed > 0 {
		p.tokens = math.Min(burst, p.tokens+elapsed*rate)
	}
	p.last = now
}

// take accounts n bytes at now and returns how long the caller should pause.
func (p *pacer) take(n int64, now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	rate := float64(p.rate.Load())
	if rate == 0 {
		return 0
	}
	p.refill(rate, now)
	p.tokens -= float64(n)
	if p.tokens >= 0 {
		return 0
	}
	return time.Duration(math.Min(-p.tokens/rate, maxPause.Seconds()) * float64(time.Second))
}

// allow takes n bytes when the bucket holds them. While a TCP connection of the same client
// waits off a debt (a saturating upload keeps the bucket near or below zero), a UDP packet may
// deepen the debt by up to a burst: the TCP connection then waits that much longer, so the two
// share the rate instead of TCP taking it all and nearly every UDP packet (a call, QUIC) being
// dropped. With no TCP waiting, UDP needs the tokens, as before.
func (p *pacer) allow(n int64, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	rate := float64(p.rate.Load())
	if rate == 0 {
		return true
	}
	p.refill(rate, now)
	if p.tokens < float64(n) && (p.waiting.Load() == 0 || p.tokens-float64(n) < -burstFor(int64(rate))) {
		return false
	}
	p.tokens -= float64(n)
	return true
}
