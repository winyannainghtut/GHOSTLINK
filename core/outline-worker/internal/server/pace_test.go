// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"sync"
	"testing"
	"time"
)

// The bucket starts full, refills at the rate up to the burst, and lets a chunk overdraw it,
// to be paid back by waiting.
func TestPacerArithmetic(t *testing.T) {
	var p pacer
	p.SetRate(1_000_000) // 1 MB/s: burst 250 KB
	start := time.Unix(1_800_000_000, 0)
	if pause := p.take(250_000, start); pause != 0 {
		t.Fatalf("the first burst should pass at once, paused %v", pause)
	}
	if pause := p.take(500_000, start); pause != 500*time.Millisecond {
		t.Fatalf("500 KB over an empty bucket should wait 0.5 s, got %v", pause)
	}
	// After 2 s the debt (500 KB) is paid and 1.5 s of refill is capped at the burst.
	if pause := p.take(250_000, start.Add(2*time.Second)); pause != 0 {
		t.Fatalf("a refilled bucket should not wait, got %v", pause)
	}
	if pause := p.take(10_000_000, start.Add(2*time.Second)); pause != maxPause {
		t.Fatalf("one wait is bounded by maxPause, got %v", pause)
	}
	p.SetRate(0)
	if pause := p.take(10_000_000, start.Add(3*time.Second)); pause != 0 {
		t.Fatalf("unlimited should never wait, got %v", pause)
	}
	// Small caps still get a 64 KB burst.
	if got := burstFor(10_000); got != 64<<10 {
		t.Fatalf("burst for 10 KB/s: %v", got)
	}
}

// Several connections of one client share its cap.
func TestPacerHoldsTheRateAcrossConnections(t *testing.T) {
	var p pacer
	const rate = 4_000_000 // 4 MB/s, burst 1 MB
	p.SetRate(rate)
	start := time.Now()
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				p.Wait(32 << 10) // 2 MiB per connection
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	// 6 MiB at 4 MB/s minus the 1 MB burst: about 1.32 s.
	want := (6*float64(1<<20) - burstFor(rate)) / rate
	if elapsed < want*0.85 || elapsed > want*1.3 {
		t.Fatalf("3 connections moved 6 MiB in %.2f s; the cap allows %.2f s", elapsed, want)
	}
	// Removing the limit takes effect for whoever is waiting next.
	p.SetRate(0)
	quick := time.Now()
	for range 1000 {
		p.Wait(1 << 20)
	}
	if time.Since(quick) > 50*time.Millisecond {
		t.Fatal("an unlimited pacer should not slow anything down")
	}
}
