// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The bucket starts full, refills at the rate up to the burst, and lets a chunk overdraw it,
// to be paid back by waiting, all of it: a cut-off would let many connections exceed the cap.
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
	if pause := p.take(10_000_000, start.Add(2*time.Second)); pause != 10*time.Second {
		t.Fatalf("10 MB over an empty bucket should wait 10 s, got %v", pause)
	}
	// Debt adds up across chunks (other connections): the next one waits for all of it.
	if pause := p.take(1_000_000, start.Add(2*time.Second)); pause != 11*time.Second {
		t.Fatalf("the next chunk should wait for the whole debt, got %v", pause)
	}
	// A new rate forgives the debt and starts with a full bucket.
	p.SetRate(2_000_000)
	if pause := p.take(500_000, start.Add(3*time.Second)); pause != 0 {
		t.Fatalf("a new rate should start with a full bucket, got %v", pause)
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

// UDP is policed: a packet passes if the bucket holds it, and is dropped otherwise, at once.
func TestPacerAllow(t *testing.T) {
	var p pacer
	p.SetRate(1_000_000)
	start := time.Unix(1_800_000_000, 0)
	if !p.allow(200_000, start) || p.allow(100_000, start) {
		t.Fatal("of a 250 KB bucket, 200 KB should pass and then 100 KB should not")
	}
	if !p.allow(100_000, start.Add(100*time.Millisecond)) {
		t.Fatal("0.1 s at 1 MB/s refills 100 KB")
	}
	p.SetRate(0)
	if !p.Allow(10_000_000) {
		t.Fatal("unlimited allows everything")
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

// A client's TCP upload that saturates its cap does not starve its UDP (a call, QUIC): while
// TCP waits off its debt, UDP still passes, and the two together stay near the cap.
func TestPacerSharesTheCapBetweenTCPAndUDP(t *testing.T) {
	var p pacer
	const rate = 1_000_000 // 1 MB/s
	p.SetRate(rate)
	stop := make(chan struct{})
	var tcp atomic.Int64
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.Wait(16 << 10)
			tcp.Add(16 << 10)
		}
	}()
	time.Sleep(400 * time.Millisecond) // the upload empties the bucket
	sent, passed := 0, 0
	tcpBefore, start := tcp.Load(), time.Now()
	for time.Since(start) < 1500*time.Millisecond {
		sent++
		if p.Allow(1200) {
			passed++
		}
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start).Seconds()
	close(stop)
	if passed < sent*8/10 {
		t.Fatalf("%d of %d UDP packets passed next to a saturating TCP upload", passed, sent)
	}
	total := float64(tcp.Load()-tcpBefore+int64(passed*1200)) / elapsed
	if total > rate*1.3 {
		t.Fatalf("TCP and UDP together moved %.0f B/s at a cap of %d B/s", total, rate)
	}
}

// A connection paying off a long wait goes on as soon as its limit changes.
func TestPacerWaitEndsWhenTheLimitChanges(t *testing.T) {
	var p pacer
	p.SetRate(100_000)
	done := make(chan time.Duration)
	go func() {
		start := time.Now()
		p.Wait(1_000_000) // about 9.4 s at 100 KB/s
		done <- time.Since(start)
	}()
	time.Sleep(200 * time.Millisecond)
	p.SetRate(0)
	select {
	case took := <-done:
		if took > 2*time.Second {
			t.Fatalf("the wait went on for %v after the limit was removed", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not end when the limit was removed")
	}
}
