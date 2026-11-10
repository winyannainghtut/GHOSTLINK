// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

// IKE-02 (v0.8.6): the IPsec component reports a client's byte counters every 5 seconds, and the
// server samples rates every second. A steady transfer used to show four seconds of nothing and
// one of five times its rate, because a report's whole growth landed in one sample. These tests
// run the real report path (recordIPsec, then Sample, as Run does) on a virtual clock: the agent's
// reports are files with their own time stamps, the server reads them once a second.

// rateStart is a whole minute, so a test of under a minute stays inside one per-minute average.
const rateStart = 1_800_000_000

type rateRig struct {
	t      *testing.T
	server *testServer
	key    keyView
	tag    string
	start  time.Time
	// noMilli writes reports as an agent from before 0.8.6 did: to the second only.
	noMilli bool
}

func newRateRig(t *testing.T) *rateRig {
	t.Helper()
	server := newTestServer(t, nil)
	fakeAgent(t, server, nil)
	server.must(t, http.StatusOK, "PATCH", "/server", map[string]any{"protocols": map[string]any{"ikev2": map[string]bool{"enabled": true}}}, nil)
	user := server.user(t, map[string]any{"name": "Phone"})
	key := server.appleKey(t, user, map[string]string{"protocol": "ikev2"})
	return &rateRig{t: t, server: server, key: key, tag: tagOf(user.ID), start: time.Unix(rateStart, 0)}
}

func (r *rateRig) at(ms int64) time.Time { return r.start.Add(time.Duration(ms) * time.Millisecond) }

// write puts the agent's report, made at ms after the start, in place.
func (r *rateRig) write(ms int64, sas, closed []ipsecproto.SA) {
	r.t.Helper()
	when := r.at(ms)
	status := ipsecproto.Status{Version: 1, UpdatedUnix: when.Unix(), UpdatedMilli: when.UnixMilli(), Running: true,
		SAs: sas, Closed: closed, Plugins: []string{"vici"}}
	if r.noMilli {
		status.UpdatedMilli = 0 // an agent from before 0.8.6
	}
	data, err := json.Marshal(status)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.server.store.Dir(), IPsecDir, ipsecproto.StatusFile), data, 0o640); err != nil {
		r.t.Fatal(err)
	}
}

// sa is a session of the client's, on its own device, with one child.
func (r *rateRig) sa(unique, child string, in, out uint64) ipsecproto.SA {
	return ipsecproto.SA{Name: "gl-ikev2-eap", UniqueID: unique, Version: 2, Identity: strings.ToUpper(r.key.Identity), Remote: "198.51.100." + unique,
		Children: []ipsecproto.Child{{UniqueID: child, BytesIn: in, BytesOut: out}}}
}

// tick is one second of Run: read the component's report, then sample. It returns the client's
// live rate, after checking that the server's headline numbers add up to the clients'.
func (r *rateRig) tick(second int) (up, down int64) {
	r.t.Helper()
	now := r.at(int64(second) * 1000)
	r.server.service.recordIPsec(now)
	r.server.service.monitor.Sample(now)
	users, series := r.server.service.monitor.Live()
	var sumUp, sumDown int64
	for _, u := range users {
		sumUp += u.UpBps
		sumDown += u.DownBps
	}
	if n := len(series); n == 0 || series[n-1].Up != sumUp || series[n-1].Down != sumDown {
		r.t.Fatalf("second %d: the server's rate %+v is not the sum of its clients' (%d up, %d down)", second, series[len(series)-1], sumUp, sumDown)
	}
	return users[r.tag].UpBps, users[r.tag].DownBps
}

type reading struct {
	second   int
	up, down int64
}

// drive ticks the server once a second from 0 to seconds. Before the tick at second s, the latest
// report the agent had written by then (reportMs: their times, in milliseconds after the start,
// oldest first) is put in place, built by build from its time.
func (r *rateRig) drive(seconds int, reportMs []int64, build func(ms int64) (sas, closed []ipsecproto.SA)) []reading {
	r.t.Helper()
	var readings []reading
	next := 0
	for second := 0; second <= seconds; second++ {
		latest := -1
		for next < len(reportMs) && reportMs[next] <= int64(second)*1000 {
			latest = next
			next++
		}
		if latest >= 0 {
			sas, closed := build(reportMs[latest])
			r.write(reportMs[latest], sas, closed)
		}
		up, down := r.tick(second)
		readings = append(readings, reading{second, up, down})
	}
	return readings
}

// every returns report times from first to last, period apart.
func every(first, last, period int64) []int64 {
	var times []int64
	for ms := first; ms <= last; ms += period {
		times = append(times, ms)
	}
	return times
}

// counterAt is what a counter reads at ms after the start for a transfer of perSecond bytes a second
// that began at begin and ended at end (milliseconds).
func counterAt(perSecond uint64, ms, begin, end int64) uint64 {
	ms = min(ms, end)
	if ms <= begin {
		return 0
	}
	return perSecond * uint64(ms-begin) / 1000
}

func (r *rateRig) steady(up, down uint64) func(ms int64) ([]ipsecproto.SA, []ipsecproto.SA) {
	return func(ms int64) ([]ipsecproto.SA, []ipsecproto.SA) {
		return []ipsecproto.SA{r.sa("7", "1", counterAt(up, ms, 0, 1<<40), counterAt(down, ms, 0, 1<<40))}, nil
	}
}

// expect fails unless every reading in [from, to] is within one byte a second of want.
func expect(t *testing.T, readings []reading, from, to int, wantUp, wantDown int64) {
	t.Helper()
	for _, rd := range readings {
		if rd.second < from || rd.second > to {
			continue
		}
		if abs(rd.up-wantUp) > 1 || abs(rd.down-wantDown) > 1 {
			t.Errorf("second %d: %d B/s up and %d B/s down, want %d and %d (all: %v)", rd.second, rd.up, rd.down, wantUp, wantDown, readings)
			return
		}
	}
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// A steady transfer of 100 KB/s up and 1 MB/s down, reported every 5 seconds, shows 100 KB/s and
// 1 MB/s every second once the first window is in: no seconds of nothing, no bursts of five
// times. The counted bytes and the per-minute average stay exact. (On 0.8.5 the readings were
// 0, 0, 0, 0, then 500 KB/s and 5 MB/s.)
func TestIPsecLiveRateOfASteadyTransferIsSteady(t *testing.T) {
	r := newRateRig(t)
	readings := r.drive(59, every(0, 55000, 5000), r.steady(100_000, 1_000_000))
	expect(t, readings, 0, 4, 0, 0) // the first report only sets the baseline
	expect(t, readings, 5, 59, 100_000, 1_000_000)
	// Exact, whatever is shown: the totals are what the counters grew by, and the per-minute
	// average is made from them, not from the rate shown.
	u := r.server.service.monitor.users[r.tag]
	if got := u.up.Load(); got != 5_500_000 {
		t.Errorf("counted %d bytes up, want 5500000", got)
	}
	if got := u.down.Load(); got != 55_000_000 {
		t.Errorf("counted %d bytes down, want 55000000", got)
	}
	r.tick(60) // the minute is over
	if minutes := r.server.service.monitor.Minutes(); len(minutes) == 0 || minutes[0].Down != 55_000_000/60 || minutes[0].Up != 5_500_000/60 {
		t.Errorf("per-minute averages %+v, want %d down and %d up", minutes, 55_000_000/60, 5_500_000/60)
	}
}

// Upload is the server's bytes in, download its bytes out, shown separately and together.
func TestIPsecLiveRateKeepsTheDirections(t *testing.T) {
	for _, c := range []struct{ up, down uint64 }{{800_000, 0}, {0, 900_000}, {300_000, 700_000}} {
		r := newRateRig(t)
		readings := r.drive(30, every(0, 30000, 5000), r.steady(c.up, c.down))
		expect(t, readings, 5, 30, int64(c.up), int64(c.down))
	}
}

// The agent and the server run on their own clocks: reports that fall between the server's ticks,
// a late one, and an irregular gap give the rate of the time between the reports, from their
// own time stamps.
func TestIPsecLiveRateUsesTheTimeBetweenReports(t *testing.T) {
	r := newRateRig(t)
	// Windows of 6, 3, 6, 5, 5 and 7 seconds, none on a whole second.
	readings := r.drive(40, []int64{400, 6400, 9400, 15400, 20400, 25400, 32400}, r.steady(100_000, 1_000_000))
	expect(t, readings, 0, 6, 0, 0)
	expect(t, readings, 7, 40, 100_000, 1_000_000)
}

// The windows are measured to the millisecond. Reports whose times fall at different fractions of
// a second (the agent's cycle is never exactly 5 s) would, cut to whole seconds, give windows of 5
// and 6 s for real windows of 5.5 and 5.4 s, and rates 10% off in both directions.
func TestIPsecLiveRateUsesMillisecondStamps(t *testing.T) {
	r := newRateRig(t)
	readings := r.drive(30, []int64{400, 5900, 11300, 16900, 22100, 27800}, r.steady(100_000, 1_000_000))
	expect(t, readings, 0, 5, 0, 0)
	expect(t, readings, 6, 30, 100_000, 1_000_000)
}

// An agent from before 0.8.6 stamps its reports to the second only: the windows are then those
// of whole seconds, which is right for reports that fall on whole seconds.
func TestIPsecLiveRateOfAnOlderAgentUsesWholeSeconds(t *testing.T) {
	r := newRateRig(t)
	r.noMilli = true
	readings := r.drive(30, every(0, 30000, 5000), r.steady(100_000, 1_000_000))
	expect(t, readings, 5, 30, 100_000, 1_000_000)
}

// A report that is read again, as most are (the server reads once a second and the agent writes
// every 5), adds nothing and does not show a quiet second.
func TestIPsecLiveRateIgnoresAReportReadAgain(t *testing.T) {
	r := newRateRig(t)
	r.write(0, []ipsecproto.SA{r.sa("7", "1", 0, 0)}, nil)
	r.tick(0)
	r.write(5000, []ipsecproto.SA{r.sa("7", "1", 500_000, 5_000_000)}, nil)
	for second := 5; second < 10; second++ {
		if up, down := r.tick(second); up != 100_000 || down != 1_000_000 {
			t.Fatalf("second %d: %d up, %d down, want 100000 and 1000000", second, up, down)
		}
	}
	if got := r.server.service.monitor.users[r.tag].down.Load(); got != 5_000_000 {
		t.Fatalf("a report read five times counted %d bytes, want 5000000", got)
	}
}

// When the transfer stops the next report shows no growth and the rate falls to zero; it does not
// stay on the screen, and it is never negative.
func TestIPsecLiveRateFallsToZeroWhenTheTransferStops(t *testing.T) {
	r := newRateRig(t)
	stops := int64(30000)
	readings := r.drive(60, every(0, 60000, 5000), func(ms int64) ([]ipsecproto.SA, []ipsecproto.SA) {
		return []ipsecproto.SA{r.sa("7", "1", counterAt(100_000, ms, 0, stops), counterAt(1_000_000, ms, 0, stops))}, nil
	})
	expect(t, readings, 5, 34, 100_000, 1_000_000)
	expect(t, readings, 35, 60, 0, 0)
}

// If the component stops reporting, the last rate is shown for the time the next report was due
// and then drops to zero, instead of staying forever.
func TestIPsecLiveRateDoesNotOutliveItsReports(t *testing.T) {
	r := newRateRig(t)
	readings := r.drive(70, every(0, 30000, 5000), r.steady(100_000, 1_000_000))
	expect(t, readings, 5, 39, 100_000, 1_000_000) // 10 s after the last report, at 30 s
	expect(t, readings, 40, 70, 0, 0)
}

// A client on two devices shows the sum of their rates, also through a rekey of one of them
// (its child is replaced, the old one reported as closed with its final counters).
func TestIPsecLiveRateOfSeveralDevicesAndARekey(t *testing.T) {
	r := newRateRig(t)
	rekey := int64(17500)
	readings := r.drive(59, every(0, 55000, 5000), func(ms int64) ([]ipsecproto.SA, []ipsecproto.SA) {
		phoneChild, phoneBegin := "A1", int64(0)
		var closed []ipsecproto.SA
		if ms >= 20000 { // reported once the rekey happened
			phoneChild, phoneBegin = "A2", rekey
			closed = []ipsecproto.SA{r.sa("7", "A1", counterAt(100_000, rekey, 0, 1<<40), counterAt(1_000_000, rekey, 0, 1<<40))}
		}
		return []ipsecproto.SA{
			r.sa("7", phoneChild, counterAt(100_000, ms, phoneBegin, 1<<40), counterAt(1_000_000, ms, phoneBegin, 1<<40)),
			r.sa("8", "B1", 0, counterAt(200_000, ms, 0, 1<<40)),
		}, closed
	})
	expect(t, readings, 5, 59, 100_000, 1_200_000)
	if got := r.server.service.monitor.users[r.tag].down.Load(); got != 55_000_000+11_000_000 {
		t.Errorf("counted %d bytes down, want %d", got, 55_000_000+11_000_000)
	}
}

// Traffic counted as it flows (WireGuard, Shadowsocks, VLESS) is shown in the second it flows,
// on top of the IPsec rate: a burst is still a burst and the IPsec part is not changed by it.
func TestIPsecLiveRateAddsToTrafficCountedAsItFlows(t *testing.T) {
	r := newRateRig(t)
	flow := r.server.service.monitor.user(r.tag)
	var readings []reading
	next := int64(0)
	for second := 0; second <= 40; second++ {
		if ms := int64(second) * 1000; ms >= next {
			r.write(ms, []ipsecproto.SA{r.sa("7", "1", counterAt(100_000, ms, 0, 1<<40), counterAt(1_000_000, ms, 0, 1<<40))}, nil)
			next += 5000
		}
		flow.down.Add(500_000)
		if second == 30 {
			flow.down.Add(3_000_000)
		}
		up, down := r.tick(second)
		readings = append(readings, reading{second, up, down})
	}
	expect(t, readings, 5, 29, 100_000, 1_500_000)
	expect(t, readings, 30, 30, 100_000, 4_500_000)
	expect(t, readings, 31, 40, 100_000, 1_500_000)
}

// A report after a start only sets the baseline: sessions that were already running do not count
// their whole totals again, or show them as a rate.
func TestIPsecLiveRateOfTheFirstReportIsNothing(t *testing.T) {
	r := newRateRig(t)
	const before = 10_000_000_000
	readings := r.drive(20, every(0, 20000, 5000), func(ms int64) ([]ipsecproto.SA, []ipsecproto.SA) {
		return []ipsecproto.SA{r.sa("7", "1", before+counterAt(100_000, ms, 0, 1<<40), before+counterAt(1_000_000, ms, 0, 1<<40))}, nil
	})
	expect(t, readings, 0, 4, 0, 0)
	expect(t, readings, 5, 20, 100_000, 1_000_000)
	if got := r.server.service.monitor.users[r.tag].down.Load(); got != 20_000_000 {
		t.Errorf("counted %d bytes down, want 20000000 (the 10 GB before the start are not counted)", got)
	}
}

// A counter that went back (the session restarted with the same ID) gives a window of nothing,
// never a negative rate, and the rate resumes with the next window.
func TestIPsecLiveRateNeverGoesNegativeWhenACounterGoesBack(t *testing.T) {
	r := newRateRig(t)
	readings := r.drive(30, every(0, 30000, 5000), func(ms int64) ([]ipsecproto.SA, []ipsecproto.SA) {
		begin := int64(0)
		if ms >= 15000 {
			begin = 15000 // the counters start again from zero
		}
		return []ipsecproto.SA{r.sa("7", "1", counterAt(100_000, ms, begin, 1<<40), counterAt(1_000_000, ms, begin, 1<<40))}, nil
	})
	for _, rd := range readings {
		if rd.up < 0 || rd.down < 0 {
			t.Fatalf("a negative rate: %v", readings)
		}
	}
	expect(t, readings, 5, 14, 100_000, 1_000_000)
	expect(t, readings, 15, 19, 0, 0)
	expect(t, readings, 20, 30, 100_000, 1_000_000)
}

// The server restarting in the middle of a transfer does not show the sessions' totals as a
// burst: the first report after the start is a baseline again.
func TestIPsecLiveRateAfterTheServerRestarts(t *testing.T) {
	r := newRateRig(t)
	build := r.steady(100_000, 1_000_000)
	var readings []reading
	times := every(0, 40000, 5000)
	next := 0
	for second := 0; second <= 40; second++ {
		for next < len(times) && times[next] <= int64(second)*1000 {
			sas, closed := build(times[next])
			r.write(times[next], sas, closed)
			next++
		}
		if second == 20 {
			// What a new server process starts with.
			svc := r.server.service
			svc.ipsecLast, svc.ipsecSeen, svc.ipsecPending, svc.ipsecRateAt = time.Time{}, nil, nil, time.Time{}
			svc.monitor.external = map[string]externalRate{}
		}
		up, down := r.tick(second)
		readings = append(readings, reading{second, up, down})
	}
	expect(t, readings, 5, 19, 100_000, 1_000_000)
	expect(t, readings, 20, 24, 0, 0)
	expect(t, readings, 25, 40, 100_000, 1_000_000)
}

// The rate set from a report: shorter than a second gives none, a first report none, and what is
// set falls to zero at the time due, at most 15 seconds on.
func TestMonitorExternalRate(t *testing.T) {
	m := NewMonitor()
	now := time.Unix(rateStart, 0)
	u := m.user("a")
	rate := func(at time.Time) int64 {
		m.Sample(at)
		return m.rates["a"][1]
	}
	m.ExternalRate("a", 0, 5_000_000, 5*time.Second, now)
	if got := rate(now); got != 1_000_000 {
		t.Errorf("rate = %d, want 1000000", got)
	}
	if got := rate(now.Add(9 * time.Second)); got != 1_000_000 {
		t.Errorf("rate at 9 s = %d, want 1000000", got)
	}
	if got := rate(now.Add(10 * time.Second)); got != 0 {
		t.Errorf("rate at 10 s = %d, want 0 (twice the window)", got)
	}
	m.ExternalRate("a", 0, 5_000_000, 400*time.Millisecond, now)
	if got := rate(now); got != 0 {
		t.Errorf("a window under a second gave %d", got)
	}
	m.ExternalRate("a", 0, 60_000_000, 60*time.Second, now)
	if got := rate(now.Add(14 * time.Second)); got != 1_000_000 {
		t.Errorf("rate of a long window at 14 s = %d, want 1000000", got)
	}
	if got := rate(now.Add(15 * time.Second)); got != 0 {
		t.Errorf("rate of a long window at 15 s = %d, want 0 (held at most 15 s)", got)
	}
	// The rate is shown only; the counters are exact whatever was shown.
	u.down.Add(123)
	if got := u.down.Load(); got != 123 {
		t.Errorf("counter = %d", got)
	}
}
