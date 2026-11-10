#!/usr/bin/env python3
"""Checks the live readings (one a second, bytes per second) of a sustained download held to a
cap: steady, not seconds of nothing followed by bursts.

Usage: liverate.py CAP READING...

The component reports every 5 seconds. On 0.8.5 a steady transfer showed four zero seconds in five,
and the fifth at about five times its rate (code review 2026-11-10, IKEv2 findings v0.8.6, IKE-02).
The first 15 readings are skipped: the first window has to fill, and the transfer ramps up. A cap
by policing (dropping above the rate) is only roughly even, so the limits are wide: they separate
a steady rate from batches, they do not measure the payload exactly.
"""
import statistics
import sys

cap = int(sys.argv[1])
readings = [int(value) for value in sys.argv[2:]]
steady = readings[15:]
if len(steady) < 40:
    sys.exit(f"only {len(steady)} readings after the first 15; need at least 40 (a transfer of 55 s or more)")
zeros = sum(1 for value in steady if value == 0)
median, peak = statistics.median(steady), max(steady)
print(f"live down_bps over {len(steady)} s: median {median:.0f}, peak {peak}, zeros {zeros} (cap {cap} B/s)")
problems = []
if zeros > 2:
    problems.append(f"{zeros} readings of nothing during a steady transfer")
if not 0.4 * cap <= median <= 1.6 * cap:
    problems.append(f"the median {median:.0f} B/s is far from the cap {cap} B/s")
if peak > 3.5 * cap:
    problems.append(f"a burst of {peak} B/s, more than 3.5 times the cap")
for problem in problems:
    print("FAIL:", problem)
sys.exit(1 if problems else 0)
