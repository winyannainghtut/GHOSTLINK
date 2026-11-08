// Number, date and file name formatting shared by both apps (shared/format.ts).
// Run: node --experimental-strip-types --test tests/
// West of UTC, where a day's usage bucket (midnight UTC) starts on the previous local day.
process.env.TZ = 'America/New_York';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bucketLabel, bytes, byteRate, confName, speed } from '../shared/format.ts';

test('speeds keep their unit and decimals', () => {
  assert.equal(speed(0), '0 B/s');
  assert.equal(speed(999), '999 B/s');
  assert.equal(speed(1500), '2 KB/s');
  assert.equal(speed(2_100_000), '2.1 MB/s');
  assert.equal(speed(3_456_000_000), '3.46 GB/s');
  assert.deepEqual(byteRate(-5), { value: '0', unit: 'B/s' });
});

test('rounding up to 1000 of a unit moves to the next unit', () => {
  assert.equal(speed(999.6), '1 KB/s');
  assert.equal(speed(999_499), '999 KB/s');
  assert.equal(speed(999_600), '1.0 MB/s');
  assert.equal(speed(999_940_000), '999.9 MB/s');
  assert.equal(speed(999_960_000), '1.00 GB/s');
  assert.equal(bytes(999_600), '1.0 MB');
  assert.equal(bytes(999_960_000), '1.0 GB');
  assert.equal(bytes(999_960_000_000), '1.00 TB');
  assert.equal(bytes(512), '512 B');
  assert.equal(bytes(4_200_000_000), '4.2 GB');
});

test('daily buckets are named by their UTC date', () => {
  const nov8 = Date.UTC(2026, 10, 8) / 1000;
  assert.equal(bucketLabel(nov8, 'day', false, 'en-US'), 'Nov 8');
  // The local date of the same instant is a day earlier here: what the chart used to show.
  assert.match(new Date(nov8 * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), /Nov 7/);
});

test('hourly buckets show the day when the chart spans several days', () => {
  const t = Date.UTC(2026, 10, 8, 14) / 1000; // 09:00 in New York
  assert.equal(bucketLabel(t, 'hour', false, 'en-GB'), '09:00');
  assert.equal(bucketLabel(t, 'hour', true, 'en-GB'), '8 Nov, 09:00');
});

test('.conf names fit WireGuard for Windows tunnel names, with room for a copy number', () => {
  const valid = /^[a-zA-Z0-9_=+.-]{1,29}$/;
  for (const [user, protocol, id] of [
    ["Grandpa's Windows PC", 'wireguard', '15'],
    ['Maya', 'amneziawg', '127'],
    ['မောင်မောင်', 'wireguard', '3'],
    ['a'.repeat(80), 'amneziawg', '123456'],
    ['---', 'wireguard', '9'],
  ]) {
    const name = confName(user, protocol, id);
    assert.match(name, valid, name);
    assert.ok(name.endsWith(`-${protocol}-${id}`), `${name} lost the protocol or key ID`);
  }
  assert.equal(confName('Maya', 'wireguard', '15'), 'Maya-wireguard-15');
  assert.equal(confName("Grandpa's Windows PC", 'wireguard', '15'), 'Grandpa-s-Window-wireguard-15');
});
