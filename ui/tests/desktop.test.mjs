// The desktop app's local IDs, failure messages and shell errors (desktop/src/ipc.ts and
// desktop/src/failures.ts). Run: node --experimental-strip-types --test tests/
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { failureText } from '../desktop/src/failures.ts';
import { ServiceUnavailable, localKeyId, rejectionError, slug, uniqueName } from '../desktop/src/ipc.ts';

// The service's rule for server IDs (core/vpn-engine/src/profile.rs, valid_name).
const validId = id => /^[A-Za-z0-9_-]{1,64}$/.test(id);

test('servers added under names in other scripts still get IDs of their own', () => {
  const taken = [];
  for (const name of ['ရန်ကုန်', 'มัณฑะเลย์', '東京', 'Москва']) {
    assert.equal(slug(name), 'server');
    const id = uniqueName(slug(name).slice(0, 40), taken);
    assert.ok(validId(id), id);
    assert.ok(!taken.includes(id), `${name} reused ${id}`);
    taken.push(id);
    // uniqueName's suffix is the time, so wait for the next millisecond.
    const until = Date.now() + 2;
    while (Date.now() < until);
  }
});

test('a key used on this device keeps its protocol and key ID, and never reuses an ID', () => {
  const long = 'Maya from the office downstairs with a very long name';
  const id = localKeyId(long, 'wireguard', '1234', []);
  assert.ok(id.endsWith('-wireguard-1234'), id);
  assert.ok(validId(id), id);
  assert.equal(localKeyId('Maya', 'vless', '7', []), 'maya-vless-7');
  const again = localKeyId('Maya', 'vless', '7', ['maya-vless-7']);
  assert.notEqual(again, 'maya-vless-7');
  assert.ok(validId(again), again);
});

test('every failure code the engines set is explained in words', () => {
  const sources = ['../../core/vpn-engine/src/worker_session.rs', '../../core/vpn-engine/src/management.rs', '../../services/vpn-daemon/src/main.rs'];
  const codes = new Set();
  for (const file of sources) {
    const text = readFileSync(new URL(file, import.meta.url), 'utf8');
    // reason = Some("code"), or Some(if … { "code" } else { "code" }); the engine's own event
    // codes tested inside that `if` are not reasons.
    for (const line of text.split('\n')) {
      if (line.includes('reason = Some(')) for (const m of line.matchAll(/Some\("([a-z_]+)"\)|\{ "([a-z_]+)" \}/g)) codes.add(m[1] ?? m[2]);
    }
    for (const m of text.matchAll(/last_error = Some\("([a-z_]+)"\.into\(\)\)/g)) codes.add(m[1]);
    // OpenVPN: reason = Some(event) for these events.
    for (const m of text.matchAll(/matches!\(event, ((?:"[a-z_]+"\s*\|?\s*)+)\)/g)) for (const c of m[1].matchAll(/"([a-z_]+)"/g)) codes.add(c[1]);
  }
  assert.ok(codes.has('outline_engine_start_failed_check_permissions_or_driver') && codes.has('authentication_failed') && codes.has('autoconnect_failed'), [...codes].join(' '));
  assert.ok(codes.size >= 15, `only ${codes.size} codes found`);
  const fallback = failureText(undefined);
  for (const code of codes) assert.notEqual(failureText(code), fallback, `${code} has no words`);
  assert.equal(failureText('something_new'), fallback);
  assert.equal(failureText('toString'), fallback);
});

test('a request the shell refuses is not reported as the service being down', () => {
  const refused = rejectionError('invalid args `action` for command `vpn_request`: invalid type: floating point `1.5`, expected u32');
  assert.ok(!(refused instanceof ServiceUnavailable));
  assert.match(refused.message, /whole numbers/);
  assert.ok(rejectionError(new Error('IPC failed')) instanceof ServiceUnavailable);
});
