// Speed and data limits as typed in the admin views (admin/limits.ts).
// Run: node --experimental-strip-types --test tests/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dataLimitValue, defaultSpeedChange, defaultSpeedText, speedChange, speedChoice, speedValue } from '../admin/limits.ts';

test('a client speed limit reads back as it was set', () => {
  assert.deepEqual(speedChoice(0), { mode: 'default', mb: '' });
  assert.deepEqual(speedChoice(-1), { mode: 'none', mb: '' });
  assert.deepEqual(speedChoice(2_500_000), { mode: 'custom', mb: '2.5' });
  assert.equal(speedValue({ mode: 'custom', mb: '2.5' }), 2_500_000);
  assert.ok(speedValue({ mode: 'custom', mb: '0.0005' }) instanceof Error);
});

test('an unchanged speed limit is left out of the save, even one the views cannot enter', () => {
  // 500 B/s, set with the server's CLI ("user speed NAME 0.5KB"), used to block every save.
  assert.equal(speedChange(speedChoice(500), 500), undefined);
  assert.equal(speedChange(speedChoice(0), 0), undefined);
  assert.equal(speedChange(speedChoice(-1), -1), undefined);
  assert.equal(speedChange({ mode: 'custom', mb: '2.0' }, 2_000_000), undefined);
  assert.equal(speedChange({ mode: 'none', mb: '' }, 500), -1);
  assert.equal(speedChange({ mode: 'custom', mb: '3' }, 500), 3_000_000);
  assert.ok(speedChange({ mode: 'custom', mb: '0.0004' }, 500) instanceof Error);
  assert.ok(speedChange({ mode: 'custom', mb: '' }, 0) instanceof Error);
});

test('an unchanged default speed limit is left out of the server settings', () => {
  assert.equal(defaultSpeedText(0), '');
  assert.equal(defaultSpeedChange(defaultSpeedText(500), 500), undefined);
  assert.equal(defaultSpeedChange('', 0), undefined);
  assert.equal(defaultSpeedChange('', 2_000_000), 0);
  assert.equal(defaultSpeedChange('5', 2_000_000), 5_000_000);
  assert.ok(defaultSpeedChange('0.0005', 2_000_000) instanceof Error);
  assert.ok(defaultSpeedChange('2e', 2_000_000) instanceof Error);
});

test('a data limit that is not a number is refused, not saved as no limit', () => {
  assert.equal(dataLimitValue(''), 0);
  assert.equal(dataLimitValue('50'), 50_000_000_000);
  assert.equal(dataLimitValue('0.5'), 500_000_000);
  // A number field shows "2e" but reports it as empty, with validity.badInput set.
  assert.ok(dataLimitValue('', true) instanceof Error);
  assert.ok(dataLimitValue('-5') instanceof Error);
  assert.ok(dataLimitValue('1e30') instanceof Error);
});
