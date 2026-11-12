// How the provider (AS and operator) of a client address is written (admin/provider.ts).
// Run: node --experimental-strip-types --test tests/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { lookupState, providerText } from '../admin/provider.ts';

test('a provider reads as AS number and operator', () => {
  assert.equal(providerText({ asn: 64496, operator: 'Example Telecom One, Inc.' }), 'AS64496 · Example Telecom One, Inc.');
  assert.equal(providerText({ asn: 64496, operator: '' }), 'AS64496');
  assert.equal(providerText({ asn: 64496 }), 'AS64496');
});

test('an address with no provider shows nothing', () => {
  assert.equal(providerText(undefined), '');
  assert.equal(providerText({}), '');
  assert.equal(providerText({ asn: 0, operator: 'Not routed' }), '');
  assert.equal(providerText({ operator: 'Operator without a number' }), '');
});

const lookup = { enabled: true, ready: true, updating: false, ranges: 579453, updated_unix: 1_000_000, source: 'iptoasn.com' };

test('the settings say how the list is doing', () => {
  const day = 86400;
  assert.equal(lookupState(undefined, 0), '');
  assert.equal(lookupState({ ...lookup, enabled: false }, 0), '');
  assert.equal(lookupState({ ...lookup, ready: false, updating: true }, 0), 'Downloading the list…');
  assert.equal(lookupState({ ...lookup, ready: false, updating: false }, 0), 'Waiting for the list…');
  assert.equal(lookupState({ ...lookup, ready: false, error: 'iptoasn.com answered 429 Too Many Requests' }, 0), 'The list could not be downloaded: iptoasn.com answered 429 Too Many Requests');
  assert.equal(lookupState(lookup, 1_000_000 + 3600), '579,453 address ranges from iptoasn.com, downloaded today.');
  assert.equal(lookupState(lookup, 1_000_000 + day + 5), '579,453 address ranges from iptoasn.com, downloaded yesterday.');
  assert.equal(lookupState(lookup, 1_000_000 + 12 * day), '579,453 address ranges from iptoasn.com, downloaded 12 days ago.');
  assert.equal(lookupState({ ...lookup, error: 'timeout' }, 1_000_000), '579,453 address ranges from iptoasn.com, downloaded today. The last update failed: timeout');
  // A clock set before the download never gives a negative age.
  assert.equal(lookupState(lookup, 5), '579,453 address ranges from iptoasn.com, downloaded today.');
});
