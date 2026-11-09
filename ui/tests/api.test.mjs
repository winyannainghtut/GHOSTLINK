// Each server's views have their own API (admin/api.ts, bindApi): an action of several requests
// keeps to the server it started on, even when another server's views open meanwhile (code
// review 2026-11-09, F2). Run: node --experimental-strip-types --test tests/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as admin from '../admin/api.ts';

// A server whose answers wait until release(); every request is logged with the server's name.
function mockServer(name, log) {
  const waiting = [];
  return {
    transport: {
      call(method, path) {
        log.push(`${name}: ${method} ${path}`);
        return new Promise(resolve => waiting.push(() => resolve({ id: '1' })));
      },
      text: async () => '',
      save: async () => null,
    },
    release: () => waiting.splice(0).forEach(answer => answer()),
  };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test("a new client's key goes to the server the client was created on", async () => {
  const log = [];
  const a = mockServer('A', log);
  const b = mockServer('B', log);
  const onA = admin.bindApi(a.transport);
  // As the New client sheet does: the client first, then its key.
  const newClient = (async () => {
    const user = await onA.api('POST', '/users', { name: 'Alice' });
    await onA.api('POST', `/users/${user.id}/keys`, { protocol: 'shadowsocks' });
  })();
  // While A has not answered yet, the user goes back and opens server B.
  const onB = admin.bindApi(b.transport);
  const openB = onB.api('GET', '/server');
  a.release();
  await settle();
  a.release();
  b.release();
  await Promise.all([newClient, openB]);
  assert.deepEqual(log, ['A: POST /users', 'B: GET /server', 'A: POST /users/1/keys']);
});

test('there is no shared current server for a view to switch', () => {
  assert.equal('setTransport' in admin, false);
  assert.equal('api' in admin, false);
});

test('only a transport that can use keys here offers to', async () => {
  const { transport } = mockServer('A', []);
  const plain = admin.bindApi(transport);
  assert.equal(plain.canUseHere, false);
  await assert.rejects(plain.useHere({}, {}), /Only the desktop app/);
  let used = 0;
  const desktop = admin.bindApi({ ...transport, useHere: async () => void used++ });
  assert.equal(desktop.canUseHere, true);
  await desktop.useHere({}, {});
  assert.equal(used, 1);
});
