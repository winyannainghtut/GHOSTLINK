// The desktop app's mapping from the admin views' requests to the local service's server_call
// operations: every request the views make maps to the right operation, with field names the
// Rust contract (packages/shared-contracts, ServerOp) actually declares; anything else is refused.
// Run: node --experimental-strip-types --test tests/
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { toOp } from '../desktop/src/routes.ts';

// ServerOp variants and their fields, read from the Rust source.
function contract() {
  const source = readFileSync(new URL('../../packages/shared-contracts/src/lib.rs', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('pub enum ServerOp {'));
  const block = body.slice(0, body.indexOf('\n}\n'));
  const ops = new Map();
  let current = null;
  for (const line of block.split('\n').slice(1)) {
    const variant = line.match(/^    ([A-Z]\w*)(\s*\{|,)/);
    if (variant) {
      const name = variant[1].replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
      current = new Set();
      ops.set(name, current);
      continue;
    }
    const field = line.match(/^        (?:pub )?([a-z_]+):/);
    if (field && current) current.add(field[1]);
  }
  return ops;
}
const ops = contract();

function check(method, path, body, expected) {
  const op = toOp(method, path, body);
  assert.deepEqual(op, expected, `${method} ${path}`);
  assert.ok(ops.has(op.op), `${op.op} is not a ServerOp`);
  for (const key of Object.keys(op)) if (key !== 'op') assert.ok(ops.get(op.op).has(key), `${op.op} has no field ${key}`);
}

test('the contract was read', () => {
  assert.ok(ops.size >= 28, `only ${ops.size} operations found`);
  assert.deepEqual([...ops.get('key_qr')].sort(), ['content', 'format', 'key', 'user']);
});

test('server, users and keys', () => {
  check('GET', '/server', undefined, { op: 'info' });
  check('PATCH', '/server', { protocols: { wireguard: { enabled: false } } }, { op: 'update', patch: { protocols: { wireguard: { enabled: false } } } });
  check('GET', '/users', undefined, { op: 'users_list' });
  check('POST', '/users', { name: 'Maya', data_limit_bytes: 5e9 }, { op: 'user_create', change: { name: 'Maya', data_limit_bytes: 5e9 } });
  check('PATCH', '/users/12', { enabled: false }, { op: 'user_update', user: '12', change: { enabled: false } });
  check('DELETE', '/users/12', undefined, { op: 'user_delete', user: '12' });
  check('GET', '/users/12/keys', undefined, { op: 'keys_list', user: '12' });
  check('POST', '/users/12/keys', { protocol: 'ikev2', auth: 'eap', server_address: 'vpn.example.com' }, { op: 'key_create', user: '12', protocol: 'ikev2', auth: 'eap', server_address: 'vpn.example.com' });
  check('DELETE', '/users/12/keys/30', undefined, { op: 'key_delete', user: '12', key: '30' });
  check('GET', '/users/12/keys/30/qr?format=svg&content=conf', undefined, { op: 'key_qr', user: '12', key: '30', format: 'svg', content: 'conf' });
  check('GET', '/users/12/keys/30/profile?prompt_password=1', undefined, { op: 'key_profile', user: '12', key: '30', prompt_password: true, on_demand: false });
  check('GET', '/users/12/kit', undefined, { op: 'kit', user: '12' });
});

test('rules, monitoring and the mesh', () => {
  const rules = { blocked_domains: ['example.com'], blocked_ips: [], blocked_ports: [], block_bittorrent: true, block_smtp: true };
  check('GET', '/rules', undefined, { op: 'rules_get' });
  check('PUT', '/rules', rules, { op: 'rules_set', rules });
  check('GET', '/metrics', undefined, { op: 'metrics' });
  check('GET', '/live', undefined, { op: 'live' });
  check('GET', '/stats?range=24h', undefined, { op: 'stats', range: '24h' });
  check('GET', '/stats?range=30d&user=4', undefined, { op: 'stats', range: '30d', user: '4' });
  check('GET', '/clients', undefined, { op: 'clients' });
  check('GET', '/clients?user=4', undefined, { op: 'clients', user: '4' });
  check('GET', '/mesh', undefined, { op: 'mesh_info' });
  check('PATCH', '/mesh', { enabled: true }, { op: 'mesh_update', patch: { enabled: true } });
  check('POST', '/mesh/invites', { tags: ['web'], uses: 1 }, { op: 'mesh_invite_create', invite: { tags: ['web'], uses: 1 } });
  check('GET', '/mesh/invites', undefined, { op: 'mesh_invite_list' });
  check('DELETE', '/mesh/invites/9', undefined, { op: 'mesh_invite_delete', invite: '9' });
  check('PATCH', '/mesh/nodes/2', { status: 'active' }, { op: 'mesh_node_update', node: '2', change: { status: 'active' } });
  check('DELETE', '/mesh/nodes/2', undefined, { op: 'mesh_node_delete', node: '2' });
  check('GET', '/mesh/rules', undefined, { op: 'mesh_rules_get' });
  const meshRules = [{ from: 'tag:web', to: 'tag:db', protocol: 'tcp', ports: ['5432'] }];
  check('PUT', '/mesh/rules', { rules: meshRules }, { op: 'mesh_rules_set', rules: meshRules });
  check('GET', '/mesh/topology', undefined, { op: 'mesh_topology' });
});

test('anything else is refused', () => {
  for (const [method, path] of [
    ['GET', '/dashboard'],
    ['GET', '/users/abc'],
    ['GET', '/users/1/../2/keys'],
    ['DELETE', '/server'],
    ['GET', '/users/12/keys/30/qr/../../kit'],
    ['POST', '/users/12/kit'],
    ['GET', '//evil.example/server'],
    ['GET', '/users/12%2F13/keys'],
  ]) {
    assert.throws(() => toOp(method, path), /cannot do/, `${method} ${path} was allowed`);
  }
});
