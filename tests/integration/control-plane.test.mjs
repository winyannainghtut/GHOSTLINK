import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import net from 'node:net';
import readline from 'node:readline';
import Ajv from 'ajv/dist/2020.js';

const root = path.resolve(import.meta.dirname, '../..');
const windows = process.platform === 'win32';
const suffix = windows ? '.exe' : '';
const bin = path.join(root, 'target', process.env.GHOSTLINK_BUILD_PROFILE || 'debug');
const temp = path.join(root, `.state-test-${process.pid}`);
const state = path.join(temp, 'daemon');
const endpoint = windows ? `\\\\.\\pipe\\ghostlink-test-${process.pid}` : path.join(temp, 'control.sock');
const engine = process.env.GHOSTLINK_TEST_ENGINE || (windows ? path.join(root, '.tools/openvpn-bin/openvpn.exe') : '/usr/sbin/openvpn');
const outlineEngine = process.env.GHOSTLINK_TEST_OUTLINE_WORKER || path.join(bin, `ghostlink-tunnel${suffix}`);
const openssl = process.env.OPENSSL || (windows ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl');
const ajv = new Ajv({ strict: false });
const validateResponse = ajv.compile(JSON.parse(await fs.readFile(path.join(root, 'packages/shared-contracts/response.schema.json'))));
const validateStatus = ajv.compile(JSON.parse(await fs.readFile(path.join(root, 'packages/shared-contracts/status.schema.json'))));
let daemon;
let daemonErrors = '';
let profile;

function cli(args, expected = 0) {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(bin, `ghostlink${suffix}`), ['--endpoint', endpoint, '--json', ...args], { windowsHide: true });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => stdout += data);
    child.stderr.on('data', data => stderr += data);
    child.on('error', reject);
    child.on('close', code => {
      try {
        assert.equal(code, expected, `exit mismatch: ${stdout} ${stderr}`);
        const response = JSON.parse(stdout);
        assert.ok(validateResponse(response), JSON.stringify(validateResponse.errors));
        assert.ok(!stdout.includes('BEGIN PRIVATE KEY'));
        resolve(response);
      } catch (e) { reject(e); }
    });
  });
}
function rpc(request) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(endpoint);
    socket.setTimeout(15000, () => socket.destroy(new Error('IPC timeout')));
    let response = '';
    socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
    socket.on('data', data => { response += data; if (response.includes('\n')) { socket.end(); resolve(JSON.parse(response)); } });
    socket.on('error', reject);
  });
}
async function start({ openvpn = engine } = {}) {
  daemonErrors = '';
  daemon = spawn(path.join(bin, `ghostlinkd${suffix}`), ['--endpoint', endpoint, '--data-dir', state, '--openvpn', openvpn, '--outline-engine', outlineEngine, '--connection-timeout-seconds', '3'], { windowsHide: true });
  daemon.stderr.on('data', data => daemonErrors += data);
  daemon.on('error', () => {});
  for (let i = 0; i < 80; i++) {
    if (daemon.exitCode !== null) throw new Error(`Daemon exited: ${daemonErrors}`);
    try { const r = await cli(['status']); if (r.success) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Daemon did not start: ${daemonErrors}`);
}
async function stop() {
  if (!daemon || daemon.exitCode !== null) return;
  const exited = once(daemon, 'exit');
  daemon.kill(); await exited;
}

before(async () => {
  await fs.mkdir(temp, { mode: 0o700 });
  await fs.writeFile(path.join(temp, 'openssl.cnf'), '[req]\ndistinguished_name=dn\n[dn]\n');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=ghostlink-test', '-config', path.join(temp, 'openssl.cnf'), '-keyout', path.join(temp, 'client.key'), '-out', path.join(temp, 'client.crt')], { windowsHide: true, stdio: 'pipe' });
  const cert = await fs.readFile(path.join(temp, 'client.crt'), 'utf8');
  const key = await fs.readFile(path.join(temp, 'client.key'), 'utf8');
  profile = `client\ndev tun\nproto udp\nremote 127.0.0.1 1\nremote-cert-tls server\nconnect-timeout 1\nconnect-retry-max 1\n<ca>\n${cert}</ca>\n<cert>\n${cert}</cert>\n<key>\n${key}</key>\n`;
  await fs.writeFile(path.join(temp, 'singapore.ovpn'), profile);
  await start();
});
after(async () => { await stop(); await fs.rm(temp, { recursive: true, force: true }); });

test('actual named-pipe / Unix IPC reports disconnected with a valid JSON schema', async () => {
  const r = await cli(['status']); assert.ok(validateStatus(r.data), JSON.stringify(validateStatus.errors));
  assert.equal(r.data.status, 'disconnected'); assert.equal(r.data.vpn_ip, null);
});
test('import, list and default are persistent and contain no certificate secrets', async () => {
  assert.equal((await cli(['profile', 'import', path.join(temp, 'singapore.ovpn')])).data.name, 'singapore');
  const r = await cli(['profile', 'list']); assert.equal(r.data.profiles.length, 1); assert.equal(r.data.profiles[0].is_default, true);
  await cli(['profile', 'default', 'singapore']);
  const persisted = await fs.readFile(path.join(state, 'state.json'), 'utf8'); assert.ok(!persisted.includes('BEGIN PRIVATE KEY'));
  if (windows) {
    const data = JSON.parse(persisted); const stored = Buffer.from(data.profiles.singapore.sealed_content).toString(); assert.ok(!stored.includes('PRIVATE KEY'));
  }
});
test('unsafe configuration cannot execute commands or disclose keys', async () => {
  for (const directive of ['up exploit.exe', 'plugin exploit.dll', 'config private.conf', 'auth-user-pass passwords.txt', 'cipher BF-CBC', 'tls-version-min 1.0', 'management 0.0.0.0 9000', 'setenv opt up exploit', 'verb 9']) {
    const r = await rpc({schema_version: 1, action: {type: 'profile_import', name: 'unsafe', content: profile + directive + '\n'}});
    assert.equal(r.success, false, directive); assert.equal(r.error.code, 'invalid_profile');
  }
  assert.equal((await cli(['profile', 'list'])).data.profiles.length, 1);
});
test('profile path traversal and malformed certificate are rejected', async () => {
  assert.equal((await rpc({schema_version: 1, action: {type: 'profile_import', name: '../escape', content: profile}})).error.code, 'invalid_profile');
  assert.equal((await rpc({schema_version: 1, action: {type: 'profile_import', name: 'badcert', content: profile.replace('BEGIN CERTIFICATE', 'BEGIN OTHER')}})).error.code, 'invalid_profile');
});
test('expired certificates are rejected at import', async () => {
  execFileSync(openssl, ['x509', '-in', path.join(temp, 'client.crt'), '-signkey', path.join(temp, 'client.key'), '-days', '-1', '-out', path.join(temp, 'expired.crt')], { windowsHide: true, stdio: 'pipe' });
  const expired = await fs.readFile(path.join(temp, 'expired.crt'), 'utf8');
  const r = await rpc({schema_version: 1, action: {type: 'profile_import', name: 'expired', content: profile.replace(/<cert>[\s\S]*?<\/cert>/, `<cert>\n${expired}</cert>`)}});
  assert.equal(r.error.code, 'invalid_profile'); assert.match(r.error.message, /expired/);
});
test('32 concurrent status commands return valid real state', async () => {
  const results = await Promise.all(Array.from({length: 32}, () => cli(['status'])));
  assert.ok(results.every(r => validateStatus(r.data)));
});
test('unknown schema and arbitrary command requests fail closed', async () => {
  assert.equal((await rpc({schema_version: 99, action: {type: 'status'}})).error.code, 'invalid_request');
  assert.equal((await rpc({schema_version: 1, action: {type: 'shell', command: 'whoami'}})).error.code, 'invalid_request');
});
test('read-only agent token is explicit, scoped, audited and revocable', async () => {
  const tokenPath = path.join(temp, 'readonly.token');
  const grant = await cli(['agent', 'grant', '--name', 'assistant', '--token-file', tokenPath]);
  assert.equal(grant.data.issued_token, undefined); assert.equal(grant.data.token_saved, true);
  const token = (await fs.readFile(tokenPath, 'utf8')).trim();
  assert.equal((await rpc({schema_version: 1, agent_token: token, action: {type: 'status'}})).success, true);
  assert.equal((await rpc({schema_version: 1, agent_token: token, action: {type: 'connect', profile: 'singapore'}})).error.code, 'permission_denied');
  assert.equal((await rpc({schema_version: 1, agent_token: token, action: {type: 'agent_grant', name: 'evil', control: true}})).error.code, 'permission_denied');
  const logs = await cli(['logs']); assert.ok(logs.data.entries.some(e => e.actor === 'agent:assistant')); assert.ok(!JSON.stringify(logs).includes(token));
  await cli(['agent', 'revoke', '--name', 'assistant']);
  assert.equal((await rpc({schema_version: 1, agent_token: token, action: {type: 'status'}})).error.code, 'permission_denied');
});
test('MCP advertises restricted tools and routes actual tool calls through the service', async () => {
  const tokenPath = path.join(temp, 'mcp.token'); await cli(['agent', 'grant', '--name', 'mcp', '--token-file', tokenPath]);
  const child = spawn(path.join(bin, `ghostlink-mcp${suffix}`), ['--endpoint', endpoint, '--token-file', tokenPath], { windowsHide: true });
  const lines = readline.createInterface({input: child.stdout}); const pending = [];
  lines.on('line', line => pending.shift()?.(JSON.parse(line)));
  const request = value => new Promise(resolve => { pending.push(resolve); child.stdin.write(JSON.stringify(value) + '\n'); });
  try {
    const init = await request({jsonrpc:'2.0', id:1, method:'initialize', params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1'}}}); assert.equal(init.result.serverInfo.name, 'ghostlink');
    const list = await request({jsonrpc:'2.0', id:2, method:'tools/list'}); assert.equal(list.result.tools.length, 3);
    const status = await request({jsonrpc:'2.0', id:3, method:'tools/call', params:{name:'vpn_status',arguments:{}}}); assert.equal(status.result.structuredContent.data.status, 'disconnected');
    const denied = await request({jsonrpc:'2.0', id:4, method:'tools/call', params:{name:'vpn_connect',arguments:{profile:'singapore'}}}); assert.equal(denied.error.code, -32602);
  } finally { child.stdin.end(); await once(child, 'exit'); lines.close(); }
});
test('actual OpenVPN engine cannot manufacture success for an unavailable server', async t => {
  try { await fs.access(engine); } catch { t.skip('Standalone OpenVPN not installed'); return; }
  const r = await cli(['connect', '--profile', 'singapore', '--timeout', '35'], 1);
  assert.equal(r.error.code, 'connection_failed');
  const state = (await cli(['status'])).data; assert.equal(state.status, 'failed'); assert.ok(state.last_error); assert.equal(state.vpn_ip, null);
  await cli(['disconnect']); assert.equal((await cli(['status'])).data.status, 'disconnected');
});
test('state survives a daemon restart without pretending a tunnel survived', async () => {
  await stop(); await start();
  assert.equal((await cli(['profile', 'list'])).data.profiles[0].name, 'singapore');
  assert.equal((await cli(['status'])).data.status, 'disconnected');
});
test('a failed autoconnect at startup keeps the service reachable and reports the failure', async () => {
  await cli(['autoconnect', 'enable']);
  await stop();
  // Make engine start fail with an internal error before anything is spawned: the private
  // runtime directory path is occupied by a regular file.
  const run = path.join(state, 'run');
  await fs.rm(run, { recursive: true, force: true }); await fs.writeFile(run, '');
  try {
    // Any existing absolute file passes the engine-path check; it is never executed here.
    await start({ openvpn: process.execPath });
    const status = (await cli(['status'])).data;
    assert.equal(status.status, 'failed'); assert.equal(status.last_error, 'autoconnect_failed'); assert.equal(status.vpn_ip, null);
    assert.equal((await cli(['autoconnect', 'disable'])).data.autoconnect, false);
    const logs = (await cli(['logs'])).data.entries;
    assert.ok(logs.some(e => e.operation === 'autoconnect' && e.outcome === 'error'));
  } finally {
    await stop(); await fs.rm(run, { force: true }); await start();
  }
  assert.equal((await cli(['status'])).data.status, 'disconnected');
});
test('crash leftovers are removed at startup and do not block state writes', async () => {
  await stop();
  await fs.mkdir(path.join(state, 'run'), { recursive: true });
  await fs.writeFile(path.join(state, 'state.pending'), 'uncommitted');
  await fs.writeFile(path.join(state, 'run', 'outline.json'), '{"password":"stale-plaintext-credential"}');
  await fs.writeFile(path.join(state, 'run', 'outline.pending'), '');
  await start();
  for (const leftover of ['state.pending', path.join('run', 'outline.json'), path.join('run', 'outline.pending')]) {
    await assert.rejects(fs.access(path.join(state, leftover)), `${leftover} should be removed`);
  }
  await cli(['profile', 'default', 'singapore']);
  assert.equal((await cli(['profile', 'list'])).data.profiles[0].name, 'singapore');
});
test('version is local, unknown profile exit is predictable, and switch validates target first', async () => {
  assert.equal((await cli(['version'])).data.version, '0.1.0');
  assert.equal((await cli(['connect', '--profile', 'missing'], 2)).error.code, 'not_found');
  assert.equal((await cli(['switch', '--profile', 'missing'], 2)).error.code, 'not_found');
});
test('Outline access keys import privately, rename, select default and remove through actual IPC', async () => {
  const secret = 'private-access-credential-do-not-output';
  const credential = Buffer.from(`chacha20-ietf-poly1305:${secret}`).toString('base64url');
  const keyPath = path.join(temp,'outline-access.txt');
  await fs.writeFile(keyPath,`ss://${credential}@127.0.0.1:1/?outline=1#Singapore`,{mode:0o600});
  const r = await cli(['key','add','--name','outline-singapore','--file',keyPath]);
  assert.equal(r.data.kind,'outline'); assert.equal(r.data.display_name,'Singapore'); assert.equal(r.data.certificate_expires_unix,null);
  assert.ok(!JSON.stringify(r).includes(secret)); assert.ok(!JSON.stringify(r).includes(credential));
  // The fingerprint visible to read-only agents must not be a plain hash of the credential.
  const plainHash = createHash('sha256').update(await fs.readFile(keyPath, 'utf8')).digest('hex');
  assert.match(r.data.sha256, /^[0-9a-f]{64}$/); assert.notEqual(r.data.sha256, plainHash);
  // An existing server ID is never silently overwritten.
  assert.equal((await cli(['key','add','--name','outline-singapore','--file',keyPath], 2)).error.code, 'invalid_request');
  assert.equal((await cli(['key','add','--name','outline-singapore','--file',keyPath,'--replace'])).data.name, 'outline-singapore');
  assert.equal((await cli(['profile','import',path.join(temp,'singapore.ovpn')], 2)).error.code, 'invalid_request');
  const renamed = await rpc({schema_version:1,action:{type:'profile_rename',name:'outline-singapore',display_name:'My Singapore'}}); assert.equal(renamed.data.display_name,'My Singapore');
  await cli(['profile','default','outline-singapore']);
  await cli(['autoconnect','enable']); assert.equal((await cli(['info'])).data.autoconnect,true);
  await cli(['autoconnect','disable']);
  const metadata = await cli(['profile','list']); assert.ok(!JSON.stringify(metadata).includes(secret));
  if (process.env.GHOSTLINK_TEST_EXPECT_UNPRIVILEGED === '1') {
    const failure = await cli(['connect','--profile','outline-singapore','--timeout','25'],1);
    assert.equal(failure.error.code,'connection_failed');
    const status = (await cli(['status'])).data;
    assert.equal(status.status,'failed'); assert.equal(status.vpn_ip,null);
    await cli(['disconnect']);
    await assert.rejects(fs.access(path.join(state,'run','outline.json')));
  }
  const logs = await cli(['logs']); assert.ok(!JSON.stringify(logs).includes(secret));
  if (windows) {
    const persisted = JSON.parse(await fs.readFile(path.join(state,'state.json'),'utf8'));
    assert.ok(!Buffer.from(persisted.profiles['outline-singapore'].sealed_content).toString().includes('ss://'));
  }
  await cli(['profile','remove','outline-singapore']); assert.equal((await cli(['info'])).data.default_profile,null);
});
test('dynamic key SSRF, obsolete ciphers and plugins fail without exposing credentials', async () => {
  for (const access_key of ['ssconf://127.0.0.1/private','ssconf://169.254.169.254/latest/meta-data','ss://none:top-secret@example.com:443','ss://aes-256-gcm:top-secret@example.com:443?plugin=evil']) {
    const r = await rpc({schema_version:1,action:{type:'access_key_import',name:'rejected',access_key}});
    assert.equal(r.success,false); assert.ok(!JSON.stringify(r).includes('top-secret'));
  }
});
