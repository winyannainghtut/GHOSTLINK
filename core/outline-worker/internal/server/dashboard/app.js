/* Ghostlink server dashboard. Talks only to this server's /api (session cookie + header). */
'use strict';
const $ = s => document.querySelector(s);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };
const svgEl = (tag, attrs) => { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v); return n; };
const PROTOCOLS = { amneziawg: 'AmneziaWG', wireguard: 'WireGuard', vless: 'VLESS with REALITY', shadowsocks: 'Shadowsocks (Outline)', ikev2: 'IKEv2 (iPhone, iPad, Mac)', ipsec: 'IPsec (iPhone, iPad, Mac; legacy)' };
const ORDER = ['amneziawg', 'wireguard', 'vless', 'shadowsocks'];
const APPLE = ['ikev2', 'ipsec'];
const AUTH = { ikev2: [['eap', 'Username and password (EAP)'], ['certificate', 'Certificate']], ipsec: [['certificate', 'Certificate'], ['psk', 'Shared group key (weak)']] };
const AUTH_TITLES = { eap: 'username and password', certificate: 'certificate', psk: 'shared group key' };
const state = { server: null, users: [], live: {}, view: 'overview', editing: null, keysUser: null, statsUser: null, rulesUser: null, confirm: null };

function data(bytes) { bytes = Number(bytes) || 0; if (bytes >= 1e12) return (bytes / 1e12).toFixed(2) + ' TB'; if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB'; if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB'; if (bytes >= 1e3) return Math.round(bytes / 1e3) + ' KB'; return bytes + ' B'; }
function speed(bps) { const bits = (Number(bps) || 0) * 8; if (bits >= 1e9) return (bits / 1e9).toFixed(2) + ' Gbit/s'; if (bits >= 1e6) return (bits / 1e6).toFixed(1) + ' Mbit/s'; if (bits >= 1e3) return Math.round(bits / 1e3) + ' kbit/s'; return Math.round(bits) + ' bit/s'; }
function ago(unix) { if (!unix) return 'never'; const s = Math.max(0, Date.now() / 1000 - unix); if (s < 90) return 'just now'; if (s < 5400) return Math.round(s / 60) + ' min ago'; if (s < 129600) return Math.round(s / 3600) + ' h ago'; return Math.round(s / 86400) + ' days ago'; }
function notice(message, bad) { $('#notice').textContent = message || ''; $('#notice').hidden = !message; $('#notice').classList.toggle('bad', Boolean(bad)); }

async function api(method, path, body, raw) {
  const response = await fetch('/api' + path, { method, credentials: 'same-origin', headers: { 'X-Ghostlink-Dashboard': '1', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (response.status === 401) { showSignin('Your session ended. Open the login link from the server again.'); throw new Error('Signed out'); }
  if (!response.ok) { let message = 'The server refused the request'; try { message = (await response.json()).error || message; } catch {} throw new Error(message); }
  if (raw) return response.blob();
  return response.status === 204 ? null : response.json();
}

function showSignin(message) { $('#app').hidden = true; $('#signin').hidden = false; $('#signin-error').textContent = message || ''; $('#signin-error').hidden = !message; }
async function signin() {
  const token = new URLSearchParams(location.hash.slice(1)).get('t');
  if (token) {
    history.replaceState(null, '', location.pathname);
    const response = await fetch('/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    if (!response.ok) { let message = 'This login link is not valid.'; try { message = (await response.json()).error; } catch {} showSignin(message); return false; }
  }
  try { state.server = await api('GET', '/server'); } catch { showSignin(token ? 'Could not sign in.' : ''); return false; }
  $('#signin').hidden = true; $('#app').hidden = false; return true;
}

// --- charts ---
function lineChart(svg, points, max) {
  svg.replaceChildren(svgEl('line', { x1: 0, y1: 159, x2: 600, y2: 159, class: 'axis' }));
  if (!points.length) return;
  const top = Math.max(max || 1, ...points.flatMap(p => [p.up, p.down]), 1);
  for (const [key, cls] of [['down', 'down'], ['up', 'up']]) {
    const path = points.map((p, i) => `${(i / Math.max(points.length - 1, 1) * 600).toFixed(1)},${(158 - p[key] / top * 150).toFixed(1)}`).join(' ');
    svg.append(svgEl('polyline', { points: path, class: cls }));
  }
  const label = svgEl('text', { x: 4, y: 12 }); label.textContent = top > 1 ? speed(top) + ' peak' : 'No traffic in the last 2 minutes'; svg.append(label);
}
function barChart(svg, series, unit) {
  svg.replaceChildren(svgEl('line', { x1: 0, y1: 159, x2: 600, y2: 159, class: 'axis' }));
  if (!series.length) { const t = svgEl('text', { x: 4, y: 80 }); t.textContent = 'No traffic recorded in this period'; svg.append(t); return; }
  const top = Math.max(...series.map(b => b.up + b.down), 1);
  const width = 600 / series.length;
  series.forEach((b, i) => {
    const down = b.down / top * 150, up = b.up / top * 150;
    svg.append(svgEl('rect', { x: i * width + 1, y: 158 - down - up, width: Math.max(width - 2, 1), height: down, class: 'bar-down' }));
    svg.append(svgEl('rect', { x: i * width + 1, y: 158 - up, width: Math.max(width - 2, 1), height: up, class: 'bar-up' }));
  });
  const label = svgEl('text', { x: 4, y: 12 }); label.textContent = data(top) + ' per ' + unit + ' at most'; svg.append(label);
}
function bars(target, items, empty) {
  target.replaceChildren();
  if (!items || !items.length) { target.append(el('p', 'hint', empty || 'Nothing recorded yet.')); return; }
  const wrap = el('div', 'bars'); const top = Math.max(...items.map(i => i.bytes), 1);
  for (const item of items) {
    const row = el('div', 'bar'); const track = el('div', 'track'); const fill = el('span', 'fill');
    fill.style.width = (item.bytes / top * 100).toFixed(1) + '%'; track.append(fill);
    row.append(el('span', '', PROTOCOLS[item.label] || item.label), track, el('span', '', data(item.bytes))); wrap.append(row);
  }
  target.append(wrap);
}

// --- overview & live ---
async function refreshLive() {
  try {
    const live = await api('GET', '/live');
    state.live = Object.fromEntries(live.users.map(u => [u.id, u]));
    $('#live-down').textContent = speed(live.down_bps); $('#live-up').textContent = speed(live.up_bps);
    $('#live-online').textContent = `${live.online_users} / ${live.users.length}`; $('#live-active').textContent = live.active;
    lineChart($('#live-chart'), live.series);
    const h = live.health, dl = $('#health'); dl.replaceChildren();
    const rows = [['Uptime', h.uptime_seconds >= 86400 ? Math.floor(h.uptime_seconds / 86400) + ' days' : Math.round(h.uptime_seconds / 3600) + ' h']];
    if (h.cpu_percent !== undefined) rows.push(['CPU', h.cpu_percent.toFixed(0) + ' %' + (h.load_1m !== undefined ? ` (load ${h.load_1m.toFixed(2)})` : '')]);
    if (h.memory_total_bytes) rows.push(['Memory', `${data(h.memory_used_bytes)} of ${data(h.memory_total_bytes)}`]);
    if (h.disk_total_bytes) rows.push(['Disk free', `${data(h.disk_free_bytes)} of ${data(h.disk_total_bytes)}`]);
    if (h.network_rx_bps !== undefined) rows.push(['Network (host)', `↓ ${speed(h.network_rx_bps)} · ↑ ${speed(h.network_tx_bps)}`]);
    rows.push(['History file', data(h.history_bytes)], ['Engine restarts', String(h.engine_reloads)]);
    for (const [k, v] of rows) dl.append(el('dt', '', k), el('dd', '', v));
    if (h.detail_paused) notice('The disk is nearly full: detailed traffic recording is paused until space is freed. Live data and totals continue.', true);
    if (state.view === 'users') renderUsers();
  } catch {}
}
async function loadOverview() {
  try {
    const [today, week] = await Promise.all([api('GET', '/stats?range=24h'), api('GET', '/stats?range=7d')]);
    const list = $('#today-users'); list.replaceChildren();
    const used = today.users.filter(u => u.up + u.down > 0);
    if (!used.length) list.append(el('p', 'hint', 'No traffic in the last 24 hours.'));
    bars(list, used.map(u => ({ label: u.name, bytes: u.up + u.down })), 'No traffic in the last 24 hours.');
    bars($('#overview-types'), week.types); bars($('#overview-protocols'), week.protocols);
    bars($('#overview-sites'), week.sites, week.site_stats ? 'No sites recorded yet.' : 'Top services are off. Turn them on in Settings.');
  } catch (error) { notice(error.message, true); }
}

// --- users ---
async function loadUsers() { state.users = await api('GET', '/users'); renderUsers(); }
function renderUsers() {
  const list = $('#user-list'); list.replaceChildren();
  if (!state.users.length) list.append(el('p', 'hint', 'No users yet. Add one, then create a key for them.'));
  for (const user of state.users) {
    const live = state.live[user.id] || {};
    const row = el('div', 'row'); const who = el('div', 'who'); const title = el('h3');
    const dot = el('span', 'dot' + (live.online ? ' on' : '')); dot.title = live.online ? 'Online' : 'Offline';
    title.append(dot, document.createTextNode(user.name), user.over_limit ? el('span', 'chip warn', 'LIMIT REACHED') : user.enabled ? el('span', 'chip', 'ACTIVE') : el('span', 'chip off', 'PAUSED'));
    who.append(title, el('div', 'sub', user.data_limit_bytes ? `${data(user.usage_bytes)} of ${data(user.data_limit_bytes)}` : `${data(user.usage_bytes)} used · no limit`));
    if (user.data_limit_bytes) { const m = el('div', 'meter'); const f = el('span'); f.style.width = Math.min(100, user.usage_bytes / user.data_limit_bytes * 100) + '%'; m.append(f); who.append(m); }
    who.append(el('div', 'sub', `${user.keys.length} key${user.keys.length === 1 ? '' : 's'} · last active ${ago(live.last_active_unix)}`));
    const speedBox = el('div', 'speed', live.online ? `↓ ${speed(live.down_bps)}  ↑ ${speed(live.up_bps)}` : 'offline');
    const actions = el('div', 'actions');
    for (const [label, cls, fn] of [['Keys', 'primary', () => openKeys(user)], ['Stats', 'secondary', () => openStats(user)], ['Edit', 'secondary', () => openUser(user)], ['Rules', 'secondary', () => openRules(user)], ['Remove', 'secondary', () => confirmAction(`Remove ${user.name}?`, 'Their keys stop working immediately.', 'Remove user', () => api('DELETE', `/users/${user.id}`))]]) {
      const b = el('button', cls, label); b.type = 'button'; b.addEventListener('click', fn); actions.append(b);
    }
    row.append(who, speedBox, actions); list.append(row);
  }
}
function openUser(user) {
  state.editing = user; $('#user-heading').textContent = user ? `Edit ${user.name}` : 'Add user';
  $('#user-name').value = user ? user.name : ''; $('#user-limit').value = user && user.data_limit_bytes ? user.data_limit_bytes / 1e9 : '';
  $('#user-enabled').checked = user ? user.enabled : true; $('#user-exempt').checked = Boolean(user && user.exempt_from_global_rules); $('#user-reset').checked = false;
  $('#user-enabled-row').hidden = !user; $('#user-reset-row').hidden = !user; $('#user-error').hidden = true; $('#user-dialog').showModal();
}
$('#user-form').addEventListener('submit', async event => {
  event.preventDefault(); const user = state.editing; const limit = $('#user-limit').value.trim();
  const change = { name: $('#user-name').value.trim(), exempt_from_global_rules: $('#user-exempt').checked };
  if (limit !== '' || user) change.data_limit_bytes = Math.round(Number(limit || 0) * 1e9);
  if (user) { change.enabled = $('#user-enabled').checked; if ($('#user-reset').checked) change.reset_usage = true; }
  try { await api(user ? 'PATCH' : 'POST', user ? `/users/${user.id}` : '/users', change); $('#user-dialog').close(); await loadUsers(); }
  catch (error) { $('#user-error').textContent = error.message; $('#user-error').hidden = false; }
});

// --- keys ---
async function openKeys(user) {
  state.keysUser = user; $('#keys-heading').textContent = `Keys for ${user.name}`; $('#keys-error').hidden = true; $('#key-list').replaceChildren();
  for (const id of ['#key-address', '#key-local-id', '#key-remote-id']) $(id).value = '';
  keyOptionsChanged(); $('#keys-dialog').showModal(); await loadKeys();
}
async function loadKeys() {
  const user = state.keysUser; const list = $('#key-list'); list.replaceChildren();
  try {
    const keys = await api('GET', `/users/${user.id}/keys`);
    if (!keys.length) list.append(el('p', 'hint', 'No keys yet. Create one below.'));
    for (const key of keys) {
      const row = el('div', 'key'); const what = el('div', 'what', PROTOCOLS[key.protocol] || key.protocol);
      what.append(el('small', '', 'Created ' + new Date(key.created_unix * 1000).toLocaleDateString())); row.append(what);
      const buttons = [];
      if (APPLE.includes(key.protocol)) {
        what.append(el('small', '', `${AUTH_TITLES[key.auth] || key.auth} · ${key.identity} · ${key.server_address}`));
        buttons.push(['Download profile', () => downloadProfile(user, key, false)]);
        if (key.auth === 'certificate') buttons.push(['Profile (ask for password)', () => downloadProfile(user, key, true)]);
      } else {
        buttons.push(['QR code', () => showQR(user, key, key.config ? 'conf' : 'key')]);
        if (key.config) buttons.push(['QR (vpn://)', () => showQR(user, key, 'key')]);
        buttons.push(['Copy key', () => copy(key.access_key, 'Key copied.')]);
        if (key.config) buttons.push(['Copy .conf', () => copy(key.config, '.conf copied.')]);
      }
      buttons.push(['Remove', () => { $('#keys-dialog').close(); confirmAction('Remove this key?', 'Anyone using it is disconnected.', 'Remove key', () => api('DELETE', `/users/${user.id}/keys/${key.id}`)); }]);
      for (const [label, fn] of buttons) { const b = el('button', 'secondary', label); b.type = 'button'; b.addEventListener('click', async () => { try { await fn(); } catch (e) { $('#keys-error').textContent = e.message; $('#keys-error').hidden = false; } }); row.append(b); }
      list.append(row);
    }
  } catch (error) { $('#keys-error').textContent = error.message; $('#keys-error').hidden = false; }
}
function saveBlob(blob, name) {
  const link = el('a'); link.href = URL.createObjectURL(blob); link.download = name; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 5000);
}
// An Apple configuration profile installs the VPN in Settings on iPhone, iPad and Mac.
async function downloadProfile(user, key, prompt) {
  const blob = await api('GET', `/users/${user.id}/keys/${key.id}/profile${prompt ? '?prompt_password=1' : ''}`, undefined, true);
  saveBlob(blob, `${user.name.replace(/[^\w.-]+/g, '-')}-${key.protocol}-${key.id}.mobileconfig`);
  notice(prompt
    ? `Profile saved without the certificate password. Give ${user.name} the password separately; the device asks for it when installing: ${key.certificate_password}`
    : 'Profile saved. Send it privately (AirDrop, Mail or Files); opening it on the device installs the VPN.');
}
function keyOptionsChanged() {
  const protocol = $('#key-protocol').value; const apple = APPLE.includes(protocol);
  $('#key-apple').hidden = !apple;
  if (!apple) return;
  const auth = $('#key-auth'); const previous = auth.value; auth.replaceChildren();
  for (const [value, label] of AUTH[protocol]) { const o = el('option', '', label); o.value = value; auth.append(o); }
  if (AUTH[protocol].some(([value]) => value === previous)) auth.value = previous;
  $('#key-remote-id').closest('label').hidden = protocol !== 'ikev2';
  $('#key-psk-warning').hidden = auth.value !== 'psk';
}
$('#key-protocol').addEventListener('change', keyOptionsChanged);
$('#key-auth').addEventListener('change', keyOptionsChanged);
async function copy(text, message) { await navigator.clipboard.writeText(text); notice(message); }
async function showQR(user, key, content) {
  const blob = await api('GET', `/users/${user.id}/keys/${key.id}/qr?format=svg&content=${content}`, undefined, true);
  const image = $('#qr-image'); if (image.src) URL.revokeObjectURL(image.src); image.src = URL.createObjectURL(blob);
  $('#qr-heading').textContent = `${PROTOCOLS[key.protocol]} · ${user.name}`;
  $('#qr-note').textContent = content === 'conf' ? 'Scan with the WireGuard or AmneziaWG app (+ → Scan from QR code).' : key.protocol === 'shadowsocks' ? 'Scan with Outline, Shadowrocket or v2rayNG.' : key.protocol === 'vless' ? 'Scan with v2rayNG, Hiddify, Streisand or Shadowrocket.' : 'Scan with the AmneziaVPN app.';
  $('#qr-dialog').showModal();
}
$('#key-form').addEventListener('submit', async event => {
  event.preventDefault(); $('#keys-error').hidden = true;
  const request = { protocol: $('#key-protocol').value };
  if (APPLE.includes(request.protocol)) {
    request.auth = $('#key-auth').value;
    for (const [field, id] of [['server_address', '#key-address'], ['local_identifier', '#key-local-id'], ['remote_identifier', '#key-remote-id']]) {
      const value = $(id).value.trim(); if (value && !(field === 'remote_identifier' && request.protocol !== 'ikev2')) request[field] = value;
    }
  }
  try { const key = await api('POST', `/users/${state.keysUser.id}/keys`, request); if (key.warning) notice(key.warning, true); await loadKeys(); }
  catch (error) { $('#keys-error').textContent = error.message; $('#keys-error').hidden = false; }
});
$('#kit-download').addEventListener('click', async () => {
  try {
    const user = state.keysUser; const blob = await api('GET', `/users/${user.id}/kit`, undefined, true);
    saveBlob(blob, `${user.name.replace(/[^\w.-]+/g, '-')}-vpn.html`);
  } catch (error) { $('#keys-error').textContent = error.message; $('#keys-error').hidden = false; }
});
$('#keys-dialog').addEventListener('close', () => { $('#key-list').replaceChildren(); loadUsers().catch(() => {}); });
$('#qr-dialog').addEventListener('close', () => { const image = $('#qr-image'); if (image.src) URL.revokeObjectURL(image.src); image.removeAttribute('src'); });

// --- stats ---
async function openStats(user) { state.statsUser = user; $('#stats-heading').textContent = `Statistics · ${user.name}`; $('#stats-dialog').showModal(); await loadStats(); }
async function loadStats() {
  const user = state.statsUser; const range = $('#stats-range').value;
  try {
    const [stats, clients] = await Promise.all([api('GET', `/stats?range=${range}&user=${user.id}`), api('GET', `/clients?user=${user.id}`)]);
    barChart($('#stats-chart'), stats.series, stats.unit);
    bars($('#stats-types'), stats.types); bars($('#stats-protocols'), stats.protocols);
    bars($('#stats-sites'), stats.sites, stats.site_stats ? 'No sites recorded in this period.' : 'Top services are off. Turn them on in Settings.');
    const target = $('#stats-clients'); target.replaceChildren();
    if (!clients.clients.length) { target.append(el('p', 'hint', 'No connections recorded in the last 30 days.')); return; }
    const table = el('table'); const head = el('tr'); for (const h of ['Address', 'Protocol', 'First seen', 'Last seen']) head.append(el('th', '', h)); table.append(head);
    for (const c of clients.clients) { const tr = el('tr'); tr.append(el('td', '', c.ip), el('td', '', PROTOCOLS[c.protocol] || c.protocol), el('td', '', new Date(c.first_unix * 1000).toLocaleString()), el('td', '', ago(c.last_unix))); table.append(tr); }
    target.append(table);
  } catch (error) { notice(error.message, true); }
}
$('#stats-range').addEventListener('change', loadStats);

// --- rules ---
function rulesForm(form, rules, title, onSave, extra) {
  form.replaceChildren();
  if (title) form.append(el('h2', '', title));
  const field = (label, value, hint) => { const l = el('label', '', label); if (hint) l.append(el('small', '', ' ' + hint)); const t = el('textarea'); t.rows = 3; t.spellcheck = false; t.value = value.join('\n'); l.append(t); form.append(l); return t; };
  const sites = field('Blocked sites', rules.blocked_domains, 'one per line; subdomains included');
  const ips = field('Blocked IP addresses or ranges', rules.blocked_ips);
  const ports = field('Blocked ports', rules.blocked_ports, 'for example 25 or 6881-6889');
  const check = (label, value) => { const l = el('label', 'check'); const c = el('input'); c.type = 'checkbox'; c.checked = value; l.append(c, document.createTextNode(' ' + label)); form.append(l); return c; };
  const torrent = check('Block BitTorrent', rules.block_bittorrent); const smtp = check('Block outgoing mail (port 25)', rules.block_smtp);
  form.append(el('p', 'hint', 'Local networks, the server itself and cloud metadata addresses are always blocked.'));
  const error = el('p', 'error'); error.hidden = true; form.append(error);
  const actions = el('div', 'actions'); if (extra) actions.append(extra); const save = el('button', 'primary', 'Save rules'); save.type = 'submit'; actions.append(save); form.append(actions);
  const lines = t => t.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  form.onsubmit = async event => { event.preventDefault(); error.hidden = true; try { await onSave({ blocked_domains: lines(sites), blocked_ips: lines(ips), blocked_ports: lines(ports), block_bittorrent: torrent.checked, block_smtp: smtp.checked }); } catch (e) { error.textContent = e.message; error.hidden = false; } };
}
async function loadGlobalRules() { rulesForm($('#global-rules'), await api('GET', '/rules'), '', async rules => { await api('PUT', '/rules', rules); notice('Rules saved.'); }); }
function openRules(user) {
  const cancel = el('button', 'secondary', 'Cancel'); cancel.type = 'button'; cancel.addEventListener('click', () => $('#rules-dialog').close());
  rulesForm($('#user-rules'), user.rules, `Rules only for ${user.name}`, async rules => { await api('PATCH', `/users/${user.id}`, { rules }); $('#rules-dialog').close(); await loadUsers(); }, cancel);
  $('#rules-dialog').showModal();
}

// --- settings ---
async function loadSettings() {
  const s = state.server = await api('GET', '/server');
  $('#set-name').value = s.name; $('#set-hostname').value = s.hostname; $('#set-reality').value = s.vless_handshake;
  const grid = $('#set-protocols'); grid.replaceChildren();
  for (const p of ORDER) { const v = s.protocols[p]; const l = el('label', 'check'); const c = el('input'); c.type = 'checkbox'; c.checked = v.enabled; c.dataset.protocol = p; l.append(c, document.createTextNode(' ' + PROTOCOLS[p])); const port = el('input'); port.type = 'number'; port.min = 1; port.max = 65535; port.value = v.port; port.dataset.port = p; port.setAttribute('aria-label', PROTOCOLS[p] + ' port'); grid.append(l, port); }
  for (const p of APPLE) { const v = s.protocols[p] || { enabled: false }; const l = el('label', 'check'); const c = el('input'); c.type = 'checkbox'; c.checked = v.enabled; c.dataset.apple = p; l.append(c, document.createTextNode(' ' + PROTOCOLS[p])); grid.append(l, el('span', 'hint', 'UDP 500 and 4500')); }
  const component = s.ipsec_component || {};
  $('#set-ipsec').textContent = component.running
    ? `IPsec component running, ${component.connections || 0} connected.` + (component.error ? ` Problem: ${component.error}` : '')
    : 'The IPsec component for iPhone, iPad and Mac (IKEv2/IPsec) is not running. Start it on the server with: sudo ghostlink-server ipsec enable';
  $('#set-sites').checked = s.site_stats; $('#set-history-days').value = s.history_days; $('#set-site-days').value = s.site_days; $('#set-history-mb').value = s.history_max_mb;
  $('#set-history-info').textContent = 'Older records are deleted automatically, and the history file never grows past the size limit (oldest site totals go first, daily totals last).';
  $('#set-dashboard').textContent = `This dashboard uses port ${s.dashboard_port} (${s.dashboard_public ? 'public HTTPS' : 'private, SSH tunnel only'}). Change it on the server with: sudo ghostlink-server dashboard --port N` + (s.dashboard_public ? ' · --private to go back to tunnel-only' : '');
}
$('#settings-form').addEventListener('submit', async event => {
  event.preventDefault(); const s = state.server; const patch = {}; const protocols = {};
  for (const [key, id] of [['name', '#set-name'], ['hostname', '#set-hostname'], ['vless_handshake', '#set-reality']]) { const v = $(id).value.trim(); if (v !== s[key]) patch[key] = v; }
  for (const p of ORDER) { const enabled = document.querySelector(`[data-protocol="${p}"]`).checked; const port = Number(document.querySelector(`[data-port="${p}"]`).value); const change = {}; if (enabled !== s.protocols[p].enabled) change.enabled = enabled; if (port !== s.protocols[p].port) change.port = port; if (Object.keys(change).length) protocols[p] = change; }
  for (const p of APPLE) { const enabled = document.querySelector(`[data-apple="${p}"]`).checked; if (enabled !== Boolean((s.protocols[p] || {}).enabled)) protocols[p] = { enabled }; }
  if (Object.keys(protocols).length) patch.protocols = protocols;
  const sites = $('#set-sites').checked; if (sites !== s.site_stats) patch.site_stats = sites;
  for (const [key, id] of [['history_days', '#set-history-days'], ['site_days', '#set-site-days'], ['history_max_mb', '#set-history-mb']]) { const v = Number($(id).value); if (v && v !== s[key]) patch[key] = v; }
  if (!Object.keys(patch).length) { notice('Nothing changed.'); return; }
  if (patch.site_stats === false && !confirm('Turning top services off deletes every recorded site. Continue?')) return;
  try { await api('PATCH', '/server', patch); notice(patch.hostname ? 'Saved. New keys use the new address; keys already shared keep the old one.' : 'Settings saved.'); await loadSettings(); }
  catch (error) { notice(error.message, true); }
});

// --- shell ---
function confirmAction(title, text, label, action) {
  $('#confirm-title').textContent = title; $('#confirm-text').textContent = text; $('#confirm-yes').textContent = label;
  state.confirm = action; $('#confirm-dialog').showModal();
}
$('#confirm-yes').addEventListener('click', async () => { $('#confirm-dialog').close(); const action = state.confirm; state.confirm = null; try { if (action) await action(); await loadUsers(); } catch (error) { notice(error.message, true); } });
document.querySelectorAll('dialog [data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
async function show(view) {
  state.view = view; notice('');
  document.querySelectorAll('.nav').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  for (const v of ['overview', 'users', 'rules', 'settings']) $(`#view-${v}`).hidden = v !== view;
  try {
    if (view === 'overview') await loadOverview();
    if (view === 'users') await loadUsers();
    if (view === 'rules') await loadGlobalRules();
    if (view === 'settings') await loadSettings();
  } catch (error) { notice(error.message, true); }
}
document.querySelectorAll('.nav').forEach(n => n.addEventListener('click', () => show(n.dataset.view)));
$('#user-add').addEventListener('click', () => openUser(null));
$('#signout').addEventListener('click', async () => { await fetch('/logout', { method: 'POST', credentials: 'same-origin' }); showSignin('Signed out.'); });

(async () => {
  if (!await signin()) return;
  $('#server-name').textContent = state.server.name;
  $('#server-address').textContent = `${state.server.hostname} · version ${state.server.version}`;
  await show('overview'); refreshLive(); setInterval(refreshLive, 2000);
})();
