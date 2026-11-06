/* Servers I run: administration of Ghostlink servers through the local service. Management keys
   go straight to the service, which seals them; access keys are fetched only when a key list is
   open and are dropped when it closes. */
'use strict';
const PROTOCOL_ORDER = ['amneziawg', 'wireguard', 'vless', 'shadowsocks'];
const protocolsInOrder = protocols => PROTOCOL_ORDER.filter(protocol => protocols[protocol]).map(protocol => [protocol, protocols[protocol]]);
const PROTOCOL_NAMES = { amneziawg: 'AmneziaWG', wireguard: 'WireGuard', vless: 'VLESS with REALITY', shadowsocks: 'Shadowsocks (Outline)', ikev2: 'IKEv2 (iPhone, iPad, Mac)', ipsec: 'IPsec (iPhone, iPad, Mac; legacy)' };
// Apple's built-in VPN types: installed with a configuration profile, never used on this device.
const APPLE_PROTOCOLS = ['ikev2', 'ipsec'];
const AUTH_METHODS = { ikev2: [['eap', 'Username and password'], ['certificate', 'Certificate']], ipsec: [['certificate', 'Certificate'], ['psk', 'Shared group key (weak)']] };
const AUTH_NAMES = { eap: 'username and password', certificate: 'certificate', psk: 'shared group key' };
const manageState = { servers: [], current: null, info: null, users: [], rules: null, editingUser: null, keysUser: null, rulesUser: null, confirm: null, live: {}, statsUser: null, polling: false };
const serverCall = op => request({ type: 'server_call', server: manageState.current, op });
const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
// Data limits are decimal gigabytes, so usage is shown the same way.
function formatData(bytes) {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(bytes >= 1e11 ? 0 : 1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${Math.round(bytes / 1e3)} KB`;
}
const hasRules = rules => rules.blocked_domains.length + rules.blocked_ips.length + rules.blocked_ports.length > 0 || rules.block_bittorrent || rules.block_smtp;
function rulesSummary(rules) {
  const parts = [];
  if (rules.blocked_domains.length) parts.push(plural(rules.blocked_domains.length, 'site'));
  if (rules.blocked_ips.length) parts.push(plural(rules.blocked_ips.length, 'IP range'));
  if (rules.blocked_ports.length) parts.push(plural(rules.blocked_ports.length, 'port rule'));
  if (rules.block_bittorrent) parts.push('BitTorrent');
  if (rules.block_smtp) parts.push('outgoing mail');
  return parts.length ? `Blocked for everyone: ${parts.join(', ')}.` : 'Nothing is blocked beyond the built-in protections.';
}
function formError(id, error) { $(id).textContent = error ? error.message : ''; $(id).hidden = !error; }

function showManagedHome() { $('#managed-home').hidden = false; $('#managed-page').hidden = true; manageState.current = null; manageState.info = null; }
async function loadManaged() {
  showManagedHome();
  try { manageState.servers = (await request({ type: 'managed_server_list' })).servers; }
  catch (error) { notice(error.message); manageState.servers = []; }
  const list = $('#managed-list'); list.replaceChildren();
  $('#managed-empty').hidden = manageState.servers.length !== 0;
  for (const server of manageState.servers) {
    const card = el('article', 'server-card');
    const head = el('div', 'server-head');
    head.append(el('div', 'server-avatar', server.server_name.slice(0, 2).toUpperCase()));
    const identity = el('div', 'server-identity');
    identity.append(el('h3', '', server.server_name), el('div', 'endpoint', server.endpoint));
    head.append(identity);
    const footer = el('div', 'server-footer');
    footer.append(el('span', 'server-status', server.version ? `Ghostlink server ${server.version}` : 'Ghostlink server'));
    const open = el('button', 'connect-button', 'MANAGE'); open.type = 'button';
    open.addEventListener('click', () => openManaged(server.name));
    footer.append(open); card.append(head, footer); list.append(card);
  }
}
async function openManaged(name) {
  manageState.current = name;
  $('#managed-home').hidden = true; $('#managed-page').hidden = false;
  $('#managed-title').textContent = 'Loading…'; $('#managed-endpoint').textContent = ''; $('#managed-protocols').textContent = '';
  $('#user-list').replaceChildren();
  await reloadManaged();
}
async function reloadManaged() {
  const name = manageState.current;
  try {
    // Reading metrics first brings each user's usage up to date.
    await serverCall({ op: 'metrics' });
    const [info, users, rules] = await Promise.all([serverCall({ op: 'info' }), serverCall({ op: 'users_list' }), serverCall({ op: 'rules_get' })]);
    if (manageState.current !== name) return;
    Object.assign(manageState, { info, users, rules });
    renderManaged();
    if (!$('#mesh-dialog').open) loadMeshCard();
  } catch (error) {
    notice(error.message);
    if (!manageState.info) showManagedHome();
  }
}
function renderManaged() {
  setTimeout(paintLive, 0);
  const { info, users, rules } = manageState;
  $('#managed-title').textContent = info.name;
  $('#managed-endpoint').textContent = `${info.hostname} · VERSION ${info.version}`.toUpperCase();
  const apple = APPLE_PROTOCOLS.filter(protocol => info.protocols[protocol] && info.protocols[protocol].enabled).map(protocol => `${PROTOCOL_NAMES[protocol]}: UDP 500/4500`);
  $('#managed-protocols').textContent = [...protocolsInOrder(info.protocols).map(([protocol, value]) => `${PROTOCOL_NAMES[protocol] || protocol}: ${value.enabled ? `port ${value.port}` : 'off'}`), ...apple].join(' · ');
  $('#global-rules-summary').textContent = rulesSummary(rules);
  $('#user-count').textContent = users.length;
  $('#usage-total').textContent = `${formatData(users.reduce((total, user) => total + user.usage_bytes, 0))} used in total`;
  const list = $('#user-list'); list.replaceChildren();
  if (!users.length) list.append(el('p', 'quiet', 'No users yet. Add one, then create a key for them.'));
  for (const user of users) {
    const row = el('div', 'user-row');
    const who = el('div', 'who'); const title = el('h3', '', user.name);
    title.append(user.over_limit ? el('span', 'chip warn', 'LIMIT REACHED') : user.enabled ? el('span', 'chip', 'ACTIVE') : el('span', 'chip off', 'PAUSED'));
    who.append(title, el('div', 'usage', user.data_limit_bytes ? `${formatData(user.usage_bytes)} of ${formatData(user.data_limit_bytes)}` : `${formatData(user.usage_bytes)} used · no limit`));
    if (user.data_limit_bytes) {
      const meter = el('div', 'meter'); const fill = el('span');
      fill.style.width = `${Math.min(100, (user.usage_bytes / user.data_limit_bytes) * 100)}%`;
      meter.append(fill); who.append(meter);
    }
    const notes = [plural(user.keys.length, 'key')];
    if (hasRules(user.rules)) notes.push('own rules');
    if (user.exempt_from_global_rules) notes.push('not affected by rules for everyone');
    who.append(el('div', 'usage', notes.join(' · ')));
    const live = el('div', 'usage live'); live.dataset.live = user.id; who.append(live);
    const actions = el('div', 'actions');
    const buttons = [
      ['Keys', 'primary', () => openKeys(user)],
      ['Stats', 'secondary', () => openStats(user)],
      ['Edit', 'secondary', () => openUser(user)],
      ['Rules', 'secondary', () => openRules(user)],
      ['Remove', 'secondary', () => confirmAction(`Remove ${user.name}?`, 'Their keys stop working immediately. This cannot be undone.', 'Remove user', () => serverCall({ op: 'user_delete', user: user.id }))],
    ];
    for (const [label, className, handler] of buttons) {
      const button = el('button', className, label); button.type = 'button'; button.addEventListener('click', handler); actions.append(button);
    }
    row.append(who, actions); list.append(row);
  }
}
function confirmAction(title, caption, label, action, after = reloadManaged) {
  $('#confirm-title').textContent = title; $('#confirm-caption').textContent = caption; $('#confirm-yes').textContent = label;
  manageState.confirm = async () => {
    try { await action(); await after(); } catch (error) { notice(error.message); }
  };
  $('#confirm-dialog').showModal();
}
$('#confirm-yes').addEventListener('click', async () => { $('#confirm-dialog').close(); const run = manageState.confirm; manageState.confirm = null; if (run) await run(); });

// --- adding a server ---
function showSetupHelp() {
  const version = appState.info?.version || '';
  $('#detail-title').textContent = 'Set up a Ghostlink server';
  const steps = [
    'You need a Linux machine (Debian/Ubuntu or Fedora/RHEL) with Docker, reachable from the internet.',
    `1. Download ghostlink-server_${version}-1_amd64.deb (or arm64), or ghostlink-server-${version}-1.x86_64.rpm, from the Ghostlink ${version} release.`,
    '2. Install it with sudo apt install ./ghostlink-server_… .deb (or sudo dnf install ./ghostlink-server-… .rpm). This loads the bundled container image and starts the server.',
    '3. Copy the management key it prints. Show it again any time with: sudo ghostlink-server show-key',
    '4. Choose Add server here and paste it.',
    '5. Allow the server ports in its firewall or cloud security group; sudo ghostlink-server status lists them.',
  ];
  const content = el('div');
  for (const step of steps) content.append(el('p', 'field-note', step));
  $('#detail-content').replaceChildren(content); $('#detail-dialog').showModal();
}
$('#setup-server').addEventListener('click', showSetupHelp);
$('#managed-empty-setup').addEventListener('click', showSetupHelp);
$('#add-managed').addEventListener('click', () => { formError('#managed-error'); $('#managed-dialog').showModal(); $('#managed-name').focus(); });
$('#managed-dialog').addEventListener('close', () => { $('#managed-key').value = ''; });
$('#managed-form').addEventListener('submit', async event => {
  event.preventDefault();
  let managementKey = $('#managed-key').value.trim();
  const name = slug($('#managed-name').value.trim()).slice(0, 40);
  $('#managed-save').disabled = true; $('#managed-save').textContent = 'Checking the server…'; formError('#managed-error');
  try {
    await request({ type: 'managed_server_add', name, management_key: managementKey });
    managementKey = ''; $('#managed-key').value = ''; $('#managed-name').value = '';
    $('#managed-dialog').close(); notice('Server added. Its management key is sealed in the local service.', true);
    await loadManaged();
  } catch (error) { formError('#managed-error', error); }
  finally { managementKey = ''; $('#managed-save').disabled = false; $('#managed-save').textContent = 'Add server'; }
});
$('#managed-back').addEventListener('click', loadManaged);
$('#managed-forget').addEventListener('click', () => confirmAction('Forget this server?', 'Ghostlink removes its management key from this device. The server, its users and their keys keep working. You need the key to add it again.', 'Forget server', () => request({ type: 'managed_server_remove', name: manageState.current }), loadManaged));

// --- users ---
function openUser(user) {
  manageState.editingUser = user;
  $('#user-scope').textContent = (manageState.info?.name || '').toUpperCase();
  $('#user-heading').textContent = user ? `Edit ${user.name}` : 'Add user';
  $('#user-name').value = user?.name || '';
  $('#user-limit').value = user?.data_limit_bytes ? String(user.data_limit_bytes / 1e9) : '';
  $('#user-enabled').checked = user ? user.enabled : true;
  $('#user-exempt').checked = Boolean(user?.exempt_from_global_rules);
  $('#user-reset').checked = false;
  $('#user-enabled-row').hidden = !user; $('#user-reset-row').hidden = !user;
  formError('#user-error'); $('#user-dialog').showModal(); $('#user-name').focus();
}
$('#user-add').addEventListener('click', () => openUser(null));
$('#user-form').addEventListener('submit', async event => {
  event.preventDefault();
  const user = manageState.editingUser;
  const limit = $('#user-limit').value.trim();
  const change = { name: $('#user-name').value.trim(), exempt_from_global_rules: $('#user-exempt').checked };
  if (limit !== '' || user) change.data_limit_bytes = Math.round(Number(limit || 0) * 1e9);
  if (user) { change.enabled = $('#user-enabled').checked; if ($('#user-reset').checked) change.reset_usage = true; }
  try {
    await serverCall(user ? { op: 'user_update', user: user.id, change } : { op: 'user_create', change });
    $('#user-dialog').close(); await reloadManaged();
  } catch (error) { formError('#user-error', error); }
});

// --- keys ---
async function openKeys(user) {
  manageState.keysUser = user;
  $('#keys-heading').textContent = `Keys for ${user.name}`;
  $('#key-here').checked = false; formError('#keys-error');
  for (const id of ['#key-address', '#key-local-id', '#key-remote-id']) $(id).value = '';
  keyFormChanged();
  $('#key-list').replaceChildren(el('p', 'quiet', 'Loading keys…'));
  $('#keys-dialog').showModal();
  await loadKeys();
}
async function loadKeys() {
  const user = manageState.keysUser;
  try { renderKeys(await serverCall({ op: 'keys_list', user: user.id })); }
  catch (error) { formError('#keys-error', error); $('#key-list').replaceChildren(); }
}
function useHere(user, key) {
  return request({ type: 'access_key_import', name: uniqueName(slug(`${user.name}-${key.protocol}`)), access_key: key.access_key });
}
function renderKeys(keys) {
  const user = manageState.keysUser;
  const list = $('#key-list'); list.replaceChildren();
  if (!keys.length) list.append(el('p', 'quiet', 'No keys yet. Create one below.'));
  for (const key of keys) {
    const row = el('div', 'key-row');
    const what = el('div', 'what', PROTOCOL_NAMES[key.protocol] || key.protocol);
    what.append(el('small', '', `Created ${new Date(key.created_unix * 1000).toLocaleDateString()}`));
    row.append(what);
    const buttons = [];
    if (APPLE_PROTOCOLS.includes(key.protocol)) {
      what.append(el('small', '', `${AUTH_NAMES[key.auth] || key.auth} · ${key.identity} · ${key.server_address}`));
      buttons.push(['Save iPhone/Mac profile', () => saveProfile(user, key, false)]);
      if (key.auth === 'certificate') buttons.push(['Profile without password', () => saveProfile(user, key, true)]);
    } else {
      buttons.push(['QR code', () => showQR(user, key, key.config ? 'conf' : 'key')]);
      if (key.config) buttons.push(['QR (vpn://)', () => showQR(user, key, 'key')]);
      buttons.push(['Copy key', () => navigator.clipboard.writeText(key.access_key).then(() => notice('Key copied. Share it only with the person it belongs to.', true))]);
      if (key.config) buttons.push(['Copy .conf', () => navigator.clipboard.writeText(key.config).then(() => notice('Configuration copied for WireGuard or AmneziaWG apps.', true))]);
      buttons.push(['Use on this device', async () => { await useHere(user, key); await refresh(); notice('Saved under My servers on this device.', true); }]);
    }
    buttons.push(['Remove', () => { $('#keys-dialog').close(); confirmAction(`Remove this ${PROTOCOL_NAMES[key.protocol] || key.protocol} key?`, 'Anyone using it is disconnected and cannot reconnect.', 'Remove key', () => serverCall({ op: 'key_delete', user: user.id, key: key.id })); }]);
    for (const [label, handler] of buttons) {
      const button = el('button', 'secondary', label); button.type = 'button';
      button.addEventListener('click', async () => { formError('#keys-error'); try { await handler(); } catch (error) { formError('#keys-error', error); } });
      row.append(button);
    }
    list.append(row);
  }
}
$('#keys-dialog').addEventListener('close', () => { $('#key-list').replaceChildren(); reloadManaged(); });
// Protocol-specific fields for IKEv2/IPsec keys.
function keyFormChanged() {
  const protocol = $('#key-protocol').value; const apple = APPLE_PROTOCOLS.includes(protocol);
  $('#key-apple').hidden = !apple;
  $('#key-here').closest('label').hidden = apple;
  if (!apple) return;
  const auth = $('#key-auth'); const previous = auth.value; auth.replaceChildren();
  for (const [value, label] of AUTH_METHODS[protocol]) { const option = el('option', '', label); option.value = value; auth.append(option); }
  if (AUTH_METHODS[protocol].some(([value]) => value === previous)) auth.value = previous;
  $('#key-remote-id').closest('label').hidden = protocol !== 'ikev2';
  $('#key-psk-warning').hidden = auth.value !== 'psk';
}
$('#key-protocol').addEventListener('change', keyFormChanged);
$('#key-auth').addEventListener('change', keyFormChanged);
$('#key-create-form').addEventListener('submit', async event => {
  event.preventDefault();
  const user = manageState.keysUser; const protocol = $('#key-protocol').value;
  const op = { op: 'key_create', user: user.id, protocol };
  if (APPLE_PROTOCOLS.includes(protocol)) {
    op.auth = $('#key-auth').value;
    for (const [field, id] of [['server_address', '#key-address'], ['local_identifier', '#key-local-id'], ['remote_identifier', '#key-remote-id']]) {
      const value = $(id).value.trim();
      if (value && !(field === 'remote_identifier' && protocol !== 'ikev2')) op[field] = value;
    }
  } else if ($('#key-here').checked) op.import_as = uniqueName(slug(`${user.name}-${protocol}`));
  formError('#keys-error');
  try {
    const created = await serverCall(op);
    if (created.warning) notice(created.warning);
    if (created.import_error) formError('#keys-error', new Error(`The key was created, but saving it here failed: ${created.import_error}`));
    else if (created.imported) { notice('Key created and saved under My servers on this device.', true); await refresh(); }
    await loadKeys();
  } catch (error) { formError('#keys-error', error); }
});

// --- rules ---
function openRules(user) {
  manageState.rulesUser = user;
  const rules = user ? user.rules : manageState.rules;
  $('#rules-scope').textContent = user ? `ONLY FOR ${user.name.toUpperCase()}` : 'EVERYONE ON THIS SERVER';
  $('#rules-sites').value = rules.blocked_domains.join('\n');
  $('#rules-ips').value = rules.blocked_ips.join('\n');
  $('#rules-ports').value = rules.blocked_ports.join('\n');
  $('#rules-bittorrent').checked = rules.block_bittorrent; $('#rules-smtp').checked = rules.block_smtp;
  formError('#rules-error'); $('#rules-dialog').showModal();
}
$('#global-rules-edit').addEventListener('click', () => openRules(null));
$('#rules-form').addEventListener('submit', async event => {
  event.preventDefault();
  const user = manageState.rulesUser;
  const rules = { blocked_domains: lines($('#rules-sites').value), blocked_ips: lines($('#rules-ips').value), blocked_ports: lines($('#rules-ports').value), block_bittorrent: $('#rules-bittorrent').checked, block_smtp: $('#rules-smtp').checked };
  try {
    await serverCall(user ? { op: 'user_update', user: user.id, change: { rules } } : { op: 'rules_set', rules });
    $('#rules-dialog').close(); await reloadManaged();
  } catch (error) { formError('#rules-error', error); }
});

// --- server settings ---
$('#managed-settings').addEventListener('click', () => {
  const info = manageState.info; if (!info) return;
  $('#settings-name').value = info.name; $('#settings-hostname').value = info.hostname; $('#settings-reality').value = info.vless_handshake;
  $('#settings-sites').checked = Boolean(info.site_stats); $('#settings-history-days').value = info.history_days || 90; $('#settings-site-days').value = info.site_days || 30; $('#settings-history-mb').value = info.history_max_mb || 20;
  const grid = $('#settings-protocols'); grid.replaceChildren();
  for (const [protocol, value] of protocolsInOrder(info.protocols)) {
    const label = el('label', 'check'); const box = el('input'); box.type = 'checkbox'; box.checked = value.enabled; box.dataset.protocol = protocol;
    label.append(box, document.createTextNode(` ${PROTOCOL_NAMES[protocol] || protocol}`));
    const port = el('input'); port.type = 'number'; port.min = '1'; port.max = '65535'; port.value = value.port; port.dataset.port = protocol;
    port.setAttribute('aria-label', `${PROTOCOL_NAMES[protocol] || protocol} port`);
    grid.append(label, port);
  }
  for (const protocol of APPLE_PROTOCOLS.filter(protocol => info.protocols[protocol])) {
    const label = el('label', 'check'); const box = el('input'); box.type = 'checkbox'; box.checked = info.protocols[protocol].enabled; box.dataset.apple = protocol;
    label.append(box, document.createTextNode(` ${PROTOCOL_NAMES[protocol]}`));
    grid.append(label, el('span', 'hint', 'UDP 500, 4500'));
  }
  const component = info.ipsec_component || {};
  $('#settings-ipsec').textContent = component.running
    ? `IPsec component running, ${component.connections || 0} connected.${component.error ? ` Problem: ${component.error}` : ''}`
    : 'IKEv2/IPsec (built-in VPN of iPhone, iPad and Mac) needs the IPsec component. Start it on the server with: sudo ghostlink-server ipsec enable';
  formError('#settings-error'); $('#server-settings-dialog').showModal();
});
$('#server-settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const info = manageState.info; const patch = {}; const protocols = {};
  const name = $('#settings-name').value.trim(), hostname = $('#settings-hostname').value.trim(), reality = $('#settings-reality').value.trim();
  if (name !== info.name) patch.name = name;
  if (hostname !== info.hostname) patch.hostname = hostname;
  if (reality !== info.vless_handshake) patch.vless_handshake = reality;
  const sites = $('#settings-sites').checked;
  if (sites !== Boolean(info.site_stats)) patch.site_stats = sites;
  for (const [key, id] of [['history_days', '#settings-history-days'], ['site_days', '#settings-site-days'], ['history_max_mb', '#settings-history-mb']]) {
    const value = Number($(id).value);
    if (value && value !== info[key]) patch[key] = value;
  }
  for (const [protocol, value] of protocolsInOrder(info.protocols)) {
    const enabled = document.querySelector(`[data-protocol="${protocol}"]`).checked;
    const port = Number(document.querySelector(`[data-port="${protocol}"]`).value);
    const change = {};
    if (enabled !== value.enabled) change.enabled = enabled;
    if (port !== value.port) change.port = port;
    if (Object.keys(change).length) protocols[protocol] = change;
  }
  for (const protocol of APPLE_PROTOCOLS.filter(protocol => info.protocols[protocol])) {
    const enabled = document.querySelector(`[data-apple="${protocol}"]`).checked;
    if (enabled !== info.protocols[protocol].enabled) protocols[protocol] = { enabled };
  }
  if (Object.keys(protocols).length) patch.protocols = protocols;
  try {
    if (Object.keys(patch).length) await serverCall({ op: 'update', patch });
    $('#server-settings-dialog').close();
    if (patch.hostname) notice('Saved. New keys use the new address; keys you already shared keep the old one.', true);
    await reloadManaged();
  } catch (error) { formError('#settings-error', error); }
});

// --- live monitoring ---
function formatSpeed(bytesPerSecond) {
  const bits = (Number(bytesPerSecond) || 0) * 8;
  if (bits >= 1e9) return (bits / 1e9).toFixed(2) + ' Gbit/s';
  if (bits >= 1e6) return (bits / 1e6).toFixed(1) + ' Mbit/s';
  if (bits >= 1e3) return Math.round(bits / 1e3) + ' kbit/s';
  return Math.round(bits) + ' bit/s';
}
const svgNode = (tag, attrs) => { const node = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v); return node; };
function liveVisible() { return Boolean(manageState.current) && !$('#manage-view').hidden && !$('#managed-page').hidden && appState.available; }
function paintLive() {
  for (const node of document.querySelectorAll('[data-live]')) {
    const live = manageState.live[node.dataset.live];
    node.replaceChildren();
    const dot = el('span', 'online-dot' + (live && live.online ? ' on' : ''));
    node.append(dot, document.createTextNode(live && live.online ? `online · ↓ ${formatSpeed(live.down_bps)} ↑ ${formatSpeed(live.up_bps)}` : 'offline'));
  }
}
async function pollLive() {
  if (!liveVisible() || manageState.polling) return;
  manageState.polling = true;
  try {
    const live = await serverCall({ op: 'live' });
    manageState.live = Object.fromEntries(live.users.map(u => [u.id, u]));
    $('#live-down').textContent = formatSpeed(live.down_bps);
    $('#live-up').textContent = formatSpeed(live.up_bps);
    $('#live-online').textContent = `${live.online_users} of ${live.users.length}`;
    const h = live.health || {};
    $('#live-health').textContent = h.cpu_percent !== undefined ? `CPU ${h.cpu_percent.toFixed(0)}%` + (h.detail_paused ? ' · disk full' : '') : (h.detail_paused ? 'disk nearly full' : 'running');
    const chart = $('#live-chart'); chart.replaceChildren();
    const series = live.series || [];
    if (series.length > 1) {
      const top = Math.max(1, ...series.flatMap(p => [p.up, p.down]));
      for (const key of ['down', 'up']) {
        const points = series.map((p, i) => `${(i / (series.length - 1) * 600).toFixed(1)},${(68 - p[key] / top * 64).toFixed(1)}`).join(' ');
        chart.append(svgNode('polyline', { points, class: key }));
      }
    }
    paintLive();
  } catch {}
  finally { manageState.polling = false; }
}
setInterval(pollLive, 2000);

// --- statistics ---
function hbars(target, items, empty) {
  target.replaceChildren();
  if (!items || !items.length) { target.append(el('p', 'field-note', empty || 'Nothing recorded yet.')); return; }
  const wrap = el('div', 'hbars'); const top = Math.max(...items.map(i => i.bytes), 1);
  for (const item of items) {
    const row = el('div', 'hbar'); const track = el('div', 'track'); const fill = el('span', 'fill');
    fill.style.width = (item.bytes / top * 100).toFixed(1) + '%'; track.append(fill);
    row.append(el('span', '', PROTOCOL_NAMES[item.label] || item.label), track, el('span', '', formatData(item.bytes)));
    wrap.append(row);
  }
  target.append(wrap);
}
function openStats(user) {
  manageState.statsUser = user;
  $('#stats-scope').textContent = user ? `ONLY ${user.name.toUpperCase()}` : 'EVERYONE ON THIS SERVER';
  $('#stats-heading').textContent = user ? `Statistics · ${user.name}` : 'Traffic statistics';
  $('#stats-dialog').showModal();
  loadStats();
}
async function loadStats() {
  const user = manageState.statsUser; const range = $('#stats-range').value;
  try {
    const [stats, clients] = await Promise.all([
      serverCall(user ? { op: 'stats', user: user.id, range } : { op: 'stats', range }),
      serverCall(user ? { op: 'clients', user: user.id } : { op: 'clients' }),
    ]);
    const chart = $('#stats-chart'); chart.replaceChildren();
    const series = stats.series || [];
    let up = 0, down = 0;
    if (series.length) {
      const top = Math.max(...series.map(b => b.up + b.down), 1); const width = 600 / series.length;
      series.forEach((b, i) => {
        up += b.up; down += b.down;
        const d = b.down / top * 128, u = b.up / top * 128;
        chart.append(svgNode('rect', { x: i * width + 1, y: 138 - d - u, width: Math.max(width - 2, 1), height: d, class: 'bar-down' }));
        chart.append(svgNode('rect', { x: i * width + 1, y: 138 - u, width: Math.max(width - 2, 1), height: u, class: 'bar-up' }));
      });
    } else {
      const text = svgNode('text', { x: 6, y: 70 }); text.textContent = 'No traffic recorded in this period'; chart.append(text);
    }
    $('#stats-total').textContent = `${formatData(down)} downloaded and ${formatData(up)} uploaded, shown per ${stats.unit}. History is kept for ${stats.retention.history_days} days.`;
    hbars($('#stats-types'), stats.types); hbars($('#stats-protocols'), stats.protocols);
    hbars($('#stats-sites'), stats.sites, stats.site_stats ? 'No sites recorded in this period.' : 'Top services are off. Turn them on in Server settings.');
    const people = $('#stats-people'); people.replaceChildren();
    if (!user && stats.users && stats.users.length) {
      people.append(el('h3', 'subhead', 'By user'));
      const box = el('div'); people.append(box);
      hbars(box, stats.users.map(u => ({ label: u.name, bytes: u.up + u.down })).filter(u => u.bytes > 0), 'No traffic in this period.');
    }
    const target = $('#stats-clients'); target.replaceChildren();
    if (!clients.clients.length) { target.append(el('p', 'field-note', 'No connections recorded in the last 30 days.')); return; }
    const table = el('table', 'client-table'); const head = el('tr');
    for (const title of [user ? '' : 'User', 'Address', 'Protocol', 'Last seen'].filter(Boolean)) head.append(el('th', '', title));
    table.append(head);
    for (const c of clients.clients.slice(0, 50)) {
      const row = el('tr');
      if (!user) row.append(el('td', '', c.name));
      row.append(el('td', '', c.ip), el('td', '', PROTOCOL_NAMES[c.protocol] || c.protocol), el('td', '', new Date(c.last_unix * 1000).toLocaleString()));
      table.append(row);
    }
    target.append(table);
  } catch (error) { notice(error.message); }
}
$('#stats-range').addEventListener('change', loadStats);
$('#server-stats').addEventListener('click', () => openStats(null));

// --- QR codes and connection kits ---
async function showQR(user, key, content) {
  const svg = await serverCall({ op: 'key_qr', user: user.id, key: key.id, format: 'svg', content });
  $('#qr-image').src = 'data:image/svg+xml;base64,' + btoa(svg);
  $('#qr-heading').textContent = `${PROTOCOL_NAMES[key.protocol] || key.protocol} · ${user.name}`;
  $('#qr-note').textContent = content === 'conf' ? 'Scan with the WireGuard or AmneziaWG app: + then Scan from QR code.'
    : key.protocol === 'shadowsocks' ? 'Scan with Outline, Shadowrocket or v2rayNG.'
    : key.protocol === 'vless' ? 'Scan with v2rayNG, Hiddify, Streisand or Shadowrocket.' : 'Scan with the AmneziaVPN app.';
  $('#qr-dialog').showModal();
}
$('#qr-dialog').addEventListener('close', () => $('#qr-image').removeAttribute('src'));
// Apple configuration profiles install IKEv2/IPsec in Settings and keep the password or
// certificate in the device's Keychain.
async function saveProfile(user, key, promptPassword) {
  const profile = await serverCall({ op: 'key_profile', user: user.id, key: key.id, prompt_password: promptPassword, on_demand: false });
  const saved = await nativeInvoke('save_download', { name: `${user.name}-${key.protocol}-${key.id}`, content: profile, extension: 'mobileconfig' });
  notice(promptPassword
    ? `Profile saved as ${saved}, without the certificate password. Give ${user.name} the password separately; the device asks for it when installing: ${key.certificate_password}`
    : `Profile saved as ${saved}. Send it privately (AirDrop, Mail or Files); opening it on the iPhone, iPad or Mac installs the VPN.`, true);
}
$('#kit-save').addEventListener('click', async () => {
  const user = manageState.keysUser; formError('#keys-error');
  try {
    const page = await serverCall({ op: 'kit', user: user.id });
    const saved = await nativeInvoke('save_download', { name: `${user.name}-vpn`, content: page });
    notice(`Connection kit for ${user.name} saved as ${saved}. Send it privately; it contains their keys.`, true);
  } catch (error) { formError('#keys-error', error); }
});
