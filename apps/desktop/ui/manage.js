/* Servers I run: administration of Ghostlink servers through the local service. Management keys
   go straight to the service, which seals them; access keys are fetched only when a key list is
   open and are dropped when it closes. */
'use strict';
const PROTOCOL_ORDER = ['amneziawg', 'wireguard', 'vless', 'shadowsocks'];
const protocolsInOrder = protocols => PROTOCOL_ORDER.filter(protocol => protocols[protocol]).map(protocol => [protocol, protocols[protocol]]);
const PROTOCOL_NAMES = { amneziawg: 'AmneziaWG', wireguard: 'WireGuard', vless: 'VLESS with REALITY', shadowsocks: 'Shadowsocks (Outline)' };
const manageState = { servers: [], current: null, info: null, users: [], rules: null, editingUser: null, keysUser: null, rulesUser: null, confirm: null };
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
  } catch (error) {
    notice(error.message);
    if (!manageState.info) showManagedHome();
  }
}
function renderManaged() {
  const { info, users, rules } = manageState;
  $('#managed-title').textContent = info.name;
  $('#managed-endpoint').textContent = `${info.hostname} · VERSION ${info.version}`.toUpperCase();
  $('#managed-protocols').textContent = protocolsInOrder(info.protocols).map(([protocol, value]) => `${PROTOCOL_NAMES[protocol] || protocol}: ${value.enabled ? `port ${value.port}` : 'off'}`).join(' · ');
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
    const actions = el('div', 'actions');
    const buttons = [
      ['Keys', 'primary', () => openKeys(user)],
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
    const buttons = [['Copy key', () => navigator.clipboard.writeText(key.access_key).then(() => notice('Key copied. Share it only with the person it belongs to.', true))]];
    if (key.config) buttons.push(['Copy .conf', () => navigator.clipboard.writeText(key.config).then(() => notice('Configuration copied for WireGuard or AmneziaWG apps.', true))]);
    buttons.push(['Use on this device', async () => { await useHere(user, key); await refresh(); notice('Saved under My servers on this device.', true); }]);
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
$('#key-create-form').addEventListener('submit', async event => {
  event.preventDefault();
  const user = manageState.keysUser; const protocol = $('#key-protocol').value;
  const op = { op: 'key_create', user: user.id, protocol };
  if ($('#key-here').checked) op.import_as = uniqueName(slug(`${user.name}-${protocol}`));
  formError('#keys-error');
  try {
    const created = await serverCall(op);
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
  const grid = $('#settings-protocols'); grid.replaceChildren();
  for (const [protocol, value] of protocolsInOrder(info.protocols)) {
    const label = el('label', 'check'); const box = el('input'); box.type = 'checkbox'; box.checked = value.enabled; box.dataset.protocol = protocol;
    label.append(box, document.createTextNode(` ${PROTOCOL_NAMES[protocol] || protocol}`));
    const port = el('input'); port.type = 'number'; port.min = '1'; port.max = '65535'; port.value = value.port; port.dataset.port = protocol;
    port.setAttribute('aria-label', `${PROTOCOL_NAMES[protocol] || protocol} port`);
    grid.append(label, port);
  }
  formError('#settings-error'); $('#server-settings-dialog').showModal();
});
$('#server-settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const info = manageState.info; const patch = {}; const protocols = {};
  const name = $('#settings-name').value.trim(), hostname = $('#settings-hostname').value.trim(), reality = $('#settings-reality').value.trim();
  if (name !== info.name) patch.name = name;
  if (hostname !== info.hostname) patch.hostname = hostname;
  if (reality !== info.vless_handshake) patch.vless_handshake = reality;
  for (const [protocol, value] of protocolsInOrder(info.protocols)) {
    const enabled = document.querySelector(`[data-protocol="${protocol}"]`).checked;
    const port = Number(document.querySelector(`[data-port="${protocol}"]`).value);
    const change = {};
    if (enabled !== value.enabled) change.enabled = enabled;
    if (port !== value.port) change.port = port;
    if (Object.keys(change).length) protocols[protocol] = change;
  }
  if (Object.keys(protocols).length) patch.protocols = protocols;
  try {
    if (Object.keys(patch).length) await serverCall({ op: 'update', patch });
    $('#server-settings-dialog').close();
    if (patch.hostname) notice('Saved. New keys use the new address; keys you already shared keep the old one.', true);
    await reloadManaged();
  } catch (error) { formError('#settings-error', error); }
});
