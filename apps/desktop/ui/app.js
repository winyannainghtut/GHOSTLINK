/* MyVPN desktop UI. Credentials are kept in memory only until private IPC import completes. */
'use strict';
const $ = selector => document.querySelector(selector);
const appState = { profiles: [], connection: null, info: null, refreshing: false, busy: false, selected: null, available: false, renderedServers: null };
const nativeInvoke = window.__TAURI__?.core?.invoke;
const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };

async function request(action) {
  if (!nativeInvoke) throw new Error('Open the installed MyVPN desktop app to use the local VPN service.');
  let response;
  try { response = await nativeInvoke('vpn_request', { action }); }
  catch { throw new Error('The desktop app could not reach the local VPN service.'); }
  if (!response.success) throw new Error(response.error?.message || 'The VPN service could not complete this request.');
  return response.data;
}
function notice(message) { $('#notice').textContent = message; $('#notice').hidden = !message; }
function formatBytes(bytes) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`; if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`; return `${(bytes / 1073741824).toFixed(1)} GB`; }
function formatTime(seconds) { return [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60].map(x => String(x).padStart(2, '0')).join(':'); }
const stateLabel = state => ({ connected: 'Connected', connecting: 'Connecting…', reconnecting: 'Reconnecting…', disconnecting: 'Disconnecting…', failed: 'Connection failed', disconnected: 'Disconnected' }[state] || 'Disconnected');

async function refresh() {
  if (appState.refreshing) return;
  appState.refreshing = true;
  try {
    const [profiles, info] = await Promise.all([request({ type: 'profile_list' }), request({ type: 'info' })]);
    appState.profiles = profiles.profiles; appState.info = info; appState.connection = info.connection;
    if (!appState.available) notice('');
    appState.available = true;
    $('#autoconnect').checked = info.autoconnect;
    render();
  } catch (error) {
    appState.available = false;
    $('#connection-state').textContent = 'VPN service unavailable';
    $('#connection-caption').textContent = 'Start the installed MyVPN service, then try again.';
    $('#duration').textContent = '—'; $('#traffic').textContent = '—';
    notice(error.message); renderServers();
  } finally { appState.refreshing = false; }
}
function render() {
  const status = appState.connection;
  $('#connection-state').textContent = status.status === 'connected' ? 'You’re connected.' : status.status === 'disconnected' ? 'Ready when you are.' : stateLabel(status.status);
  const server = appState.profiles.find(profile => profile.name === status.profile);
  $('#connection-caption').textContent = status.status === 'connected' ? `Connected through ${server?.display_name || server?.name || 'your server'}.` : status.status === 'disconnected' ? 'Choose a server below to start your connection.' : status.status === 'failed' ? 'Could not establish a connection. Check your key and service diagnostics.' : `Connecting to ${server?.display_name || server?.name || 'your server'}…`;
  $('#duration').textContent = status.status === 'connected' ? formatTime(status.connected_duration_seconds) : '—';
  $('#traffic').textContent = status.status === 'connected' ? `${formatBytes(status.bytes_received)} / ${formatBytes(status.bytes_sent)}` : '—';
  renderServers();
}
function renderServers() {
  const query = $('#search').value.trim().toLowerCase();
  // Status polling must not replace focused controls or dismiss an open server menu.
  const signature = JSON.stringify([appState.profiles, appState.connection?.profile, appState.connection?.status, appState.busy, appState.available, query]);
  if (signature === appState.renderedServers) return;
  appState.renderedServers = signature;
  const profiles = appState.profiles.filter(profile => `${profile.display_name} ${profile.name} ${profile.remotes[0]?.host}`.toLowerCase().includes(query));
  $('#count').textContent = appState.profiles.length;
  const list = $('#server-list'); list.replaceChildren();
  $('#empty').hidden = appState.profiles.length !== 0;
  for (const profile of profiles) {
    const active = appState.connection?.profile === profile.name;
    const status = active ? appState.connection.status : 'disconnected';
    const card = el('article', `server-card${status === 'connected' ? ' is-connected' : ''}`);
    const head = el('div', 'server-head');
    const title = profile.display_name || profile.name;
    head.append(el('div', 'server-avatar', title.slice(0, 2).toUpperCase()));
    const identity = el('div', 'server-identity'); const heading = el('h3', '', title);
    if (profile.is_default) { const star = el('span', 'default-star', '★'); star.title = 'Default server'; heading.append(star); }
    identity.append(heading, el('div', 'endpoint', `${profile.remotes[0]?.host || 'Dynamic server'}:${profile.remotes[0]?.port || ''}`)); head.append(identity);
    const menuContainer = el('div', 'server-menu'); const toggle = el('button', 'menu-toggle', '⋮');
    toggle.setAttribute('aria-label', `Options for ${title}`); toggle.setAttribute('aria-expanded', 'false');
    const menu = el('div', 'card-menu'); menu.hidden = true;
    for (const [label, action] of [['Server details', () => showDetails(profile)], ['Rename', () => rename(profile)], ['Make default', () => mutate({type:'profile_default',name:profile.name})], ['Remove server', () => remove(profile)]]) {
      const button = el('button', '', label); button.addEventListener('click', () => { menu.hidden = true; toggle.setAttribute('aria-expanded','false'); action(); }); menu.append(button);
    }
    toggle.addEventListener('click', () => { const wasHidden = menu.hidden; document.querySelectorAll('.card-menu').forEach(node => node.hidden = true); menu.hidden = !wasHidden; toggle.setAttribute('aria-expanded', String(wasHidden)); });
    menuContainer.append(toggle, menu); head.append(menuContainer);
    const footer = el('div', 'server-footer'); const label = el('span', 'server-status'); label.append(el('span','status-dot'),document.createTextNode(stateLabel(status))); footer.append(label);
    const connect = el('button', 'connect-button', ['connected','connecting','reconnecting'].includes(status) ? 'DISCONNECT' : 'CONNECT');
    connect.disabled = appState.busy || !appState.available || status === 'disconnecting';
    connect.addEventListener('click', () => {
      if (['connected','connecting','reconnecting'].includes(status)) mutate({type:'disconnect'});
      else if (appState.connection && !['disconnected','failed'].includes(appState.connection.status)) mutate({type:'switch',profile:profile.name});
      else mutate({type:'connect',profile:profile.name});
    });
    footer.append(connect); card.append(head, footer); list.append(card);
  }
  if (query && !profiles.length && appState.profiles.length) list.append(el('p','quiet','No servers match your search.'));
}
async function mutate(action) {
  if (appState.busy) return;
  appState.busy = true; renderServers(); notice('');
  try { await request(action); await refresh(); } catch (error) { notice(error.message); }
  finally { appState.busy = false; renderServers(); }
}
function openKeyDialog() { $('#key-error').hidden = true; $('#key-dialog').showModal(); $('#server-name').focus(); }
function rename(profile) { appState.selected = profile; $('#rename-value').value = profile.display_name || profile.name; $('#rename-dialog').showModal(); $('#rename-value').focus(); }
function remove(profile) { appState.selected = profile; $('#remove-caption').textContent = `This removes ${profile.display_name || profile.name} from this device. You’ll need its access key to add it again.`; $('#remove-dialog').showModal(); }
function showDetails(profile) {
  $('#detail-title').textContent = profile.display_name || profile.name; const dl = el('dl');
  const details = [['Server ID',profile.name],['Address',profile.remotes.map(remote => `${remote.host}:${remote.port}`).join(', ')],['Transport',profile.kind === 'outline' ? 'Outline-compatible Shadowsocks' : 'OpenVPN'],['Tunnel',profile.tunnel_mode === 'full' ? 'Full tunnel' : 'Split tunnel'],['Default',profile.is_default ? 'Yes' : 'No']];
  if (profile.certificate_expires_unix) details.push(['Certificate expiry', new Date(profile.certificate_expires_unix * 1000).toLocaleDateString()]);
  for (const [name,value] of details) dl.append(el('dt','',name),el('dd','',value));
  $('#detail-content').replaceChildren(dl); $('#detail-dialog').showModal();
}
function theme(value) { document.documentElement.dataset.theme = value; localStorage.setItem('myvpn-theme',value); $('#theme').textContent = value === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'; }

$('#add').addEventListener('click',openKeyDialog); $('#empty-add').addEventListener('click',openKeyDialog);
$('#search').addEventListener('input',renderServers);
document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => document.getElementById(button.dataset.close).close()));
$('#key-dialog').addEventListener('close', () => { $('#access-key').value = ''; $('#access-key').type = 'password'; $('#reveal-key').textContent = 'Show'; });
$('#reveal-key').addEventListener('click', () => { const hidden = $('#access-key').type === 'password'; $('#access-key').type = hidden ? 'text' : 'password'; $('#reveal-key').textContent = hidden ? 'Hide' : 'Show'; });
$('#key-form').addEventListener('submit', async event => {
  event.preventDefault(); const displayName = $('#server-name').value.trim(); let source = $('#access-key').value.trim();
  if (!source.startsWith('ss://') && !source.startsWith('ssconf://')) { $('#key-error').textContent = 'Paste a valid Outline key beginning with ss:// or ssconf://.'; $('#key-error').hidden = false; return; }
  let name = displayName.toLowerCase().replace(/[^a-z0-9_-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,45) || 'server';
  if (appState.profiles.some(profile => profile.name === name)) name += `-${Date.now().toString(36)}`;
  $('#save-key').disabled = true; $('#save-key').textContent = 'Adding…'; $('#key-error').hidden = true;
  try {
    await request({type:'access_key_import',name,access_key:source});
    source = ''; $('#access-key').value = '';
    await request({type:'profile_rename',name,display_name:displayName});
    $('#key-dialog').close(); $('#server-name').value = ''; notice(''); await refresh();
  } catch (error) { $('#key-error').textContent = error.message; $('#key-error').hidden = false; }
  finally { source = ''; $('#save-key').disabled = false; $('#save-key').textContent = 'Add server'; }
});
$('#rename-form').addEventListener('submit', async event => { event.preventDefault(); const profile = appState.selected; $('#rename-dialog').close(); await mutate({type:'profile_rename',name:profile.name,display_name:$('#rename-value').value.trim()}); });
$('#confirm-remove').addEventListener('click', async () => { const profile = appState.selected; $('#remove-dialog').close(); await mutate({type:'profile_remove',name:profile.name}); });
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('[data-view]').forEach(item => item.classList.toggle('active',item === button));
  $('#servers-view').hidden = button.dataset.view !== 'servers'; $('#settings-view').hidden = button.dataset.view !== 'settings';
}));
$('#autoconnect').addEventListener('change', async event => { await mutate({type:'autoconnect',enabled:event.target.checked}); if (appState.info) event.target.checked = appState.info.autoconnect; });
$('#theme').addEventListener('click', () => theme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
$('#diagnostics').addEventListener('click', async () => {
  $('#detail-title').textContent = 'Connection diagnostics';
  try { const data = await request({type:'doctor'}); $('#detail-content').replaceChildren(el('pre','',JSON.stringify(data,null,2))); $('#detail-dialog').showModal(); }
  catch (error) { notice(error.message); }
});
$('#help').addEventListener('click', () => {
  $('#detail-title').textContent = 'Private by choice.';
  const copy = el('p','field-note','MyVPN is an independent personal VPN client compatible with standard Outline access keys. Add a key supplied by your server administrator, then choose Connect. Keys are stored by your local service. Quitting the interface leaves the VPN service running; use Disconnect to stop your connection.');
  $('#detail-content').replaceChildren(copy); $('#detail-dialog').showModal();
});
theme(localStorage.getItem('myvpn-theme') === 'dark' ? 'dark' : 'light');
refresh(); setInterval(refresh, 1500);
