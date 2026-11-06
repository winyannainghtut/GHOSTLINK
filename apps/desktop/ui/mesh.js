/* Servers I run → Mesh: the private network between Linux servers that a managed Ghostlink server
   coordinates. The map is drawn by mesh-map.js; this file holds the panels and dialogs. All calls
   go through the local service (serverCall), like the rest of manage.js. */
'use strict';
const meshState = { info: null, topology: null, map: null, selected: null, timer: null, busy: false, sideKey: '' };

function meshNode(id) { return (meshState.topology?.nodes || []).find(n => n.id === id); }
function meshNodeName(id) { return meshNode(id)?.name || id; }

async function loadMeshCard() {
  try {
    meshState.info = await serverCall({ op: 'mesh_info' });
    renderMeshCard();
  } catch (error) {
    meshState.info = null;
    $('#mesh-summary').textContent = `Not available: ${error.message}. Mesh needs Ghostlink server 0.6.0 or later.`;
    $('#mesh-open').hidden = true;
  }
}

function renderMeshCard() {
  const info = meshState.info;
  $('#mesh-open').hidden = false;
  if (!info.enabled) {
    $('#mesh-summary').textContent = 'Off. Connect your Linux servers in a private network with their own addresses, and see it as a live map.';
    $('#mesh-open').textContent = 'Turn on mesh';
    return;
  }
  $('#mesh-summary').textContent = `${plural(info.nodes, 'node')}${info.pending ? `, ${info.pending} waiting for approval` : ''} · ${info.cidr}`;
  $('#mesh-open').textContent = 'Open mesh map';
}

$('#mesh-open').addEventListener('click', async () => {
  try {
    if (!meshState.info?.enabled) {
      meshState.info = await serverCall({ op: 'mesh_update', patch: { enabled: true } });
      renderMeshCard();
      notice(`Mesh turned on (${meshState.info.cidr}). Allow TCP ${meshState.info.port} on the server so other servers can join.`, true);
    }
    openMesh();
  } catch (error) { notice(error.message); }
});

function openMesh() {
  $('#mesh-heading').textContent = meshState.info?.name || 'Mesh';
  $('#mesh-eyebrow').textContent = `MESH · ${meshState.info?.cidr || ''}`.toUpperCase();
  formError('#mesh-error');
  meshState.selected = null;
  meshState.sideKey = '';
  $('#mesh-dialog').showModal();
  if (!meshState.map) {
    meshState.map = new GhostlinkMeshMap.MeshMap($('#mesh-svg'), {
      storage: window.localStorage,
      onSelect: id => { meshState.selected = id; meshState.sideKey = ''; renderMeshSide(); },
    });
  }
  refreshMesh();
  clearInterval(meshState.timer);
  meshState.timer = setInterval(refreshMesh, 5000);
}

$('#mesh-dialog').addEventListener('close', () => {
  clearInterval(meshState.timer);
  meshState.timer = null;
  loadMeshCard();
});

async function refreshMesh() {
  if (meshState.busy || !$('#mesh-dialog').open) return;
  meshState.busy = true;
  try {
    const topology = await serverCall({ op: 'mesh_topology' });
    meshState.topology = topology;
    meshState.map.update(topology);
    const online = topology.nodes.filter(n => n.online).length;
    const relayed = topology.links.filter(l => l.path === 'relay').length;
    const down = topology.links.filter(l => l.path === 'down').length;
    $('#mesh-stats').textContent = `${plural(topology.nodes.length, 'node')}, ${online} online · ${plural(topology.links.length, 'link')}${relayed ? `, ${relayed} through the relay` : ''}${down ? `, ${down} down` : ''} · ${topology.rule_count ? plural(topology.rule_count, 'access rule') : 'no access rules (open)'}`;
    renderMeshSide();
  } catch (error) { formError('#mesh-error', error); }
  finally { meshState.busy = false; }
}

async function meshChange(op, message) {
  formError('#mesh-error');
  try {
    await serverCall(op);
    if (message) notice(message, true);
    meshState.sideKey = '';
    await refreshMesh();
  } catch (error) { formError('#mesh-error', error); }
}

function sideButton(label, cls, handler) {
  const button = el('button', cls, label);
  button.type = 'button';
  button.addEventListener('click', handler);
  return button;
}

// The side panel shows the overview, or the selected node. It is not rebuilt while you type.
function renderMeshSide() {
  const side = $('#mesh-side');
  if (side.contains(document.activeElement) && document.activeElement.matches('input, select, textarea')) return;
  const node = meshNode(meshState.selected);
  const key = JSON.stringify([meshState.selected, node, (meshState.topology?.links || []).filter(l => node && (l.a === node.id || l.b === node.id)),
    meshState.selected ? null : meshState.topology?.nodes.map(n => [n.id, n.status, n.online, n.name])]);
  if (key === meshState.sideKey) return;
  meshState.sideKey = key;
  side.replaceChildren();
  if (!node) return renderMeshOverview(side);
  const head = el('div', 'mesh-side-head');
  head.append(el('h3', '', node.name), sideButton('×', 'text-button', () => meshState.map.select(null)));
  side.append(head);
  const state = node.status !== 'active' ? node.status : node.online ? 'online' : 'offline';
  const facts = el('dl');
  const fact = (label, value) => { if (value) facts.append(el('dt', '', label), el('dd', '', value)); };
  fact('Address', `${node.address} (${node.name}.mesh)`);
  fact('State', state + (node.relay_in_use ? ', relay' : node.relay ? ', standby relay' : '') + (node.in_sync === false && node.online ? ', applying changes' : ''));
  fact('Reached at', node.endpoint || 'behind NAT (connects out)');
  fact('Seen from', node.seen_from);
  fact('Last seen', node.last_seen_unix ? new Date(node.last_seen_unix * 1000).toLocaleString() : 'never');
  fact('Agent', node.version ? `${node.version} (${node.os})` : '');
  fact('Problem', node.error);
  side.append(facts);

  if (node.status === 'pending') {
    side.append(el('p', 'field-note', 'This server joined with an invite that needs approval.'),
      sideButton('Approve', 'primary', () => meshChange({ op: 'mesh_node_update', node: node.id, change: { status: 'active' } }, `${node.name} is in the mesh.`)));
  }
  const tags = el('label', '', 'Tags ');
  tags.append(el('span', 'hint', 'for access rules, comma-separated'));
  const tagInput = el('input'); tagInput.value = (node.tags || []).join(', '); tagInput.spellcheck = false;
  tags.append(tagInput);
  side.append(tags, sideButton('Save tags', 'secondary', () => meshChange({ op: 'mesh_node_update', node: node.id, change: { tags: lines(tagInput.value.replaceAll(',', '\n')).map(t => t.toLowerCase()) } })));

  if ((node.advertised_routes || []).length) {
    side.append(el('h4', 'subhead', 'Shared subnets'), el('p', 'field-note', 'Subnets this server offers. Shared ones are reachable from the whole mesh (under the access rules).'));
    const boxes = [];
    for (const route of node.advertised_routes) {
      const label = el('label', 'check'); const box = el('input'); box.type = 'checkbox'; box.checked = (node.approved_routes || []).includes(route); box.value = route;
      boxes.push(box); label.append(box, document.createTextNode(' ' + route)); side.append(label);
    }
    side.append(sideButton('Save subnets', 'secondary', () => meshChange({ op: 'mesh_node_update', node: node.id, change: { approved_routes: boxes.filter(b => b.checked).map(b => b.value) } }, 'Subnets saved.')));
  }
  const relay = el('label', 'check'); const relayBox = el('input'); relayBox.type = 'checkbox'; relayBox.checked = node.relay;
  relay.append(relayBox, document.createTextNode(' Relay for servers behind NAT'));
  relayBox.addEventListener('change', () => meshChange({ op: 'mesh_node_update', node: node.id, change: { relay: relayBox.checked } }));
  side.append(relay, el('p', 'field-note', 'The relay forwards traffic between nodes that cannot connect directly, so it can read that traffic. Use your own server.'));

  const links = (meshState.topology.links || []).filter(l => l.a === node.id || l.b === node.id);
  if (links.length) {
    side.append(el('h4', 'subhead', 'Links'));
    const table = el('table', 'client-table');
    const head = el('tr'); for (const h of ['To', 'Path', 'Latency']) head.append(el('th', '', h)); table.append(head);
    for (const link of links) {
      const other = link.a === node.id ? link.b : link.a;
      const row = el('tr');
      row.append(el('td', '', meshNodeName(other)), el('td', '', link.path === 'relay' ? `via ${meshNodeName(link.via)}` : link.path),
        el('td', '', link.rtt_ms > 0 ? `${link.rtt_ms.toFixed(1)} ms` : '—'));
      table.append(row);
    }
    side.append(table);
  }
  const actions = el('div', 'dialog-actions');
  actions.append(node.status === 'disabled'
    ? sideButton('Enable', 'secondary', () => meshChange({ op: 'mesh_node_update', node: node.id, change: { status: 'active' } }))
    : sideButton('Disable', 'secondary', () => meshChange({ op: 'mesh_node_update', node: node.id, change: { status: 'disabled' } }, `${node.name} is disconnected until you enable it.`)),
    sideButton('Remove', 'danger', () => confirmAction(`Remove ${node.name} from the mesh?`,
      'Its agent removes the mesh interface and stops. Joining again needs a new invite.', 'Remove node', async () => {
        await serverCall({ op: 'mesh_node_delete', node: node.id });
        meshState.map.select(null);
        notice(`${node.name} removed. The other nodes drop it within seconds.`, true);
      }, refreshMesh)));
  side.append(actions);
}

function renderMeshOverview(side) {
  const nodes = meshState.topology?.nodes || [];
  const pending = nodes.filter(n => n.status === 'pending');
  if (pending.length) {
    side.append(el('h3', '', 'Waiting for approval'));
    for (const n of pending) {
      const row = el('div', 'key-row');
      const what = el('div', 'what', n.name); what.append(el('small', '', n.seen_from || n.address));
      row.append(what, sideButton('Approve', 'primary', () => meshChange({ op: 'mesh_node_update', node: n.id, change: { status: 'active' } }, `${n.name} is in the mesh.`)),
        sideButton('Reject', 'secondary', () => meshChange({ op: 'mesh_node_delete', node: n.id })));
      side.append(row);
    }
  }
  side.append(el('h3', '', 'Nodes'));
  if (!nodes.length) side.append(el('p', 'field-note', 'No nodes yet. Choose Add node and run the command it gives you on each Linux server.'));
  for (const n of nodes) {
    const row = sideButton('', 'mesh-node-row', () => meshState.map.select(n.id));
    const dot = el('span', `online-dot${n.online ? ' on' : ''}`);
    row.append(dot, el('span', '', ` ${n.name}`), el('small', '', ` ${n.address}${n.relay_in_use ? ' · relay' : ''}${(n.tags || []).length ? ' · ' + n.tags.join(', ') : ''}`));
    side.append(row);
  }
  const settings = el('div', 'mesh-settings');
  const ping = el('label', 'check'); const pingBox = el('input'); pingBox.type = 'checkbox'; pingBox.checked = meshState.info?.ping !== false;
  ping.append(pingBox, document.createTextNode(' Nodes can always ping each other (shows latency)'));
  pingBox.addEventListener('change', async () => {
    try { meshState.info = await serverCall({ op: 'mesh_update', patch: { ping: pingBox.checked } }); } catch (error) { formError('#mesh-error', error); }
  });
  settings.append(el('h4', 'subhead', 'Mesh settings'), ping, sideButton('Rearrange the map', 'text-button', () => meshState.map.forgetLayout()),
    sideButton('Turn the mesh off', 'text-button', () => confirmAction('Turn the mesh off?',
      'Every node disconnects within seconds. Nodes, invites and rules are kept for when you turn it on again.', 'Turn off', async () => {
        meshState.info = await serverCall({ op: 'mesh_update', patch: { enabled: false } });
        $('#mesh-dialog').close();
        notice('Mesh turned off.', true);
      }, async () => {})));
  side.append(settings);
}

// --- Add node ---
$('#mesh-add').addEventListener('click', () => {
  $('#mesh-invite-form').reset(); $('#mesh-invite-uses').value = 1; $('#mesh-invite-hours').value = 24;
  $('#mesh-invite-result').hidden = true; $('#mesh-invite-form').hidden = false; formError('#mesh-invite-error');
  $('#mesh-invite-dialog').showModal();
});
$('#mesh-invite-form').addEventListener('submit', async event => {
  event.preventDefault();
  formError('#mesh-invite-error');
  try {
    const created = await serverCall({ op: 'mesh_invite_create', invite: {
      tags: lines($('#mesh-invite-tags').value.replaceAll(',', '\n')).map(t => t.toLowerCase()),
      uses: Number($('#mesh-invite-uses').value) || 1, expires_hours: Number($('#mesh-invite-hours').value) || 24,
      relay: $('#mesh-invite-relay').checked, approval: $('#mesh-invite-approval').checked } });
    $('#mesh-invite-command').value = created.command;
    $('#mesh-invite-expiry').textContent = `Works ${plural(created.uses_left, 'time')}, until ${new Date(created.expires_unix * 1000).toLocaleString()}. Keep it private until it is used.`;
    $('#mesh-invite-ports').textContent = `The node connects out to TCP ${meshState.info?.port || 'the mesh port'} on this server. A node with a public address should allow UDP 51820 in; a node behind NAT needs nothing open.`;
    $('#mesh-invite-form').hidden = true; $('#mesh-invite-result').hidden = false;
    loadMeshCard();
  } catch (error) { formError('#mesh-invite-error', error); }
});
$('#mesh-invite-copy').addEventListener('click', () => navigator.clipboard.writeText($('#mesh-invite-command').value).then(() => notice('Join command copied. Run it on the server you want to add.', true)));

// --- Access rules ---
function ruleRow(rule) {
  const row = el('div', 'mesh-rule');
  const input = (value, placeholder, label) => { const i = el('input'); i.value = value || ''; i.placeholder = placeholder; i.spellcheck = false; i.setAttribute('aria-label', label); return i; };
  const from = input(rule.from, 'tag:web', 'From'), to = input(rule.to, 'tag:db', 'To');
  const protocol = el('select'); for (const p of ['tcp', 'udp', 'icmp', 'any']) { const o = el('option', '', p); o.value = p; protocol.append(o); }
  protocol.value = rule.protocol || 'tcp'; protocol.setAttribute('aria-label', 'Protocol');
  const ports = input((rule.ports || []).join(','), '5432 or 8000-8100', 'Ports');
  row.append(from, el('span', 'arrow', '→'), to, protocol, ports, sideButton('Remove', 'text-button', () => row.remove()));
  row.read = () => ({ from: from.value.trim() || '*', to: to.value.trim() || '*', protocol: protocol.value, ports: ['tcp', 'udp'].includes(protocol.value) ? lines(ports.value.replaceAll(',', '\n')) : [] });
  return row;
}
$('#mesh-rules').addEventListener('click', async () => {
  formError('#mesh-rules-error');
  try {
    const { rules } = await serverCall({ op: 'mesh_rules_get' });
    const list = $('#mesh-rule-list'); list.replaceChildren();
    for (const r of rules) list.append(ruleRow(r));
    $('#mesh-rules-dialog').showModal();
  } catch (error) { formError('#mesh-error', error); }
});
$('#mesh-rule-add').addEventListener('click', () => $('#mesh-rule-list').append(ruleRow({ from: 'tag:', to: 'tag:', protocol: 'tcp' })));
$('#mesh-rules-form').addEventListener('submit', async event => {
  event.preventDefault();
  const rules = [...$('#mesh-rule-list').children].map(row => row.read());
  try {
    await serverCall({ op: 'mesh_rules_set', rules });
    $('#mesh-rules-dialog').close();
    notice(rules.length ? `Saved ${plural(rules.length, 'rule')}. Everything else between nodes is blocked.` : 'No rules: every node reaches every node.', true);
    meshState.sideKey = '';
    refreshMesh();
  } catch (error) { formError('#mesh-rules-error', error); }
});
