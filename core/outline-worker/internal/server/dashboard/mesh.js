/* Dashboard → Mesh: the private network between Linux servers this server coordinates.
   The map is mesh-map.js, the same file the desktop app uses. */
'use strict';
const mesh = { info: null, topology: null, map: null, selected: null, sideKey: '', busy: false };
const meshName = id => (mesh.topology?.nodes || []).find(n => n.id === id)?.name || id;
const meshWords = text => text.split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
const meshPlural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;

function meshButton(label, cls, handler) {
  const b = el('button', cls, label); b.type = 'button'; b.addEventListener('click', handler); return b;
}

async function loadMesh() {
  mesh.info = await api('GET', '/mesh');
  $('#mesh-off').hidden = mesh.info.enabled;
  $('#mesh-on').hidden = $('#mesh-tools').hidden = $('#mesh-legend').hidden = !mesh.info.enabled;
  $('#mesh-address').textContent = mesh.info.enabled ? `${mesh.info.cidr} · agents connect to TCP ${mesh.info.port}` : '';
  if (!mesh.info.enabled) return;
  if (!mesh.map) {
    mesh.map = new GhostlinkMeshMap.MeshMap($('#mesh-svg'), {
      storage: window.localStorage,
      onSelect: id => { mesh.selected = id; mesh.sideKey = ''; renderMeshSide(); },
    });
  }
  await refreshMesh();
}

async function refreshMesh() {
  if (mesh.busy || state.view !== 'mesh' || !mesh.info?.enabled) return;
  mesh.busy = true;
  try {
    mesh.topology = await api('GET', '/mesh/topology');
    mesh.map.update(mesh.topology);
    const t = mesh.topology, online = t.nodes.filter(n => n.online).length, relayed = t.links.filter(l => l.path === 'relay').length;
    $('#mesh-stats').textContent = `${meshPlural(t.nodes.length, 'node')}, ${online} online · ${meshPlural(t.links.length, 'link')}${relayed ? `, ${relayed} through the relay` : ''} · ${t.rule_count ? meshPlural(t.rule_count, 'access rule') : 'no access rules (open)'}`;
    renderMeshSide();
  } catch (error) { notice(error.message, true); }
  finally { mesh.busy = false; }
}
setInterval(refreshMesh, 5000);

async function meshDo(method, path, body, message) {
  try {
    await api(method, path, body);
    if (message) notice(message);
    mesh.sideKey = '';
    await refreshMesh();
  } catch (error) { notice(error.message, true); }
}
const updateNode = (node, change, message) => meshDo('PATCH', `/mesh/nodes/${node.id}`, change, message);

function renderMeshSide() {
  const side = $('#mesh-side');
  if (side.contains(document.activeElement) && document.activeElement.matches('input, select, textarea')) return;
  const node = (mesh.topology?.nodes || []).find(n => n.id === mesh.selected);
  const links = (mesh.topology?.links || []).filter(l => node && (l.a === node.id || l.b === node.id));
  const key = JSON.stringify([mesh.selected, node, links, node ? null : mesh.topology?.nodes.map(n => [n.id, n.status, n.online, n.name, n.tags])]);
  if (key === mesh.sideKey) return;
  mesh.sideKey = key;
  side.replaceChildren();
  if (!node) {
    const nodes = mesh.topology?.nodes || [];
    for (const n of nodes.filter(n => n.status === 'pending')) {
      const row = el('div', 'key'); const what = el('div', 'what', `${n.name} is waiting for approval`); what.append(el('small', '', n.seen_from || n.address));
      row.append(what, meshButton('Approve', 'primary', () => updateNode(n, { status: 'active' }, `${n.name} is in the mesh.`)),
        meshButton('Reject', 'secondary', () => meshDo('DELETE', `/mesh/nodes/${n.id}`)));
      side.append(row);
    }
    side.append(el('h2', '', 'Nodes'));
    if (!nodes.length) side.append(el('p', 'hint', 'No nodes yet. Choose Add node and run the command it gives you on each Linux server.'));
    for (const n of nodes) {
      const row = meshButton('', 'mesh-node-row', () => mesh.map.select(n.id));
      row.append(el('span', `dot${n.online ? ' on' : ''}`), el('span', '', ` ${n.name}`), el('small', '', ` ${n.address}${n.relay_in_use ? ' · relay' : ''}${(n.tags || []).length ? ' · ' + n.tags.join(', ') : ''}`));
      side.append(row);
    }
    const ping = el('label', 'check'); const box = el('input'); box.type = 'checkbox'; box.checked = mesh.info.ping !== false;
    ping.append(box, document.createTextNode(' Nodes can always ping each other (shows latency)'));
    box.addEventListener('change', () => meshDo('PATCH', '/mesh', { ping: box.checked }));
    side.append(el('h3', '', 'Settings'), ping, meshButton('Rearrange the map', 'text', () => mesh.map.forgetLayout()), el('br'),
      meshButton('Turn the mesh off', 'text', () => confirmAction('Turn the mesh off?', 'Every node disconnects within seconds. Nodes, invites and rules are kept.', 'Turn off', async () => {
        await api('PATCH', '/mesh', { enabled: false }); notice('Mesh turned off.'); await loadMesh();
      })));
    return;
  }
  const head = el('div', 'mesh-side-head');
  head.append(el('h2', '', node.name), meshButton('×', 'text', () => mesh.map.select(null)));
  const condition = node.status !== 'active' ? node.status : node.online ? 'online' : 'offline';
  const facts = el('dl');
  const fact = (label, value) => { if (value) facts.append(el('dt', '', label), el('dd', '', value)); };
  fact('Address', `${node.address} (${node.name}.mesh)`);
  fact('State', condition + (node.relay_in_use ? ', relay' : node.relay ? ', standby relay' : '') + (node.online && node.in_sync === false ? ', applying changes' : ''));
  fact('Reached at', node.endpoint || 'behind NAT (connects out)');
  fact('Seen from', node.seen_from);
  fact('Last seen', ago(node.last_seen_unix));
  fact('Agent', node.version ? `${node.version} (${node.os})` : '');
  fact('Problem', node.error);
  side.append(head, facts);
  if (node.status === 'pending') side.append(meshButton('Approve', 'primary', () => updateNode(node, { status: 'active' }, `${node.name} is in the mesh.`)));
  const tags = el('label', '', 'Tags '); tags.append(el('small', '', 'for access rules'));
  const tagInput = el('input'); tagInput.value = (node.tags || []).join(', '); tagInput.spellcheck = false; tags.append(tagInput);
  side.append(tags, meshButton('Save tags', 'secondary', () => updateNode(node, { tags: meshWords(tagInput.value) })));
  if ((node.advertised_routes || []).length) {
    side.append(el('h3', '', 'Shared subnets'), el('p', 'hint', 'Subnets this server offers; shared ones are reachable from the mesh (under the access rules).'));
    const boxes = node.advertised_routes.map(route => {
      const label = el('label', 'check'); const b = el('input'); b.type = 'checkbox'; b.value = route; b.checked = (node.approved_routes || []).includes(route);
      label.append(b, document.createTextNode(' ' + route)); side.append(label); return b;
    });
    side.append(meshButton('Save subnets', 'secondary', () => updateNode(node, { approved_routes: boxes.filter(b => b.checked).map(b => b.value) }, 'Subnets saved.')));
  }
  const relay = el('label', 'check'); const relayBox = el('input'); relayBox.type = 'checkbox'; relayBox.checked = node.relay;
  relay.append(relayBox, document.createTextNode(' Relay for servers behind NAT'));
  relayBox.addEventListener('change', () => updateNode(node, { relay: relayBox.checked }));
  side.append(relay, el('p', 'hint', 'A relay forwards traffic between nodes that cannot connect directly, so it can read that traffic. Use your own server.'));
  if (links.length) {
    const table = el('table'); const tr = el('tr'); for (const h of ['To', 'Path', 'Latency']) tr.append(el('th', '', h)); table.append(tr);
    for (const l of links) {
      const row = el('tr');
      row.append(el('td', '', meshName(l.a === node.id ? l.b : l.a)), el('td', '', l.path === 'relay' ? `via ${meshName(l.via)}` : l.path), el('td', '', l.rtt_ms > 0 ? `${l.rtt_ms.toFixed(1)} ms` : '—'));
      table.append(row);
    }
    side.append(el('h3', '', 'Links'), table);
  }
  const actions = el('div', 'actions');
  actions.append(node.status === 'disabled'
    ? meshButton('Enable', 'secondary', () => updateNode(node, { status: 'active' }))
    : meshButton('Disable', 'secondary', () => updateNode(node, { status: 'disabled' }, `${node.name} is disconnected until you enable it.`)),
    meshButton('Remove', 'danger', () => confirmAction(`Remove ${node.name} from the mesh?`, 'Its agent removes the mesh interface and stops. Joining again needs a new invite.', 'Remove node', async () => {
      await api('DELETE', `/mesh/nodes/${node.id}`); mesh.map.select(null); notice(`${node.name} removed.`); await refreshMesh();
    })));
  side.append(actions);
}

$('#mesh-enable').addEventListener('click', async () => {
  try { await api('PATCH', '/mesh', { enabled: true }); await loadMesh(); notice(`Mesh turned on. Allow TCP ${mesh.info.port} in this server's firewall so other servers can join.`); }
  catch (error) { notice(error.message, true); }
});

// --- Add node ---
$('#mesh-add').addEventListener('click', () => {
  $('#mesh-invite-form').reset(); $('#mesh-invite-form').hidden = false; $('#mesh-invite-result').hidden = true; $('#mesh-invite-error').hidden = true;
  $('#mesh-invite-dialog').showModal();
});
$('#mesh-invite-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const created = await api('POST', '/mesh/invites', { tags: meshWords($('#mesh-invite-tags').value), uses: Number($('#mesh-invite-uses').value) || 1,
      expires_hours: Number($('#mesh-invite-hours').value) || 24, relay: $('#mesh-invite-relay').checked, approval: $('#mesh-invite-approval').checked });
    $('#mesh-invite-command').value = created.command;
    $('#mesh-invite-expiry').textContent = `Works ${meshPlural(created.uses_left, 'time')}, until ${new Date(created.expires_unix * 1000).toLocaleString()}. Keep it private until it is used. The node connects out to TCP ${mesh.info.port} here; a node with a public address should allow UDP 51820 in.`;
    $('#mesh-invite-form').hidden = true; $('#mesh-invite-result').hidden = false;
  } catch (error) { $('#mesh-invite-error').textContent = error.message; $('#mesh-invite-error').hidden = false; }
});
$('#mesh-invite-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#mesh-invite-command').value); notice('Join command copied.'); }
  catch { $('#mesh-invite-command').select(); notice('Press Ctrl+C to copy the selected command.'); }
});

// --- Access rules: one per line, FROM TO PROTOCOL [PORTS] ---
$('#mesh-rules').addEventListener('click', async () => {
  try {
    const { rules } = await api('GET', '/mesh/rules');
    $('#mesh-rules-text').value = rules.map(r => [r.from, r.to, r.protocol, (r.ports || []).join(',')].filter(Boolean).join(' ')).join('\n');
    $('#mesh-rules-error').hidden = true;
    $('#mesh-rules-dialog').showModal();
  } catch (error) { notice(error.message, true); }
});
$('#mesh-rules-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const rules = $('#mesh-rules-text').value.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')).map(line => {
      const parts = line.split(/\s+/);
      if (parts.length < 3 || parts.length > 4) throw new Error(`"${line}": use FROM TO PROTOCOL [PORTS], for example tag:web tag:db tcp 5432`);
      return { from: parts[0], to: parts[1], protocol: parts[2].toLowerCase(), ports: parts[3] ? parts[3].split(',') : [] };
    });
    await api('PUT', '/mesh/rules', { rules });
    $('#mesh-rules-dialog').close();
    notice(rules.length ? `Saved ${meshPlural(rules.length, 'rule')}. Everything else between nodes is blocked.` : 'No rules: every node reaches every node.');
    mesh.sideKey = ''; await refreshMesh();
  } catch (error) { $('#mesh-rules-error').textContent = error.message; $('#mesh-rules-error').hidden = false; }
});
