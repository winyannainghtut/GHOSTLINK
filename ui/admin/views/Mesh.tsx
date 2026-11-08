// The mesh of Linux servers this server coordinates: the live map, node details, approvals,
// invites ("Add node") and access rules.
import { Copy, Plus, Route, Shuffle, Trash2, X } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { MeshMap, type MeshNode, type Topology } from '@shared/MeshMap';
import { ago, dateTime, plural, words } from '@shared/format';
import { Button, Card, CardTitle, Check, Facts, Field, IconButton, Inner, Note, Segmented, Sheet, StatusDot, Switch, useUI } from '@shared/glass';
import { usePoll } from '@shared/hooks';
import { api, type MeshInfo, type MeshRule } from '../api';

export function MeshCard() {
  const { toast } = useUI();
  const [info, setInfo] = useState<MeshInfo | null>(null);
  const [topology, setTopology] = useState<Topology | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [reset, setReset] = useState(0);
  const [invite, setInvite] = useState(false);
  const [rules, setRules] = useState(false);

  const loadInfo = () => api<MeshInfo>('GET', '/mesh').then(setInfo);
  useEffect(() => void loadInfo().catch(() => {}), []);
  usePoll(async () => {
    if (info?.enabled) setTopology(await api<Topology>('GET', '/mesh/topology'));
  }, 5000, [info?.enabled]);

  const refresh = async () => {
    await loadInfo();
    setTopology(await api<Topology>('GET', '/mesh/topology'));
  };
  // Reports whether the server took the change; a failure is shown as a toast.
  const change = async (method: string, path: string, body: unknown, message?: string) => {
    try {
      await api(method, path, body);
    } catch (error) {
      toast((error as Error).message, 'bad');
      return false;
    }
    if (message) toast(message);
    await refresh().catch(error => toast((error as Error).message, 'bad'));
    return true;
  };

  if (!info) return null;
  if (!info.enabled) {
    return (
      <Card>
        <CardTitle title="Mesh" detail="A private network between your Linux servers" />
        <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-end">
          <p className="max-w-2xl text-[13.5px] text-fg-2">
            Every Linux server you add gets a private address (<span className="mono">100.96.x.x</span>) and reaches the others over WireGuard, directly or through a relay when it is behind NAT. Access rules decide what may connect. This server coordinates the mesh,
            and you see it here as a live map. Windows servers and the Ghostlink app as a node will follow in a later version.
          </p>
          <Button
            variant="cta"
            onClick={async () => {
              if (!(await change('PATCH', '/mesh', { enabled: true }))) return;
              try {
                const next = await api<MeshInfo>('GET', '/mesh');
                toast(`Mesh on. Allow TCP ${next.port} in this server's firewall so other servers can join.`);
              } catch (error) {
                toast((error as Error).message, 'bad');
              }
            }}
          >
            Turn on mesh
          </Button>
        </div>
      </Card>
    );
  }

  const nodes = topology?.nodes ?? [];
  const node = nodes.find(n => n.id === selected) ?? null;
  const online = nodes.filter(n => n.online).length;
  const relayed = (topology?.links ?? []).filter(l => l.path === 'relay').length;
  return (
    <Card>
      <CardTitle
        title="Mesh"
        detail={
          <>
            <span className="mono">{info.cidr}</span> · agents connect to TCP <span className="mono">{info.port}</span> ·{' '}
            <span className="num">
              {plural(nodes.length, 'node')}, {online} online{relayed ? ` · ${relayed} through the relay` : ''}
            </span>{' '}
            · {info.rules ? plural(info.rules, 'access rule') : 'open (no rules)'}
          </>
        }
        action={
          <>
            <IconButton label="Rearrange the map" onClick={() => setReset(Date.now())}>
              <Shuffle size={16} />
            </IconButton>
            <Button size="sm" icon={<Route size={14} />} onClick={() => setRules(true)}>
              Access rules
            </Button>
            <Button size="sm" variant="cta" icon={<Plus size={14} />} onClick={() => setInvite(true)}>
              Add node
            </Button>
          </>
        }
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="inset-glass overflow-hidden rounded-[24px]">
          {topology && <MeshMap topology={topology} selected={selected} onSelect={setSelected} resetToken={reset} className="h-[min(62vh,760px)]" />}
          <div className="flex flex-wrap items-center gap-4 border-t border-line px-4 py-2.5 text-[12px] text-fg-3">
            <LegendLine className="bg-ok" label="Direct" />
            <LegendLine className="border-t-2 border-dashed border-relay bg-transparent" label="Through the relay" />
            <LegendLine className="border-t-2 border-dotted border-bad bg-transparent" label="Down" />
            <span className="ml-auto">Drag nodes to arrange the map</span>
          </div>
        </div>
        <aside className="max-h-[min(62vh,800px)] overflow-y-auto">
          {node ? <NodePanel node={node} topology={topology!} onClose={() => setSelected(null)} change={change} /> : <Overview nodes={nodes} info={info} onSelect={setSelected} change={change} />}
        </aside>
      </div>
      <InviteSheet open={invite} info={info} onClose={() => (setInvite(false), loadInfo().catch(() => {}))} />
      <RulesSheet open={rules} onClose={() => setRules(false)} onSaved={refresh} />
    </Card>
  );
}

function LegendLine({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`inline-block h-0.5 w-6 rounded-full ${className}`} />
      {label}
    </span>
  );
}

type Change = (method: string, path: string, body: unknown, message?: string) => Promise<boolean>;

const STATE_LABELS: Record<string, string> = { online: 'Online', offline: 'Offline', pending: 'Waiting for approval', disabled: 'Disabled' };

function Overview({ nodes, info, onSelect, change }: { nodes: MeshNode[]; info: MeshInfo; onSelect: (id: string) => void; change: Change }) {
  const { confirm } = useUI();
  const pending = nodes.filter(n => n.status === 'pending');
  return (
    <div className="grid gap-4">
      {pending.length > 0 && (
        <Inner className="grid gap-2">
          <h3 className="text-[14px]">Waiting for approval</h3>
          {pending.map(n => (
            <div key={n.id} className="flex items-center gap-2">
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13.5px]">{n.name}</div>
                <div className="mono text-[11.5px] text-fg-3">{n.seen_from || n.address}</div>
              </div>
              <Button size="sm" variant="cta" onClick={() => change('PATCH', `/mesh/nodes/${n.id}`, { status: 'active' }, `${n.name} is in the mesh.`)}>
                Approve
              </Button>
              <Button size="sm" variant="ghost" onClick={() => change('DELETE', `/mesh/nodes/${n.id}`, undefined, `${n.name} rejected.`)}>
                Reject
              </Button>
            </div>
          ))}
        </Inner>
      )}
      <div>
        <h3 className="mb-2 px-1 text-[14px]">Nodes</h3>
        {!nodes.length && <Note>No nodes yet. Choose Add node and run the command it gives you on each Linux server.</Note>}
        <ul className="grid gap-1">
          {nodes.map(n => (
            <li key={n.id}>
              <button type="button" onClick={() => onSelect(n.id)} className="flex w-full items-center gap-3 rounded-[18px] px-3 py-2 text-left transition hover:bg-glass-strong">
                <StatusDot status={n.status === 'pending' ? 'pending' : n.status === 'disabled' ? 'paused' : n.online ? 'online' : 'offline'} />
                <span className="min-w-0 flex-1 truncate text-[13.5px]">{n.name}</span>
                <span className="mono text-[11.5px] text-fg-3">{n.address}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
      <Inner className="grid gap-1">
        <Check checked={info.ping} onChange={on => change('PATCH', '/mesh', { ping: on })}>
          Nodes can always ping each other
        </Check>
        <Note>Ping shows latency on the map, even when access rules restrict other traffic.</Note>
        <Button
          size="sm"
          variant="ghost"
          className="mt-2 justify-self-start"
          onClick={async () => {
            if (await confirm({ title: 'Turn the mesh off?', text: 'Connected nodes take their links down within seconds. Nodes, invites and rules are kept for when you turn it on again.', action: 'Turn off', danger: true })) await change('PATCH', '/mesh', { enabled: false }, 'Mesh turned off.');
          }}
        >
          Turn the mesh off
        </Button>
      </Inner>
    </div>
  );
}

function NodePanel({ node, topology, onClose, change }: { node: MeshNode; topology: Topology; onClose: () => void; change: Change }) {
  const { confirm } = useUI();
  const [tags, setTags] = useState((node.tags ?? []).join(', '));
  const [routes, setRoutes] = useState<string[]>(node.approved_routes ?? []);
  // The topology poll brings new arrays every 5 s: follow the saved values only when they change,
  // so tags being typed and subnet switches not yet saved stay as they are.
  const savedTags = (node.tags ?? []).join(', ');
  const savedRoutes = (node.approved_routes ?? []).join('\n');
  useEffect(() => {
    setTags(savedTags);
    setRoutes(savedRoutes ? savedRoutes.split('\n') : []);
  }, [node.id, savedTags, savedRoutes]);
  const name = (id: string) => topology.nodes.find(n => n.id === id)?.name ?? id;
  const links = topology.links.filter(l => l.a === node.id || l.b === node.id);
  const state = node.status !== 'active' ? node.status : node.online ? 'online' : 'offline';
  const stateLabel = STATE_LABELS[state] ?? state;
  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-[17px]">{node.name}</h3>
        <IconButton label="Back to all nodes" onClick={onClose}>
          <X size={17} />
        </IconButton>
      </div>
      <Facts
        rows={[
          ['Address', <span className="mono">{node.address}</span>],
          ['Name', <span className="mono">{node.name}.mesh</span>],
          ['State', `${stateLabel}${node.relay_in_use ? ', relay' : node.relay ? ', standby relay' : ''}${node.online && !node.in_sync ? ', applying changes' : ''}`],
          ['Reached at', node.endpoint ? <span className="mono">{node.endpoint}</span> : 'Behind NAT (connects out)'],
          ['Seen from', node.seen_from ? <span className="mono">{node.seen_from}</span> : '—'],
          ['Last seen', <span className="num">{node.last_seen_unix ? ago(node.last_seen_unix) : 'Never'}</span>],
          ['Agent', node.version ? `${node.version} (${node.os})` : '—'],
          ...(node.error ? [['Problem', <span className="text-bad">{node.error}</span>] as [string, ReactNode]] : []),
        ]}
      />
      {node.status === 'pending' && (
        <Button variant="cta" onClick={() => change('PATCH', `/mesh/nodes/${node.id}`, { status: 'active' }, `${node.name} is in the mesh.`)}>
          Approve
        </Button>
      )}
      <Field label="Tags" hint="for access rules">
        <div className="flex gap-2">
          <input className="field" spellCheck={false} value={tags} onChange={e => setTags(e.target.value)} />
          <Button size="md" onClick={() => change('PATCH', `/mesh/nodes/${node.id}`, { tags: words(tags.toLowerCase()) }, 'Tags saved.')}>
            Save
          </Button>
        </div>
      </Field>
      {(node.advertised_routes ?? []).length > 0 && (
        <Inner className="grid gap-2">
          <h4 className="text-[13.5px]">Shared subnets</h4>
          <Note>Subnets this server offers. Shared ones are reachable from the mesh, under the access rules.</Note>
          {(node.advertised_routes ?? []).map(route => (
            <label key={route} className="flex items-center justify-between gap-3 py-1">
              <span className="mono text-[13px]">{route}</span>
              <Switch checked={routes.includes(route)} onChange={on => setRoutes(on ? [...routes, route] : routes.filter(r => r !== route))} label={`Share ${route}`} />
            </label>
          ))}
          <Button size="sm" className="justify-self-end" onClick={() => change('PATCH', `/mesh/nodes/${node.id}`, { approved_routes: routes }, 'Subnets saved.')}>
            Save subnets
          </Button>
        </Inner>
      )}
      <div className="grid gap-1">
        <Check checked={node.relay} onChange={on => change('PATCH', `/mesh/nodes/${node.id}`, { relay: on })}>
          Relay for servers behind NAT
        </Check>
        <Note>A relay forwards traffic between nodes that cannot connect directly, so it can read that traffic. Use your own server.</Note>
      </div>
      {links.length > 0 && (
        <div>
          <h4 className="mb-2 text-[13.5px]">Links</h4>
          <ul className="grid gap-1.5">
            {links.map(l => (
              <li key={l.a + l.b} className="inset-glass flex items-center justify-between gap-2 rounded-[16px] px-3 py-2 text-[12.5px]">
                <span>{name(l.a === node.id ? l.b : l.a)}</span>
                <span className={l.path === 'direct' ? 'text-ok' : l.path === 'relay' ? 'text-relay' : 'text-bad'}>{l.path === 'relay' ? `Via ${name(l.via ?? '')}` : l.path === 'direct' ? 'Direct' : 'Down'}</span>
                <span className="num text-fg-2">{l.rtt_ms > 0 ? `${l.rtt_ms.toFixed(1)} ms` : '—'}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {node.status === 'disabled' ? (
          <Button onClick={() => change('PATCH', `/mesh/nodes/${node.id}`, { status: 'active' }, `${node.name} enabled.`)}>Enable</Button>
        ) : (
          <Button onClick={() => change('PATCH', `/mesh/nodes/${node.id}`, { status: 'disabled' }, `${node.name} is disconnected until you enable it.`)}>Disable</Button>
        )}
        <Button
          variant="danger"
          icon={<Trash2 size={14} />}
          onClick={async () => {
            if (!(await confirm({ title: `Remove ${node.name} from the mesh?`, text: 'Its agent removes the mesh interface and stops. Joining again needs a new invite.', action: 'Remove node', danger: true }))) return;
            onClose();
            await change('DELETE', `/mesh/nodes/${node.id}`, undefined, `${node.name} removed. The other nodes drop it within seconds.`);
          }}
        >
          Remove
        </Button>
      </div>
    </div>
  );
}

function InviteSheet({ open, info, onClose }: { open: boolean; info: MeshInfo; onClose: () => void }) {
  const { toast } = useUI();
  const [tags, setTags] = useState('');
  const [uses, setUses] = useState('1');
  const [hours, setHours] = useState('24');
  const [relay, setRelay] = useState(false);
  const [approval, setApproval] = useState(false);
  const [result, setResult] = useState<{ command: string; expires_unix: number; uses_left: number } | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (open) {
      setResult(null);
      setError('');
      setTags('');
      setUses('1');
      setHours('24');
      setRelay(false);
      setApproval(false);
    }
  }, [open]);
  const create = async () => {
    const count = Number(uses) || 1, valid = Number(hours) || 24;
    // Whole numbers only: the desktop app's service refuses a fraction before the server sees it.
    if (![count, valid].every(Number.isInteger) || count < 1 || valid < 1) {
      setError('An invite works 1-1000 times for 1 hour to 90 days, in whole numbers.');
      return;
    }
    try {
      setResult(await api('POST', '/mesh/invites', { tags: words(tags.toLowerCase()), uses: count, expires_hours: valid, relay, approval }));
    } catch (e) {
      setError((e as Error).message);
    }
  };
  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="Add a node"
      subtitle="An invite and one command to run on the Linux server you want to add (Ubuntu, Debian, Fedora, RHEL and similar, with kernel WireGuard)."
      footer={
        result ? (
          <>
            <Button icon={<Copy size={14} />} onClick={() => navigator.clipboard.writeText(result.command).then(() => toast('Join command copied. Run it on the server you want to add.'))}>
              Copy command
            </Button>
            <Button variant="cta" onClick={onClose}>
              Done
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="cta" onClick={create}>
              Create invite
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="grid gap-3">
          <Field label="Run this on the server">
            <textarea className="field min-h-[120px]" readOnly spellCheck={false} value={result.command} onFocus={e => e.currentTarget.select()} />
          </Field>
          <Note>
            Works {plural(result.uses_left, 'time')}, until {dateTime(result.expires_unix)}. Keep it private until it is used. The node connects out to TCP <span className="mono">{info.port}</span> here; a node with a public address should allow UDP{' '}
            <span className="mono">51820</span> in.
          </Note>
        </div>
      ) : (
        <div className="grid gap-4">
          <Field label="Tags" hint="for access rules, for example web or db">
            <input className="field" spellCheck={false} value={tags} onChange={e => setTags(e.target.value)} />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Uses">
              <input className="field num" type="number" min={1} max={1000} value={uses} onChange={e => setUses(e.target.value)} />
            </Field>
            <Field label="Valid for" hint="hours">
              <input className="field num" type="number" min={1} max={2160} value={hours} onChange={e => setHours(e.target.value)} />
            </Field>
          </div>
          <Check checked={relay} onChange={setRelay}>
            Relay for nodes behind NAT (needs a public address)
          </Check>
          <Check checked={approval} onChange={setApproval}>
            Wait for my approval before it joins
          </Check>
          {error && <Note tone="bad">{error}</Note>}
        </div>
      )}
    </Sheet>
  );
}

// A rule being edited keeps its ports as typed ("5432, 8000-8100"); they are split on save, so a
// comma or space can be typed between them.
type DraftRule = Omit<MeshRule, 'ports'> & { ports: string };
const PROTOCOL_LABELS: Record<MeshRule['protocol'], string> = { tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', any: 'Any' };

function RulesSheet({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: () => Promise<void> }) {
  const { toast } = useUI();
  const [rules, setRules] = useState<DraftRule[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    if (open) {
      setError('');
      api<{ rules: MeshRule[] }>('GET', '/mesh/rules')
        .then(r => setRules((r.rules ?? []).map(rule => ({ ...rule, ports: (rule.ports ?? []).join(', ') }))))
        .catch(e => setError(e.message));
    }
  }, [open]);
  const update = (i: number, next: Partial<DraftRule>) => setRules(rules.map((r, j) => (j === i ? { ...r, ...next } : r)));
  return (
    <Sheet
      open={open}
      onClose={onClose}
      size="medium"
      title="Access rules"
      subtitle="With no rules every node reaches every node. Once you add one, only matching traffic passes; replies always do."
      footer={
        <>
          <Button variant="ghost" icon={<Plus size={14} />} onClick={() => setRules([...rules, { from: 'tag:', to: 'tag:', protocol: 'tcp', ports: '' }])}>
            Add a rule
          </Button>
          <Button
            variant="cta"
            onClick={async () => {
              try {
                const clean: MeshRule[] = rules.map(r => ({ from: r.from.trim() || '*', to: r.to.trim() || '*', protocol: r.protocol, ports: r.protocol === 'tcp' || r.protocol === 'udp' ? words(r.ports) : [] }));
                await api('PUT', '/mesh/rules', { rules: clean });
                toast(clean.length ? `Saved ${plural(clean.length, 'rule')}. Everything else between nodes is blocked.` : 'No rules: every node reaches every node.');
                onClose();
                await onSaved();
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            Save rules
          </Button>
        </>
      }
    >
      <div className="grid gap-3">
        <Note>
          From and to are <span className="mono">*</span>, <span className="mono">tag:NAME</span> or <span className="mono">node:NAME</span>. Rules are enforced on the receiving node; a node's shared subnets count as part of it.
        </Note>
        {!rules.length && <Inner><Note>No rules: the mesh is open.</Note></Inner>}
        {rules.map((rule, i) => (
          <div key={i} className="inset-glass grid items-center gap-2 rounded-[22px] p-3 sm:grid-cols-[1fr_auto_1fr_auto_140px_auto]">
            <input className="field mono" aria-label="From" spellCheck={false} value={rule.from} onChange={e => update(i, { from: e.target.value })} placeholder="tag:web" />
            <span className="text-center text-fg-3">→</span>
            <input className="field mono" aria-label="To" spellCheck={false} value={rule.to} onChange={e => update(i, { to: e.target.value })} placeholder="tag:db" />
            <Segmented
              size="sm"
              label="Protocol"
              value={rule.protocol}
              onChange={protocol => update(i, { protocol })}
              options={(['tcp', 'udp', 'icmp', 'any'] as const).map(p => ({ value: p, label: PROTOCOL_LABELS[p] }))}
            />
            <input
              className="field mono"
              aria-label="Ports"
              spellCheck={false}
              disabled={rule.protocol === 'icmp' || rule.protocol === 'any'}
              value={rule.ports}
              onChange={e => update(i, { ports: e.target.value })}
              placeholder="5432, 8000-8100"
            />
            <IconButton label="Remove rule" onClick={() => setRules(rules.filter((_, j) => j !== i))}>
              <Trash2 size={15} />
            </IconButton>
          </div>
        ))}
        {error && <Note tone="bad">{error}</Note>}
      </div>
    </Sheet>
  );
}
