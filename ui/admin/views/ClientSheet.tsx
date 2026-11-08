// One client: keys (create, share, revoke), usage history, own rules and settings.
import { Copy, FileDown, KeyRound, QrCode, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { BarChart, fillBuckets } from '@shared/BarChart';
import { Bars } from '@shared/Bars';
import { ago, bytes, dateTime, plural, speed } from '@shared/format';
import { Button, Check, Field, Inner, Note, Segmented, Sheet, StatusDot, useUI } from '@shared/glass';
import { AUTH, KEY_PROTOCOLS, PROTOCOLS, PROTOCOL_HINTS, api, protocolName, type Client, type Key, type ProtocolId, type Stats, type User } from '../api';
import { hasConf, isApple, tunnelAddress, useKeyTools } from '../keys';
import { dataLimitValue } from '../limits';
import { RulesEditor } from '../RulesEditor';
import { SpeedLimitField, speedChange, speedChoice } from '../SpeedLimit';
import { clientStatus, statusLabel, useStore } from '../store';

type Tab = 'keys' | 'usage' | 'rules' | 'settings';

// An IKEv2/IPsec key's sign-in method, named as in the New key form.
const authName = (key: Key) => AUTH[key.protocol as 'ikev2' | 'ipsec']?.find(([value]) => value === key.auth)?.[1] ?? key.auth;

export function ClientSheet({ user, onClose }: { user: User | null; onClose: () => void }) {
  const { liveById } = useStore();
  const [tab, setTab] = useState<Tab>('keys');
  useEffect(() => setTab('keys'), [user?.id]);
  const status = user ? clientStatus(user, liveById[user.id]) : 'idle';
  return (
    <Sheet
      open={user !== null}
      onClose={onClose}
      size="medium"
      title={user?.name ?? ''}
      subtitle={
        user && (
          <span className="num inline-flex items-center gap-1.5">
            <StatusDot status={status} /> {statusLabel[status]} · {plural(user.keys.length, 'key')} · {bytes(user.usage_bytes)} used
          </span>
        )
      }
    >
      {user && (
        <div className="grid gap-5">
          <Segmented
            label="Section"
            value={tab}
            onChange={setTab}
            options={[
              { value: 'keys', label: 'Keys' },
              { value: 'usage', label: 'Usage' },
              { value: 'rules', label: 'Rules' },
              { value: 'settings', label: 'Settings' },
            ]}
          />
          {tab === 'keys' && <KeysTab user={user} />}
          {tab === 'usage' && <UsageTab user={user} />}
          {tab === 'rules' && <RulesTab user={user} />}
          {tab === 'settings' && <SettingsTab user={user} onRemoved={onClose} />}
        </div>
      )}
    </Sheet>
  );
}

function KeysTab({ user }: { user: User }) {
  const { reloadUsers, server } = useStore();
  const { toast } = useUI();
  const [keys, setKeys] = useState<Key[] | null>(null);
  const load = () => api<Key[]>('GET', `/users/${user.id}/keys`).then(setKeys).catch(e => toast(e.message, 'bad'));
  const tools = useKeyTools(() => (load(), reloadUsers()));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void load(), [user.id, user.keys.length]);

  const [protocol, setProtocol] = useState<ProtocolId>('amneziawg');
  const [auth, setAuth] = useState('eap');
  const [address, setAddress] = useState('');
  const [remoteId, setRemoteId] = useState('');
  const [localId, setLocalId] = useState('');
  const apple = isApple(protocol);
  useEffect(() => {
    if (apple) setAuth(AUTH[protocol as 'ikev2' | 'ipsec'][0][0]);
  }, [protocol, apple]);

  const create = async () => {
    const request: Record<string, string> = { protocol };
    if (apple) {
      request.auth = auth;
      if (address.trim()) request.server_address = address.trim();
      if (localId.trim()) request.local_identifier = localId.trim();
      if (remoteId.trim() && protocol === 'ikev2') request.remote_identifier = remoteId.trim();
    }
    try {
      const key = await api<Key>('POST', `/users/${user.id}/keys`, request);
      toast(key.warning || `${protocolName(protocol)} key created.`, key.warning ? 'info' : 'ok');
      await load();
      await reloadUsers();
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };

  const available = KEY_PROTOCOLS.filter(p => server.protocols[p]?.enabled);
  return (
    <div className="grid gap-4">
      {keys === null ? (
        <Note>Loading keys…</Note>
      ) : !keys.length ? (
        <Inner>
          <Note>No keys yet. Create one below; Ghostlink generates it on the server.</Note>
        </Inner>
      ) : (
        <ul className="grid grid-cols-1 gap-2.5">
          {keys.map(key => {
            const summary = user.keys.find(k => k.id === key.id);
            return (
              <li key={key.id} className="inset-glass grid grid-cols-1 gap-3 rounded-[24px] px-4 py-3">
                <div className="flex items-center gap-3">
                <div className="grid size-9 place-items-center rounded-full bg-glass-strong text-fg-2">
                  <KeyRound size={16} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[14px] text-fg">{protocolName(key.protocol)}</div>
                  <div className="truncate text-[12px] text-fg-3">
                    Created {dateTime(key.created_unix)}
                    {summary?.address && (
                      <>
                        {' · '}
                        <span className="mono">{summary.address}/32</span>
                      </>
                    )}
                    {isApple(key.protocol) && ` · ${authName(key)} · `}
                    {isApple(key.protocol) && <span className="mono">{key.identity}</span>}
                  </div>
                </div>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-1.5">
                  {isApple(key.protocol) ? (
                    <>
                      <Button size="sm" icon={<FileDown size={14} />} onClick={() => tools.downloadProfile(user, key.id)}>
                        Profile
                      </Button>
                      {key.auth === 'certificate' && (
                        <Button size="sm" variant="ghost" onClick={() => tools.downloadProfile(user, key.id, true)}>
                          Without password
                        </Button>
                      )}
                    </>
                  ) : (
                    <>
                      <Button size="sm" icon={<QrCode size={14} />} onClick={() => tools.showQR(user, key.id)}>
                        QR code
                      </Button>
                      {hasConf(key.protocol) && (
                        <>
                          <Button size="sm" variant="ghost" onClick={() => tools.showQR(user, key.id, 'key')}>
                            QR vpn://
                          </Button>
                          <Button size="sm" icon={<FileDown size={14} />} onClick={() => tools.downloadConf(user, key.id)}>
                            .conf
                          </Button>
                        </>
                      )}
                      <Button size="sm" icon={<Copy size={13} />} onClick={() => tools.copyKey(user, key.id)}>
                        Copy key
                      </Button>
                      {tools.canUseHere && (
                        <Button size="sm" variant="ghost" onClick={() => tools.useHere(user, key.id)}>
                          Use on this device
                        </Button>
                      )}
                    </>
                  )}
                  {summary && (
                    <Button size="sm" variant="danger" icon={<Trash2 size={13} />} onClick={() => tools.revoke(user, summary)}>
                      Revoke
                    </Button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <Inner className="grid gap-4">
        <h3 className="text-[14px]">New key</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Protocol" hint={PROTOCOL_HINTS[protocol]}>
            <select className="field" value={protocol} onChange={e => setProtocol(e.target.value as ProtocolId)}>
              {KEY_PROTOCOLS.map(p => (
                <option key={p} value={p} disabled={!available.includes(p)}>
                  {PROTOCOLS[p]}
                  {!available.includes(p) ? ' (off)' : ''}
                </option>
              ))}
            </select>
          </Field>
          {apple && (
            <Field label="Sign-in">
              <select className="field" value={auth} onChange={e => setAuth(e.target.value)}>
                {AUTH[protocol as 'ikev2' | 'ipsec'].map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>
        {apple && (
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Server address" hint="optional">
              <input className="field mono" spellCheck={false} value={address} onChange={e => setAddress(e.target.value)} placeholder={server.hostname} />
            </Field>
            {protocol === 'ikev2' && (
              <Field label="Remote identifier" hint="optional">
                <input className="field mono" spellCheck={false} value={remoteId} onChange={e => setRemoteId(e.target.value)} placeholder={server.hostname} />
              </Field>
            )}
            <Field label="Local identifier" hint="optional">
              <input className="field mono" spellCheck={false} value={localId} onChange={e => setLocalId(e.target.value)} placeholder="name-ID@ghostlink" />
            </Field>
          </div>
        )}
        {auth === 'psk' && apple && <Note tone="warn">A shared group key is weak: everyone with it can pretend to be this server to other IPsec users, and its handshake can be guessed offline. Prefer a certificate or IKEv2.</Note>}
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="ghost" icon={<FileDown size={14} />} onClick={() => tools.downloadKit(user)}>
            Connection kit
          </Button>
          <Button variant="cta" icon={<KeyRound size={14} />} onClick={create} disabled={!available.includes(protocol)}>
            Create key
          </Button>
        </div>
      </Inner>
      {tools.sheet}
    </div>
  );
}

function UsageTab({ user }: { user: User }) {
  const [range, setRange] = useState<'24h' | '7d' | '30d' | '90d'>('7d');
  const [stats, setStats] = useState<Stats | null>(null);
  const [clients, setClients] = useState<Client[]>([]);
  useEffect(() => {
    let current = true;
    Promise.all([api<Stats>('GET', `/stats?range=${range}&user=${user.id}`), api<{ clients: Client[] }>('GET', `/clients?user=${user.id}`)])
      .then(([s, c]) => current && (setStats(s), setClients(c.clients)))
      .catch(() => {});
    return () => {
      current = false;
    };
  }, [range, user.id]);
  return (
    <div className="grid grid-cols-1 gap-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented
          size="sm"
          label="Period"
          value={range}
          onChange={setRange}
          options={[
            { value: '24h', label: '24 h' },
            { value: '7d', label: '7 days' },
            { value: '30d', label: '30 days' },
            { value: '90d', label: '90 days' },
          ]}
        />
        <span className="num text-[13px] text-fg-2">{stats ? bytes(stats.series.reduce((n, b) => n + b.up + b.down, 0)) + ' in this period' : ''}</span>
      </div>
      <BarChart buckets={fillBuckets((stats?.series ?? []).map(b => ({ t: b.t, down: b.down, up: b.up })), stats?.unit === 'day' ? 86400 : 3600, { '24h': 24, '7d': 168, '30d': 30, '90d': 90 }[range])} unit={stats?.unit ?? 'hour'} />
      <div className="grid gap-5 sm:grid-cols-2">
        <div>
          <h3 className="mb-3 text-[14px]">Traffic types</h3>
          <Bars items={stats?.types} empty="Nothing recorded." />
        </div>
        <div>
          <h3 className="mb-3 text-[14px]">Protocols used</h3>
          <Bars items={stats?.protocols} empty="Nothing recorded." label={protocolName} />
        </div>
      </div>
      <div>
        <h3 className="mb-3 text-[14px]">Top services</h3>
        <Bars items={stats?.sites} empty={stats && !stats.site_stats ? 'Top services are off. Turn them on in Server settings.' : 'No services recorded.'} />
      </div>
      <div>
        <h3 className="mb-3 text-[14px]">Connected from</h3>
        {!clients.length ? (
          <Note>No connections recorded in the last 30 days.</Note>
        ) : (
          <ul className="grid grid-cols-1 gap-2">
            {clients.map(c => (
              <li key={c.ip + c.protocol} className="inset-glass flex items-center justify-between gap-3 rounded-[20px] px-4 py-2.5 text-[13px]">
                <span className="mono min-w-0 truncate text-fg" title={c.ip}>{c.ip}</span>
                <span className="shrink-0 text-fg-3">{protocolName(c.protocol)}</span>
                <span className="num shrink-0 text-fg-2">{ago(c.last_unix)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function RulesTab({ user }: { user: User }) {
  const { reloadUsers } = useStore();
  const { toast } = useUI();
  return (
    <div className="grid gap-3">
      <Note>These apply only to {user.name}, in addition to the rules for everyone{user.exempt_from_global_rules ? ' (from which this client is exempt)' : ''}.</Note>
      <RulesEditor
        rules={user.rules}
        onSave={async rules => {
          await api('PATCH', `/users/${user.id}`, { rules });
          toast(`Rules for ${user.name} saved.`);
          await reloadUsers();
        }}
      />
    </div>
  );
}

function SettingsTab({ user, onRemoved }: { user: User; onRemoved: () => void }) {
  const { server, reloadUsers } = useStore();
  const { toast, confirm } = useUI();
  const [name, setName] = useState(user.name);
  const [limit, setLimit] = useState(user.data_limit_bytes ? String(user.data_limit_bytes / 1e9) : '');
  const [speedLimit, setSpeedLimit] = useState(speedChoice(user.speed_limit_bps));
  const [exempt, setExempt] = useState(user.exempt_from_global_rules);
  const limitField = useRef<HTMLInputElement>(null);
  const save = async () => {
    // Sent only when changed: servers before 0.8.0 refuse fields they don't know.
    const bps = speedChange(speedLimit, user.speed_limit_bps ?? 0);
    if (bps instanceof Error) {
      toast(bps.message, 'bad');
      return;
    }
    const dataLimit = dataLimitValue(limit, limitField.current?.validity.badInput);
    if (dataLimit instanceof Error) {
      toast(dataLimit.message, 'bad');
      return;
    }
    const body: Record<string, unknown> = { name: name.trim(), data_limit_bytes: dataLimit, exempt_from_global_rules: exempt };
    if (bps !== undefined) body.speed_limit_bps = bps;
    try {
      await api('PATCH', `/users/${user.id}`, body);
      toast('Client saved.');
      await reloadUsers();
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };
  // Only the usage: edits not yet saved stay as they are, and cannot block the reset.
  const resetUsage = async () => {
    if (!(await confirm({ title: `Reset ${user.name}'s usage?`, text: `Data used goes back to zero${user.data_limit_bytes ? ', and a client stopped at its data limit can connect again' : ''}. This cannot be undone.`, action: 'Reset usage' }))) return;
    try {
      await api('PATCH', `/users/${user.id}`, { reset_usage: true });
      toast('Usage reset to zero.');
      await reloadUsers();
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };
  const address = tunnelAddress(user);
  return (
    <div className="grid gap-5">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name">
          <input className="field" value={name} maxLength={64} onChange={e => setName(e.target.value)} />
        </Field>
        <Field label="Data limit" hint="GB, empty for no limit">
          <input ref={limitField} className="field num" type="number" min="0" step="any" inputMode="decimal" value={limit} onChange={e => setLimit(e.target.value)} />
        </Field>
      </div>
      <SpeedLimitField value={speedLimit} onChange={setSpeedLimit} defaultBps={server.default_speed_limit_bps ?? 0} />
      <Check checked={exempt} onChange={setExempt}>
        Not affected by the rules for everyone
      </Check>
      <Inner className="grid gap-2 text-[13px]">
        <div className="flex justify-between">
          <span className="text-fg-3">Created</span>
          <span>{dateTime(user.created_unix)}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-fg-3">Tunnel IP</span>
          <span className="mono">{address ? `${address}/32` : '—'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-fg-3">Data used</span>
          <span className="num">{bytes(user.usage_bytes)}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-fg-3">Speed limit now</span>
          <span className="num">{user.effective_speed_limit_bps > 0 ? `${speed(user.effective_speed_limit_bps)}${user.speed_limit_bps === 0 ? ' (server default)' : ''}` : 'None'}</span>
        </div>
      </Inner>
      <div className="flex flex-wrap justify-between gap-2">
        <div className="flex gap-2">
          <Button
            variant="danger"
            icon={<Trash2 size={14} />}
            onClick={async () => {
              if (!(await confirm({ title: `Remove ${user.name}?`, text: 'All their keys stop working immediately. This cannot be undone.', action: 'Remove client', danger: true }))) return;
              try {
                await api('DELETE', `/users/${user.id}`);
                toast(`${user.name} removed.`);
                onRemoved();
                await reloadUsers();
              } catch (error) {
                toast((error as Error).message, 'bad');
              }
            }}
          >
            Remove client
          </Button>
          <Button variant="ghost" onClick={resetUsage}>
            Reset usage
          </Button>
        </div>
        <Button variant="cta" onClick={() => save()}>
          Save
        </Button>
      </div>
    </div>
  );
}
