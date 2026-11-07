// Clients (Ghostlink users): search, status filters, cards or a list, quick key actions.
import { ChevronRight, Copy, FileDown, KeyRound, LayoutGrid, List, QrCode, Search, Trash2, UserPlus } from 'lucide-react';
import { useMemo, useState } from 'react';
import { ago, bytes, plural, speed } from '@shared/format';
import { Button, Card, Empty, IconButton, Meter, Segmented, StatusDot, Switch, cx, useUI, type Status } from '@shared/glass';
import { useNow, useStoredState } from '@shared/hooks';
import { api, protocolName, type User } from '../api';
import { DeviceIcon, hasConf, isApple, primaryKey, tunnelAddress, useKeyTools } from '../keys';
import { speedLabel } from '../SpeedLimit';
import { clientStatus, statusLabel, useStore } from '../store';
import { ClientSheet } from './ClientSheet';

type Filter = 'all' | 'online' | 'idle' | 'paused';
const FILTERS = ['all', 'online', 'idle', 'paused'] as const;

export function Clients({ onNewClient }: { onNewClient: () => void }) {
  const { users, liveById, lastClient, reloadUsers, loaded } = useStore();
  const { toast } = useUI();
  const now = useNow(1000);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useStoredState<Filter>('ghostlink-client-filter', 'all', FILTERS);
  const [mode, setMode] = useStoredState<'cards' | 'list'>('ghostlink-client-view', 'cards', ['cards', 'list']);
  const [openId, setOpenId] = useState<string | null>(null);
  const tools = useKeyTools(reloadUsers);

  const statusOf = (u: User): Status => clientStatus(u, liveById[u.id]);
  const bucket = (s: Status): Filter => (s === 'online' ? 'online' : s === 'idle' ? 'idle' : 'paused');
  const counts = useMemo(() => {
    const c = { all: users.length, online: 0, idle: 0, paused: 0 };
    for (const u of users) c[bucket(statusOf(u))]++;
    return c;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [users, liveById]);
  const shown = users.filter(u => (filter === 'all' || bucket(statusOf(u)) === filter) && (!query || [u.name, tunnelAddress(u) ?? '', lastClient[u.id]?.ip ?? ''].some(v => v.toLowerCase().includes(query.toLowerCase()))));

  const setEnabled = async (user: User, enabled: boolean) => {
    try {
      await api('PATCH', `/users/${user.id}`, { enabled });
      toast(enabled ? `${user.name} can connect again.` : `${user.name} is paused; their sessions end.`);
      await reloadUsers();
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };

  const open = users.find(u => u.id === openId) ?? null;

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <label className="inset-glass flex h-10 min-w-[220px] flex-1 items-center gap-2 rounded-full px-4 sm:max-w-sm">
          <Search size={16} className="text-fg-3" />
          <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search name, tunnel IP or endpoint" className="w-full bg-transparent text-[13.5px] outline-none placeholder:text-fg-3" aria-label="Search clients" />
        </label>
        <Segmented
          label="Status"
          value={filter}
          onChange={setFilter}
          options={FILTERS.map(f => ({ value: f, label: <span>{f === 'all' ? 'All' : statusLabel[f]} <span className="num text-fg-3">{counts[f]}</span></span> }))}
        />
        <Segmented
          className="ml-auto"
          label="Layout"
          value={mode}
          onChange={setMode}
          options={[
            { value: 'cards', label: 'Cards', icon: <LayoutGrid size={14} /> },
            { value: 'list', label: 'List', icon: <List size={14} /> },
          ]}
        />
      </div>

      {loaded && !users.length ? (
        <Card>
          <Empty icon={<UserPlus size={22} />} title="No clients yet">
            <p>A client is a person or device. Create one and Ghostlink issues its key, address and QR code.</p>
            <Button variant="cta" className="mt-4" icon={<UserPlus size={15} />} onClick={onNewClient}>
              New client
            </Button>
          </Empty>
        </Card>
      ) : !shown.length ? (
        <Card>
          <Empty icon={<Search size={20} />} title="No matching clients">
            Try another search or status.
          </Empty>
        </Card>
      ) : mode === 'cards' ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3 min-[112.5rem]:grid-cols-4 min-[143.75rem]:grid-cols-5">
          {shown.map(u => (
            <ClientCard key={u.id} user={u} status={statusOf(u)} now={now} onOpen={() => setOpenId(u.id)} onEnabled={on => setEnabled(u, on)} tools={tools} />
          ))}
        </div>
      ) : (
        <Card className="overflow-x-auto p-0 sm:p-0">
          <table className="w-full min-w-[1020px] border-collapse text-[13px]">
            <thead>
              <tr className="text-left text-[12px] text-fg-3">
                {['Client', 'Tunnel IP', 'Endpoint', 'Last handshake', 'Live', 'Usage', 'Speed limit', 'Access', ''].map(h => (
                  <th key={h} className="border-b border-line px-4 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map(u => {
                const live = liveById[u.id], status = statusOf(u), address = tunnelAddress(u);
                return (
                  <tr key={u.id} className="cursor-pointer transition hover:bg-glass" onClick={() => setOpenId(u.id)}>
                    <td className="border-b border-line px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className="grid size-8 place-items-center rounded-full bg-glass-strong text-fg-2">
                          <DeviceIcon user={u} size={15} />
                        </span>
                        <div>
                          <div className="font-medium text-fg">{u.name}</div>
                          <div className="flex items-center gap-1.5 text-[12px] text-fg-3">
                            <StatusDot status={status} className="scale-75" /> {statusLabel[status]}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="mono border-b border-line px-4 py-3 text-fg-2">{address ? `${address}/32` : '—'}</td>
                    <td className="mono border-b border-line px-4 py-3 text-fg-2">{lastClient[u.id]?.ip ?? '—'}</td>
                    <td className="num border-b border-line px-4 py-3 text-fg-2">{ago(live?.last_active_unix, now)}</td>
                    <td className="num border-b border-line px-4 py-3">
                      <span className="text-down">↓ {speed(live?.down_bps ?? 0)}</span> <span className="ml-2 text-up">↑ {speed(live?.up_bps ?? 0)}</span>
                    </td>
                    <td className="num border-b border-line px-4 py-3 text-fg-2">{u.data_limit_bytes ? `${bytes(u.usage_bytes)} of ${bytes(u.data_limit_bytes)}` : bytes(u.usage_bytes)}</td>
                    <td className="num border-b border-line px-4 py-3 text-fg-2">{speedLabel(u.effective_speed_limit_bps) || '—'}</td>
                    <td className="border-b border-line px-4 py-3">
                      <Switch checked={u.enabled} onChange={on => setEnabled(u, on)} label={`${u.name} may connect`} />
                    </td>
                    <td className="border-b border-line px-2 py-3 text-right">
                      <ChevronRight size={16} className="inline text-fg-3" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
      <p className="text-center text-[12px] text-fg-3">
        {plural(shown.length, 'client')} shown · live data every second
      </p>
      {tools.sheet}
      <ClientSheet user={open} onClose={() => setOpenId(null)} />
    </div>
  );
}

function ClientCard({ user, status, now, onOpen, onEnabled, tools }: {
  user: User;
  status: Status;
  now: number;
  onOpen: () => void;
  onEnabled: (on: boolean) => void;
  tools: ReturnType<typeof useKeyTools>;
}) {
  const { liveById, lastClient } = useStore();
  const live = liveById[user.id];
  const key = primaryKey(user);
  const address = tunnelAddress(user);
  return (
    <Card as="article" className="flex flex-col gap-3.5 sm:p-5">
      <div className="flex items-start gap-3">
        <button type="button" onClick={onOpen} className="grid size-11 shrink-0 place-items-center rounded-[16px] bg-glass-strong text-fg-2 transition hover:text-fg" aria-label={`Open ${user.name}`}>
          <DeviceIcon user={user} />
        </button>
        <button type="button" onClick={onOpen} className="min-w-0 flex-1 text-left">
          <h3 className="truncate text-[16px]">{user.name}</h3>
          <div className="mt-0.5 flex items-center gap-1.5 text-[12.5px] text-fg-2">
            <StatusDot status={status} /> {statusLabel[status]}
            <span className="text-fg-3">· {plural(user.keys.length, 'key')}</span>
            {user.effective_speed_limit_bps > 0 && (
              <span className="num ml-1 rounded-full bg-glass-strong px-2 py-0.5 text-[11.5px] text-fg-2" title="Speed limit, download and upload alike">
                {speedLabel(user.effective_speed_limit_bps)}
              </span>
            )}
          </div>
        </button>
        <Switch checked={user.enabled} onChange={onEnabled} label={`${user.name} may connect`} />
      </div>

      <div className="inset-glass grid grid-cols-2 gap-x-4 gap-y-2.5 rounded-[22px] px-4 py-3 text-[12.5px]">
        <Cell label="Tunnel IP" value={address ? `${address}/32` : '—'} mono />
        <Cell label="Endpoint" value={lastClient[user.id]?.ip ?? '—'} mono />
        <Cell label="Last handshake" value={ago(live?.last_active_unix, now)} />
        <div className="grid min-w-0 gap-0.5">
          <span className="text-fg-3">Live</span>
          <span className="num truncate">
            <span className="text-down">↓ {speed(live?.down_bps ?? 0)}</span> <span className="text-up">↑ {speed(live?.up_bps ?? 0)}</span>
          </span>
        </div>
      </div>

      <div className="grid gap-1.5">
        <div className="flex justify-between text-[12.5px]">
          <span className="text-fg-3">Data used</span>
          <span className="num text-fg-2">{user.data_limit_bytes ? `${bytes(user.usage_bytes)} of ${bytes(user.data_limit_bytes)}` : `${bytes(user.usage_bytes)} · no limit`}</span>
        </div>
        {user.data_limit_bytes > 0 && <Meter fraction={user.usage_bytes / user.data_limit_bytes} tone={user.over_limit ? 'bad' : 'fg'} />}
      </div>

      <div className="mt-auto flex items-center gap-1 border-t border-line pt-3">
        {key ? (
          <>
            {!isApple(key.protocol) && (
              <IconButton label="QR code" onClick={() => tools.showQR(user, key.id)}>
                <QrCode size={17} />
              </IconButton>
            )}
            {hasConf(key.protocol) && (
              <IconButton label="Download .conf" onClick={() => tools.downloadConf(user, key.id)}>
                <FileDown size={17} />
              </IconButton>
            )}
            {isApple(key.protocol) ? (
              <IconButton label="Download iPhone/Mac profile" onClick={() => tools.downloadProfile(user, key.id)}>
                <FileDown size={17} />
              </IconButton>
            ) : (
              <IconButton label="Copy key" onClick={() => tools.copyKey(user, key.id)}>
                <Copy size={16} />
              </IconButton>
            )}
            <IconButton label="Revoke key" className="hover:text-bad" onClick={() => tools.revoke(user, key)}>
              <Trash2 size={16} />
            </IconButton>
            <span className="ml-1 truncate text-[12px] text-fg-3">{protocolName(key.protocol)}</span>
          </>
        ) : (
          <Button size="sm" icon={<KeyRound size={14} />} onClick={onOpen}>
            Create a key
          </Button>
        )}
        <Button size="sm" variant="ghost" className={cx('ml-auto')} onClick={onOpen}>
          Details <ChevronRight size={14} />
        </Button>
      </div>
    </Card>
  );
}

function Cell({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <span className="text-fg-3">{label}</span>
      <span className={cx('truncate text-fg', mono ? 'mono' : 'num')} title={value}>
        {value}
      </span>
    </div>
  );
}
