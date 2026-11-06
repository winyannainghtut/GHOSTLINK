// My servers: the connection, and the servers saved on this device (from access keys or
// WireGuard/AmneziaWG files).
import { Eye, EyeOff, FileUp, Info as InfoIcon, KeyRound, MoreHorizontal, Pencil, Power, Route, Search, Star, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { MenuItem, Popover } from '@shared/Popover';
import { bytes, speed } from '@shared/format';
import { Button, Card, Empty, Facts, Field, IconButton, Note, Sheet, StatusDot, cx, useUI } from '@shared/glass';
import { KEY_PREFIXES, KINDS, KIND_DETAIL, isActive, request, slug, stateLabel, uniqueName, type ConnectionState, type Profile } from '../ipc';
import { useService } from '../service';
import { SplitSheet } from './SplitSheet';

function clock(seconds: number): string {
  return [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60].map(n => String(n).padStart(2, '0')).join(':');
}

export function MyServers({ addKeySignal }: { addKeySignal: number }) {
  const { info, profiles, available, error, act, busy } = useService();
  const [query, setQuery] = useState('');
  const [adding, setAdding] = useState(false);
  const [details, setDetails] = useState<Profile | null>(null);
  const [renaming, setRenaming] = useState<Profile | null>(null);
  const [split, setSplit] = useState<Profile | null | undefined>(undefined);
  const { confirm } = useUI();
  useEffect(() => {
    if (addKeySignal) setAdding(true);
  }, [addKeySignal]);

  const c = info?.connection;
  const current = profiles.find(p => p.name === c?.profile);
  const fallback = profiles.find(p => p.is_default) ?? profiles[0];
  const target = current ?? fallback;
  const shown = profiles.filter(p => `${p.display_name} ${p.name} ${p.remotes[0]?.host ?? ''}`.toLowerCase().includes(query.toLowerCase()));

  const toggle = (p: Profile | undefined) => {
    if (!p) return;
    if (c && isActive(c.status) && c.profile === p.name) return act({ type: 'disconnect' }, 'Disconnected.');
    if (c && c.status !== 'disconnected' && c.status !== 'failed') return act({ type: 'switch', profile: p.name });
    return act({ type: 'connect', profile: p.name });
  };
  const headline = !available ? 'VPN service unavailable' : c?.status === 'connected' ? 'You’re connected.' : c?.status === 'failed' ? 'Could not connect.' : c && isActive(c.status) ? stateLabel[c.status] : 'Ready when you are.';
  const caption = !available
    ? `${error} Start the installed Ghostlink service, then try again.`
    : c?.status === 'connected'
      ? `Through ${current?.display_name || current?.name}${c.vpn_ip ? `, tunnel address ${c.vpn_ip}` : ''}.`
      : c?.status === 'failed'
        ? c.last_error || 'Check your key, then the diagnostics in Settings.'
        : c && isActive(c.status)
          ? `Connecting to ${current?.display_name || current?.name}…`
          : profiles.length
            ? `Choose a server below, or connect to ${target?.display_name || target?.name}.`
            : 'Add an access key to get started.';
  const on = !!c && isActive(c.status);

  return (
    <div className="grid gap-4">
      <Card className="grid gap-6 md:grid-cols-[1fr_auto] md:items-center">
        <div className="grid gap-5">
          <div>
            <h1 className="text-[30px] leading-tight tracking-[-0.03em]">{headline}</h1>
            <p className="mt-1.5 max-w-xl text-[13.5px] text-fg-2">{caption}</p>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Duration" value={c?.status === 'connected' ? clock(c.connected_duration_seconds) : '—'} mono />
            <Stat label="Downloaded" value={c?.status === 'connected' ? bytes(c.bytes_received) : '—'} />
            <Stat label="Uploaded" value={c?.status === 'connected' ? bytes(c.bytes_sent) : '—'} />
            <Stat label="Live" value={c?.status === 'connected' ? `↓ ${speed(c.receive_bytes_per_second)}` : '—'} sub={c?.status === 'connected' ? `↑ ${speed(c.send_bytes_per_second)}` : undefined} />
          </div>
        </div>
        <button
          type="button"
          disabled={!available || busy || !target || c?.status === 'disconnecting'}
          onClick={() => toggle(target)}
          aria-label={on ? 'Disconnect' : `Connect to ${target?.display_name || target?.name || 'a server'}`}
          className={cx(
            'group relative mx-auto grid size-36 place-items-center rounded-full border transition duration-500 active:scale-95 disabled:opacity-50',
            on ? 'border-ok/50 bg-ok/15 text-ok shadow-[0_0_60px_-10px_var(--ok)]' : 'inset-glass text-fg-2 hover:text-fg',
          )}
        >
          {c && (c.status === 'connecting' || c.status === 'reconnecting') && <span className="absolute inset-2 animate-ping rounded-full border border-idle/40 motion-reduce:animate-none" />}
          <span className="grid justify-items-center gap-1.5">
            <Power size={34} strokeWidth={1.8} />
            <span className="text-[12px] font-medium">{on ? 'Disconnect' : 'Connect'}</span>
          </span>
        </button>
      </Card>

      <div className="flex flex-wrap items-center gap-3">
        <label className="inset-glass flex h-10 min-w-[220px] flex-1 items-center gap-2 rounded-full px-4 sm:max-w-sm">
          <Search size={16} className="text-fg-3" />
          <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search servers" className="w-full bg-transparent text-[13.5px] outline-none placeholder:text-fg-3" aria-label="Search servers" />
        </label>
        <span className="num text-[12.5px] text-fg-3">{profiles.length} on this device</span>
      </div>

      {!profiles.length ? (
        <Card>
          <Empty icon={<KeyRound size={22} />} title="No servers yet">
            <p>Paste an access key from your server administrator: Outline, VLESS or Amnezia. Or import a WireGuard or AmneziaWG .conf file.</p>
            <Button variant="cta" className="mt-4" icon={<KeyRound size={15} />} onClick={() => setAdding(true)}>
              Add access key
            </Button>
          </Empty>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {shown.map(p => (
            <ServerCard
              key={p.name}
              profile={p}
              status={c?.profile === p.name ? c.status : 'disconnected'}
              disabled={!available || busy}
              onToggle={() => toggle(p)}
              onDetails={() => setDetails(p)}
              onRename={() => setRenaming(p)}
              onDefault={() => act({ type: 'profile_default', name: p.name }, `${p.display_name || p.name} is the default server.`)}
              onSplit={p.kind !== 'openvpn' ? () => setSplit(p) : undefined}
              onRemove={async () => {
                if (await confirm({ title: `Remove ${p.display_name || p.name}?`, text: 'This removes it from this device. You need its access key to add it again.', action: 'Remove server', danger: true })) act({ type: 'profile_remove', name: p.name }, 'Server removed.');
              }}
            />
          ))}
        </div>
      )}

      <AddKeySheet open={adding} onClose={() => setAdding(false)} />
      <Sheet open={details !== null} onClose={() => setDetails(null)} title={details?.display_name || details?.name || ''} subtitle="Connection details" footer={<Button variant="cta" onClick={() => setDetails(null)}>Done</Button>}>
        {details && (
          <Facts
            rows={[
              ['Server ID', <span className="mono">{details.name}</span>],
              ['Address', <span className="mono">{details.remotes.map(r => `${r.host}:${r.port}`).join(', ') || 'Fetched when connecting'}</span>],
              ['Transport', KIND_DETAIL[details.kind] ?? details.kind],
              ['Tunnel', details.tunnel_mode === 'full' ? 'Full tunnel' : 'Split tunnel'],
              ['Default', details.is_default ? 'Yes' : 'No'],
              ...(details.certificate_expires_unix ? [['Certificate expiry', new Date(details.certificate_expires_unix * 1000).toLocaleDateString()] as [string, string]] : []),
            ]}
          />
        )}
      </Sheet>
      <RenameSheet profile={renaming} onClose={() => setRenaming(null)} />
      <SplitSheet profile={split} onClose={() => setSplit(undefined)} />
    </div>
  );
}

function Stat({ label, value, sub, mono }: { label: string; value: string; sub?: string; mono?: boolean }) {
  return (
    <div className="inset-glass rounded-[20px] px-4 py-3">
      <div className="text-[12px] text-fg-3">{label}</div>
      <div className={cx('mt-0.5 truncate text-[16px] font-medium', mono ? 'mono' : 'num')}>{value}</div>
      {sub && <div className="num truncate text-[12px] text-fg-2">{sub}</div>}
    </div>
  );
}

function ServerCard({ profile, status, disabled, onToggle, onDetails, onRename, onDefault, onSplit, onRemove }: {
  profile: Profile;
  status: ConnectionState;
  disabled: boolean;
  onToggle: () => void;
  onDetails: () => void;
  onRename: () => void;
  onDefault: () => void;
  onSplit?: () => void;
  onRemove: () => void;
}) {
  const [menu, setMenu] = useState(false);
  const anchor = useRef<HTMLButtonElement>(null);
  const title = profile.display_name || profile.name;
  const remote = profile.remotes[0];
  const on = isActive(status);
  const pick = (fn: () => void) => () => (setMenu(false), fn());
  return (
    <Card as="article" className={cx('flex flex-col gap-4 sm:p-5', status === 'connected' && 'border-ok/40')}>
      <div className="flex items-start gap-3">
        <div className="grid size-11 shrink-0 place-items-center rounded-[16px] bg-glass-strong text-[13px] font-semibold text-fg-2">{title.slice(0, 2).toUpperCase()}</div>
        <div className="min-w-0 flex-1">
          <h3 className="flex items-center gap-1.5 truncate text-[16px]">
            {title}
            {profile.is_default && <Star size={13} className="shrink-0 fill-current text-idle" aria-label="Default server" />}
          </h3>
          <div className="mono mt-0.5 truncate text-[12px] text-fg-3">{remote ? `${remote.host}:${remote.port}` : 'Fetched when connecting'}</div>
        </div>
        <IconButton ref={anchor} label={`Options for ${title}`} aria-expanded={menu} onClick={() => setMenu(!menu)}>
          <MoreHorizontal size={18} />
        </IconButton>
        <Popover anchor={anchor} open={menu} onClose={() => setMenu(false)} width={210}>
          <MenuItem icon={<InfoIcon size={15} />} onClick={pick(onDetails)}>
            Connection details
          </MenuItem>
          <MenuItem icon={<Pencil size={15} />} onClick={pick(onRename)}>
            Rename
          </MenuItem>
          {!profile.is_default && (
            <MenuItem icon={<Star size={15} />} onClick={pick(onDefault)}>
              Make default
            </MenuItem>
          )}
          {onSplit && (
            <MenuItem icon={<Route size={15} />} onClick={pick(onSplit)}>
              Split tunneling
            </MenuItem>
          )}
          <MenuItem danger icon={<Trash2 size={15} />} onClick={pick(onRemove)}>
            Remove server
          </MenuItem>
        </Popover>
      </div>
      <div className="flex items-center justify-between gap-3 border-t border-line pt-3">
        <span className="flex items-center gap-2 text-[12.5px] text-fg-2">
          <StatusDot status={status === 'connected' ? 'online' : status === 'failed' ? 'limit' : on ? 'pending' : 'offline'} />
          {stateLabel[status]}
          <span className="inset-glass rounded-full px-2 py-0.5 text-[11px] text-fg-3">{KINDS[profile.kind] ?? profile.kind}</span>
        </span>
        <Button size="sm" variant={on ? 'danger' : 'cta'} icon={<Power size={13} />} disabled={disabled || status === 'disconnecting'} onClick={onToggle}>
          {on ? 'Disconnect' : 'Connect'}
        </Button>
      </div>
    </Card>
  );
}

function AddKeySheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { profiles, refresh } = useService();
  const { toast } = useUI();
  const [name, setName] = useState('');
  const [key, setKey] = useState('');
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const file = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!open) {
      setKey('');
      setReveal(false);
    } else {
      setName('');
      setError('');
    }
  }, [open]);
  const taken = profiles.map(p => p.name);
  const finish = async (id: string, displayName: string) => {
    if (displayName) await request({ type: 'profile_rename', name: id, display_name: displayName.slice(0, 80) });
    await refresh();
    toast(`${displayName || id} added.`);
    onClose();
  };
  const add = async () => {
    const source = key.trim();
    if (!KEY_PREFIXES.some(p => source.startsWith(p))) {
      setError('Paste a key beginning with ss://, ssconf://, vless:// or vpn://, or import a WireGuard file.');
      return;
    }
    setBusy(true);
    setError('');
    const id = uniqueName(slug(name.trim() || 'server'), taken);
    try {
      await request({ type: 'access_key_import', name: id, access_key: source });
      setKey('');
      await finish(id, name.trim());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  // WireGuard/AmneziaWG files are read here and sent straight to the service.
  const importFile = async (f: File) => {
    setError('');
    if (f.size > 65536) {
      setError('That file is too large to be a WireGuard configuration.');
      return;
    }
    const displayName = name.trim() || f.name.replace(/\.(conf|txt)$/i, '');
    const id = uniqueName(slug(displayName), taken);
    try {
      await request({ type: 'profile_import', name: id, content: await f.text() });
      await finish(id, displayName);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="Add access key"
      subtitle="Paste the key shared by your server administrator: Outline, VLESS or Amnezia."
      footer={
        <>
          <Button variant="ghost" icon={<FileUp size={15} />} onClick={() => file.current?.click()}>
            Import a .conf file
          </Button>
          <Button variant="cta" disabled={busy || !key.trim()} onClick={add}>
            {busy ? 'Adding…' : 'Add server'}
          </Button>
        </>
      }
    >
      <form
        className="grid gap-4"
        onSubmit={e => {
          e.preventDefault();
          add();
        }}
      >
        <Field label="Name on this device">
          <input className="field" maxLength={80} value={name} onChange={e => setName(e.target.value)} placeholder="For example Singapore" autoComplete="off" autoFocus />
        </Field>
        <Field label="Access key">
          <div className="relative">
            <input className="field mono pr-12" type={reveal ? 'text' : 'password'} value={key} onChange={e => setKey(e.target.value)} placeholder="ss://, ssconf://, vless:// or vpn://" autoComplete="off" spellCheck={false} />
            <IconButton label={reveal ? 'Hide key' : 'Show key'} className="absolute top-0.5 right-1" onClick={() => setReveal(!reveal)}>
              {reveal ? <EyeOff size={16} /> : <Eye size={16} />}
            </IconButton>
          </div>
        </Field>
        <Note>The key holds private credentials. Ghostlink keeps it in the local service and never puts it in logs or connection details.</Note>
        {error && <Note tone="bad">{error}</Note>}
        <input
          ref={file}
          type="file"
          accept=".conf,.txt"
          hidden
          onChange={e => {
            const f = e.target.files?.[0];
            e.target.value = '';
            if (f) importFile(f);
          }}
        />
        <button type="submit" hidden />
      </form>
    </Sheet>
  );
}

function RenameSheet({ profile, onClose }: { profile: Profile | null; onClose: () => void }) {
  const { act } = useService();
  const [value, setValue] = useState('');
  useEffect(() => setValue(profile?.display_name || profile?.name || ''), [profile]);
  const save = async () => {
    if (profile && value.trim() && (await act({ type: 'profile_rename', name: profile.name, display_name: value.trim() }, 'Renamed.'))) onClose();
  };
  return (
    <Sheet
      open={profile !== null}
      onClose={onClose}
      title="Rename server"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="cta" onClick={save}>
            Save name
          </Button>
        </>
      }
    >
      <form
        onSubmit={e => {
          e.preventDefault();
          save();
        }}
      >
        <Field label="Name">
          <input className="field" maxLength={80} value={value} onChange={e => setValue(e.target.value)} autoFocus />
        </Field>
      </form>
    </Sheet>
  );
}
