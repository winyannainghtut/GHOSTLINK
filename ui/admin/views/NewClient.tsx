// New client: name, protocol and an optional data limit. The server creates the client and its
// key (WireGuard-family keys get the next free /32 and a fresh Curve25519 key pair), then the
// sheet shows the QR code, the .conf and the share options.
import { Check as CheckIcon, Copy, FileDown, KeyRound, MonitorDown } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Button, Field, Inner, Note, Sheet, cx, useUI } from '@shared/glass';
import { AUTH, KEY_PROTOCOLS, PROTOCOLS, PROTOCOL_HINTS, api, canUseHere, useHere, type Key, type ProtocolId, type User } from '../api';
import { hasConf, isApple, qrFor, saveConf, saveKit, saveProfile } from '../keys';
import { useStore } from '../store';

type Created = { user: User; key: Key; qr?: string };

export function NewClient({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { server, reloadUsers, reloadServer } = useStore();
  const { toast } = useUI();
  const available = KEY_PROTOCOLS.filter(p => server.protocols[p]?.enabled);
  const [name, setName] = useState('');
  const [protocol, setProtocol] = useState<ProtocolId>('amneziawg');
  const [auth, setAuth] = useState('eap');
  const [limit, setLimit] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<Created | null>(null);

  useEffect(() => {
    if (!open) return;
    setName('');
    setLimit('');
    setError('');
    setCreated(null);
    setProtocol(available.includes('amneziawg') ? 'amneziawg' : available[0] ?? 'amneziawg');
    reloadServer().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  useEffect(() => {
    if (isApple(protocol)) setAuth(AUTH[protocol as 'ikev2' | 'ipsec'][0][0]);
  }, [protocol]);

  const pool = server.address_pools?.find(p => p.protocol === protocol);
  const run = async (work: () => Promise<string>) => {
    try {
      toast(await work());
    } catch (e) {
      toast((e as Error).message, 'bad');
    }
  };

  const create = async () => {
    setBusy(true);
    setError('');
    let user: User | null = null;
    try {
      const body: Record<string, unknown> = { name: name.trim() };
      if (limit.trim()) body.data_limit_bytes = Math.round(Number(limit) * 1e9);
      user = await api<User>('POST', '/users', body);
      const key = await api<Key>('POST', `/users/${user.id}/keys`, isApple(protocol) ? { protocol, auth } : { protocol });
      let qr: string | undefined;
      if (!isApple(protocol)) qr = await qrFor(user, key, key.config ? 'conf' : 'key');
      setCreated({ user, key, qr });
      if (key.warning) toast(key.warning, 'info');
      await Promise.all([reloadUsers(), reloadServer()]);
    } catch (e) {
      setError(user ? `${user.name} was created, but the key was not: ${(e as Error).message}` : (e as Error).message);
      if (user) await reloadUsers();
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    const { user, key } = created;
    return (
      <Sheet
        open={open}
        onClose={onClose}
        title={`${user.name} is ready`}
        subtitle={`${PROTOCOLS[key.protocol]} key, generated on the server`}
        footer={
          <Button variant="cta" icon={<CheckIcon size={15} />} onClick={onClose}>
            Done
          </Button>
        }
      >
        <div className="grid gap-5 sm:grid-cols-[minmax(0,300px)_1fr] sm:items-center">
          {created.qr ? (
            <img src={created.qr} alt={`QR code for ${user.name}`} className="w-full rounded-[24px] bg-white p-4" />
          ) : (
            <Inner className="grid aspect-square place-items-center text-center text-[13px] text-fg-3">The iPhone, iPad or Mac installs this VPN from a profile instead of a QR code.</Inner>
          )}
          <div className="grid gap-3">
            {key.config && (
              <Inner className="grid gap-1 text-[13px]">
                <span className="text-fg-3">Tunnel IP</span>
                <span className="mono text-[15px]">{key.config.match(/Address\s*=\s*([\d.]+\/\d+)/)?.[1] ?? '—'}</span>
              </Inner>
            )}
            <p className="text-[13px] text-fg-2">
              {key.config ? 'Scan the code with the WireGuard or AmneziaWG app, or send the .conf file.' : isApple(key.protocol) ? 'Download the profile and send it privately (AirDrop, Mail or Files).' : 'Scan the code with the app, or copy the key.'}
            </p>
            <div className="flex flex-wrap gap-2">
              {hasConf(key.protocol) && key.config && (
                <Button icon={<FileDown size={14} />} onClick={() => run(() => saveConf(user, key))}>
                  Download .conf
                </Button>
              )}
              {isApple(key.protocol) ? (
                <Button
                  variant="cta"
                  icon={<FileDown size={14} />}
                  onClick={() => run(() => saveProfile(user, key))}
                >
                  Download profile
                </Button>
              ) : (
                <Button icon={<Copy size={14} />} onClick={() => navigator.clipboard.writeText(key.access_key).then(() => toast('Key copied.'))}>
                  Copy key
                </Button>
              )}
              {canUseHere() && !isApple(key.protocol) && (
                <Button icon={<MonitorDown size={14} />} onClick={() => run(async () => (await useHere(user, key), 'Saved under My servers on this device.'))}>
                  Use on this device
                </Button>
              )}
              <Button variant="ghost" icon={<FileDown size={14} />} onClick={() => run(() => saveKit(user))}>
                Connection kit
              </Button>
            </div>
            <Note>Share these only with {user.name}: anyone holding them can use this connection.</Note>
          </div>
        </div>
      </Sheet>
    );
  }

  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="New client"
      subtitle="A person or device. Ghostlink issues its key, address and QR code."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="cta" icon={<KeyRound size={15} />} disabled={busy || !name.trim() || !available.includes(protocol)} onClick={create}>
            {busy ? 'Creating…' : 'Create client'}
          </Button>
        </>
      }
    >
      <form
        className="grid gap-5"
        onSubmit={event => {
          event.preventDefault();
          if (name.trim()) create();
        }}
      >
        <Field label="Name">
          <input className="field" autoFocus maxLength={64} value={name} onChange={e => setName(e.target.value)} placeholder="For example Maya's phone" />
        </Field>
        <div className="grid gap-2">
          <span className="text-[12.5px] font-medium text-fg-2">Protocol</span>
          <div className="grid gap-2 sm:grid-cols-2">
            {KEY_PROTOCOLS.map(p => {
              const on = available.includes(p);
              return (
                <button
                  key={p}
                  type="button"
                  disabled={!on}
                  onClick={() => setProtocol(p)}
                  aria-pressed={protocol === p}
                  className={cx(
                    'rounded-[20px] border px-4 py-3 text-left transition',
                    protocol === p ? 'border-fg/40 bg-glass-strong shadow-[inset_0_1px_0_var(--highlight)]' : 'border-line bg-field hover:bg-glass-strong',
                  )}
                >
                  <div className="flex items-center justify-between text-[13.5px] font-medium">
                    {PROTOCOLS[p]}
                    {protocol === p && <CheckIcon size={15} />}
                  </div>
                  <div className="mt-0.5 text-[12px] text-fg-3">{on ? PROTOCOL_HINTS[p] : 'Off on this server'}</div>
                </button>
              );
            })}
          </div>
        </div>
        {isApple(protocol) && (
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
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Data limit" hint="GB, optional">
            <input className="field num" type="number" min="0" step="any" inputMode="decimal" value={limit} onChange={e => setLimit(e.target.value)} placeholder="No limit" />
          </Field>
          <Inner className="grid content-center gap-0.5 rounded-[20px] px-4 py-2.5">
            <span className="text-[12px] text-fg-3">Tunnel address</span>
            {pool ? (
              <span className="mono text-[14px]">{pool.next ? `${pool.next}/32` : 'Pool full'}</span>
            ) : (
              <span className="text-[13px] text-fg-2">{isApple(protocol) ? 'From the IKEv2 pool' : 'Not needed'}</span>
            )}
          </Inner>
        </div>
        <Note>
          {pool ? 'The next free address is assigned automatically and a new Curve25519 key pair is generated on the server.' : 'The key is generated on the server.'} You can add more keys for other protocols later.
        </Note>
        {error && <Note tone="bad">{error}</Note>}
        <button type="submit" hidden />
      </form>
    </Sheet>
  );
}
