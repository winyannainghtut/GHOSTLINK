// Actions on a client's keys, shared by the client cards, the list, the client sheet and the
// new-client flow. Files go through the transport (a download in the dashboard, the Downloads
// folder in the desktop app).
import { Copy, Globe, Laptop, Smartphone, UserRound } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { confName, fileSafe } from '@shared/format';
import { Button, Sheet, useUI } from '@shared/glass';
import { APPLE, protocolName, svgURL, type Key, type KeySummary, type ServerApi, type User } from './api';
import { useApi } from './store';

export const isApple = (protocol: string) => (APPLE as string[]).includes(protocol);
export const hasConf = (protocol: string) => protocol === 'wireguard' || protocol === 'amneziawg';

// The key a card's quick actions use: the newest app key, else the newest Apple key.
export function primaryKey(user: User): KeySummary | undefined {
  const newest = [...user.keys].sort((a, b) => b.created_unix - a.created_unix);
  return newest.find(k => !isApple(k.protocol)) ?? newest[0];
}

export function tunnelAddress(user: User): string | undefined {
  return user.keys.find(k => k.address)?.address;
}

export function DeviceIcon({ user, size = 18 }: { user: User; size?: number }) {
  const protocols = user.keys.map(k => k.protocol);
  if (protocols.some(isApple)) return <Smartphone size={size} />;
  if (protocols.some(hasConf)) return <Laptop size={size} />;
  if (protocols.length) return <Globe size={size} />;
  return <UserRound size={size} />;
}

const saved = (where: string | null, what: string) => (where ? `${what} saved to ${where}.` : `${what} downloaded.`);

// Each takes the API of the server the key is on (useApi).
export async function saveConf({ saveFile }: ServerApi, user: User, key: Key): Promise<string> {
  if (!key.config) throw new Error('This key has no .conf file.');
  const where = await saveFile({ name: confName(user.name, key.protocol, key.id), extension: 'conf', content: key.config, mime: 'text/plain' });
  return saved(where, '.conf') + ' Import it in the WireGuard or AmneziaWG app.';
}

export async function saveProfile({ apiText, saveFile }: ServerApi, user: User, key: Key, askPassword = false): Promise<string> {
  const content = await apiText(`/users/${user.id}/keys/${key.id}/profile${askPassword ? '?prompt_password=1' : ''}`);
  const where = await saveFile({ name: `${fileSafe(user.name)}-${key.protocol}-${key.id}`, extension: 'mobileconfig', content, mime: 'application/x-apple-aspen-config' });
  return askPassword
    ? `${saved(where, 'Profile')} It has no password inside: the device asks for the certificate's password while installing, so give it to ${user.name} separately.`
    : `${saved(where, 'Profile')} Send it privately (AirDrop, Mail or Files); opening it installs the VPN.`;
}

export async function saveKit({ apiText, saveFile }: ServerApi, user: User): Promise<string> {
  const where = await saveFile({ name: `${fileSafe(user.name)}-vpn`, extension: 'html', content: await apiText(`/users/${user.id}/kit`), mime: 'text/html' });
  return `${saved(where, 'Connection kit')} It contains ${user.name}'s keys: send it privately.`;
}

export async function qrFor({ apiText }: ServerApi, user: User, key: Key, content: 'conf' | 'key'): Promise<string> {
  return svgURL(await apiText(`/users/${user.id}/keys/${key.id}/qr?format=svg&content=${content}`));
}

const scanHint = (key: Key, content: string) =>
  content === 'conf'
    ? 'Scan with the WireGuard or AmneziaWG app: + → Scan from QR code.'
    : key.protocol === 'shadowsocks'
      ? 'Scan with Outline, Shadowrocket or v2rayNG.'
      : key.protocol === 'vless'
        ? 'Scan with v2rayNG, Hiddify, Streisand or Shadowrocket.'
        : 'Scan with the AmneziaVPN app.';

export function useKeyTools(onChanged?: () => void) {
  const { toast, confirm } = useUI();
  const server = useApi();
  const { api } = server;
  const [qr, setQr] = useState<{ url: string; title: string; note: string } | null>(null);
  // A profile saved without its password: the password stays on screen until the admin is done,
  // rather than in a toast that disappears.
  const [secret, setSecret] = useState<{ title: string; note: string; password: string } | null>(null);

  const full = async (user: User, id: string) => {
    const keys = await api<Key[]>('GET', `/users/${user.id}/keys`);
    const key = keys.find(k => k.id === id);
    if (!key) throw new Error('That key no longer exists.');
    return key;
  };
  const run = async (work: () => Promise<void>) => {
    try {
      await work();
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };

  const tools = {
    canUseHere: server.canUseHere,
    showQR: (user: User, id: string, content: 'auto' | 'conf' | 'key' = 'auto') =>
      run(async () => {
        const key = await full(user, id);
        const kind = content === 'auto' ? (key.config ? 'conf' : 'key') : content;
        setQr({ url: await qrFor(server, user, key, kind), title: `${protocolName(key.protocol)} · ${user.name}`, note: scanHint(key, kind) });
      }),
    downloadConf: (user: User, id: string) => run(async () => toast(await saveConf(server, user, await full(user, id)))),
    copyKey: (user: User, id: string) =>
      run(async () => {
        const key = await full(user, id);
        await navigator.clipboard.writeText(key.access_key);
        toast('Key copied. Share it only with ' + user.name + '.');
      }),
    downloadProfile: (user: User, id: string, askPassword = false) =>
      run(async () => {
        const key = await full(user, id);
        const note = await saveProfile(server, user, key, askPassword);
        if (askPassword && key.certificate_password) setSecret({ title: `Password for ${user.name}'s profile`, note, password: key.certificate_password });
        else toast(note);
      }),
    downloadKit: (user: User) => run(async () => toast(await saveKit(server, user))),
    useHere: (user: User, id: string) =>
      run(async () => {
        await server.useHere(user, await full(user, id));
        toast('Saved under My servers on this device.');
      }),
    revoke: (user: User, key: KeySummary) =>
      run(async () => {
        const yes = await confirm({ title: `Revoke this ${protocolName(key.protocol)} key?`, text: `Anyone using it is disconnected at once. ${user.name}'s other keys keep working.`, action: 'Revoke key', danger: true });
        if (!yes) return;
        await api('DELETE', `/users/${user.id}/keys/${key.id}`);
        toast('Key revoked.');
        onChanged?.();
      }),
  };

  const sheet: ReactNode = (
    <>
      <Sheet open={qr !== null} onClose={() => setQr(null)} title={qr?.title ?? ''} subtitle="Scan with the phone's VPN app" footer={<Button variant="cta" onClick={() => setQr(null)}>Done</Button>}>
        {qr && (
          <div className="grid justify-items-center gap-4">
            <img src={qr.url} alt="QR code" className="w-full max-w-[300px] rounded-[24px] bg-white p-4" />
            <p className="text-center text-[13px] text-fg-3">{qr.note}</p>
          </div>
        )}
      </Sheet>
      <Sheet
        open={secret !== null}
        onClose={() => setSecret(null)}
        title={secret?.title ?? ''}
        footer={
          <>
            <Button icon={<Copy size={14} />} onClick={() => secret && navigator.clipboard.writeText(secret.password).then(() => toast('Password copied.'), () => toast('Could not copy the password.', 'bad'))}>
              Copy password
            </Button>
            <Button variant="cta" onClick={() => setSecret(null)}>
              Done
            </Button>
          </>
        }
      >
        {secret && (
          <div className="grid gap-3">
            <p className="text-[13px] text-fg-2">{secret.note}</p>
            <input className="field mono" readOnly spellCheck={false} aria-label="Certificate password" value={secret.password} onFocus={e => e.currentTarget.select()} />
          </div>
        )}
      </Sheet>
    </>
  );
  return { ...tools, sheet };
}
