// Actions on a client's keys, shared by the client cards, the list and the client sheet.
import { Smartphone, Laptop, Globe, UserRound } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { fileSafe, saveBlob } from '@shared/format';
import { Button, Sheet, useUI } from '@shared/glass';
import { APPLE, api, apiBlob, protocolName, type Key, type KeySummary, type User } from './api';

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
  const [qr, setQr] = useState<{ url: string; title: string; note: string } | null>(null);
  useEffect(() => () => {
    if (qr?.url) URL.revokeObjectURL(qr.url);
  }, [qr]);

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
    showQR: (user: User, id: string, content: 'auto' | 'conf' | 'key' = 'auto') =>
      run(async () => {
        const key = await full(user, id);
        const kind = content === 'auto' ? (key.config ? 'conf' : 'key') : content;
        const blob = await apiBlob(`/users/${user.id}/keys/${key.id}/qr?format=svg&content=${kind}`);
        setQr({ url: URL.createObjectURL(blob), title: `${protocolName(key.protocol)} · ${user.name}`, note: scanHint(key, kind) });
      }),
    downloadConf: (user: User, id: string) =>
      run(async () => {
        const key = await full(user, id);
        if (!key.config) throw new Error('This key has no .conf file.');
        saveBlob(new Blob([key.config], { type: 'text/plain' }), `${fileSafe(user.name)}-${key.protocol}-${key.id}.conf`);
        toast('.conf downloaded. Import it in the WireGuard or AmneziaWG app.');
      }),
    copyKey: (user: User, id: string) =>
      run(async () => {
        const key = await full(user, id);
        await navigator.clipboard.writeText(key.access_key);
        toast('Key copied. Share it only with ' + user.name + '.');
      }),
    copyConf: (user: User, id: string) =>
      run(async () => {
        const key = await full(user, id);
        await navigator.clipboard.writeText(key.config ?? '');
        toast('.conf copied.');
      }),
    downloadProfile: (user: User, id: string, askPassword = false) =>
      run(async () => {
        const key = await full(user, id);
        const blob = await apiBlob(`/users/${user.id}/keys/${key.id}/profile${askPassword ? '?prompt_password=1' : ''}`);
        saveBlob(blob, `${fileSafe(user.name)}-${key.protocol}-${key.id}.mobileconfig`);
        toast(
          askPassword
            ? `Profile saved without its password. Give ${user.name} this password separately: ${key.certificate_password}`
            : 'Profile saved. Send it privately (AirDrop, Mail or Files); opening it installs the VPN.',
          askPassword ? 'info' : 'ok',
        );
      }),
    downloadKit: (user: User) =>
      run(async () => {
        saveBlob(await apiBlob(`/users/${user.id}/kit`), `${fileSafe(user.name)}-vpn.html`);
        toast('Connection kit saved. It contains ' + user.name + "'s keys: send it privately.");
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
    <Sheet open={qr !== null} onClose={() => setQr(null)} title={qr?.title ?? ''} subtitle="Scan with the phone's VPN app" footer={<Button variant="cta" onClick={() => setQr(null)}>Done</Button>}>
      {qr && (
        <div className="grid justify-items-center gap-4">
          <img src={qr.url} alt="QR code" className="w-full max-w-[300px] rounded-[24px] bg-white p-4" />
          <p className="text-center text-[13px] text-fg-3">{qr.note}</p>
        </div>
      )}
    </Sheet>
  );
  return { ...tools, sheet };
}
