// The dashboard talks only to this server's /api (session cookie plus the CSRF header).
import type { Topology } from '@shared/MeshMap';

export type ProtocolId = 'amneziawg' | 'wireguard' | 'vless' | 'shadowsocks' | 'ikev2' | 'ipsec';
export const PROTOCOLS: Record<ProtocolId, string> = {
  amneziawg: 'AmneziaWG',
  wireguard: 'WireGuard',
  vless: 'VLESS-REALITY',
  shadowsocks: 'Shadowsocks',
  ikev2: 'IKEv2',
  ipsec: 'IPsec',
};
export const PROTOCOL_HINTS: Record<ProtocolId, string> = {
  amneziawg: 'Obfuscated WireGuard, hard to block',
  wireguard: 'Fast, any WireGuard app',
  vless: 'Looks like ordinary HTTPS',
  shadowsocks: 'Outline-compatible',
  ikev2: 'Built-in VPN of iPhone, iPad and Mac',
  ipsec: 'Older Apple devices (legacy)',
};
export const KEY_PROTOCOLS: ProtocolId[] = ['amneziawg', 'wireguard', 'vless', 'shadowsocks', 'ikev2', 'ipsec'];
export const APPLE: ProtocolId[] = ['ikev2', 'ipsec'];
export const AUTH: Record<'ikev2' | 'ipsec', [string, string][]> = {
  ikev2: [
    ['eap', 'Username and password'],
    ['certificate', 'Certificate'],
  ],
  ipsec: [
    ['certificate', 'Certificate'],
    ['psk', 'Shared group key (weak)'],
  ],
};
export const protocolName = (p: string) => PROTOCOLS[p as ProtocolId] ?? p;

export type Rules = { blocked_domains: string[]; blocked_ips: string[]; blocked_ports: string[]; block_bittorrent: boolean; block_smtp: boolean };
export type KeySummary = { id: string; protocol: ProtocolId; created_unix: number; auth?: string; address?: string };
export type User = {
  id: string;
  name: string;
  created_unix: number;
  enabled: boolean;
  data_limit_bytes: number;
  usage_bytes: number;
  over_limit: boolean;
  exempt_from_global_rules: boolean;
  rules: Rules;
  keys: KeySummary[];
};
export type Key = {
  id: string;
  protocol: ProtocolId;
  created_unix: number;
  auth?: string;
  identity?: string;
  server_address?: string;
  remote_identifier?: string;
  warning?: string;
  certificate_password?: string;
  access_key: string;
  config?: string;
};
export type AddressPool = { protocol: ProtocolId; cidr: string; used: number; capacity: number; next?: string };
export type Server = {
  name: string;
  hostname: string;
  version: string;
  created_unix: number;
  api_port: number;
  protocols: Record<ProtocolId, { enabled: boolean; port: number }>;
  vless_handshake: string;
  shadowsocks_method: string;
  users: number;
  site_stats: boolean;
  history_days: number;
  site_days: number;
  history_max_mb: number;
  dashboard_port: number;
  dashboard_public: boolean;
  ipsec_component: { running: boolean; error?: string; connections: number; ports: string };
  address_pools?: AddressPool[];
};
export type Rate = { t: number; up: number; down: number };
export type LiveUser = { id: string; name: string; up_bps: number; down_bps: number; active: number; online: boolean; last_active_unix: number };
export type Health = {
  cpu_percent?: number;
  load_1m?: number;
  memory_used_bytes?: number;
  memory_total_bytes?: number;
  disk_free_bytes?: number;
  disk_total_bytes?: number;
  network_rx_bps?: number;
  network_tx_bps?: number;
  uptime_seconds: number;
  engine_reloads: number;
  detail_paused: boolean;
  history_bytes: number;
};
export type Live = { time_unix: number; up_bps: number; down_bps: number; active: number; online_users: number; series: Rate[]; minutes?: Rate[]; users: LiveUser[]; health: Health };
export type LabelBytes = { label: string; bytes: number };
export type Stats = {
  range: string;
  unit: 'hour' | 'day';
  series: Rate[];
  types: LabelBytes[];
  protocols: LabelBytes[];
  sites: LabelBytes[];
  site_stats: boolean;
  users?: { id: string; name: string; up: number; down: number }[];
};
export type Client = { user: string; name: string; ip: string; protocol: string; first_unix: number; last_unix: number };
export type Invite = { id: string; created_unix: number; expires_unix: number; uses_left: number; tags: string[]; relay: boolean; approval: boolean; note?: string };
export type MeshInfo = { enabled: boolean; id: string; name: string; cidr: string; port: number; ping: boolean; url: string; nodes: number; pending: number; rules: number; invites: Invite[] };
export type MeshRule = { from: string; to: string; protocol: 'tcp' | 'udp' | 'icmp' | 'any'; ports: string[] };
export type { Topology };

export class SignedOut extends Error {}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: { 'X-Ghostlink-Dashboard': '1', 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) throw new SignedOut('Your session ended. Open the login link from the server again.');
  if (!response.ok) {
    let message = 'The server refused the request';
    try {
      message = (await response.json()).error || message;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }
  return response.status === 204 ? (null as T) : ((await response.json()) as T);
}

export async function apiBlob(path: string): Promise<Blob> {
  const response = await fetch('/api' + path, { credentials: 'same-origin', headers: { 'X-Ghostlink-Dashboard': '1' } });
  if (response.status === 401) throw new SignedOut('Your session ended.');
  if (!response.ok) throw new Error('The server refused the request');
  return response.blob();
}

// Sign in with the token after # in the login link (it never reaches a request line).
export async function signIn(): Promise<{ server: Server | null; error: string }> {
  const token = new URLSearchParams(location.hash.slice(1)).get('t');
  if (token) {
    history.replaceState(null, '', location.pathname);
    const response = await fetch('/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    if (!response.ok) {
      let message = 'This login link is not valid.';
      try {
        message = (await response.json()).error || message;
      } catch {
        /* not JSON */
      }
      return { server: null, error: message };
    }
  }
  try {
    return { server: await api<Server>('GET', '/server'), error: '' };
  } catch {
    return { server: null, error: token ? 'Could not sign in.' : '' };
  }
}

export async function signOut(): Promise<void> {
  await fetch('/logout', { method: 'POST', credentials: 'same-origin' });
}
