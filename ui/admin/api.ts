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
  // Bytes per second, download and upload alike: 0 follows the server's default, -1 is no limit.
  speed_limit_bps: number;
  // The cap in force (the client's own or the server's default), 0 for none.
  effective_speed_limit_bps: number;
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
  // Ports of keys imported from Outline that kept their own port.
  shadowsocks_extra_ports?: number[];
  // Speed limit for clients without one of their own, bytes per second (0: none).
  default_speed_limit_bps: number;
  users: number;
  site_stats: boolean;
  history_days: number;
  site_days: number;
  history_max_mb: number;
  dashboard_port: number;
  dashboard_public: boolean;
  // Missing on servers before 0.5.0, which the desktop app can still manage.
  ipsec_component?: { running: boolean; error?: string; connections: number; ports: string };
  address_pools?: AddressPool[];
  // Missing on servers before 0.9.0.
  asn?: ProviderLookup;
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
  // The size the history file is kept under, the size of the server's whole state directory, and
  // how much room the disk has left: "ok", "low" (a warning) or "full" (recording is paused).
  // Missing on servers before 0.9.0.
  history_max_bytes?: number;
  state_bytes?: number;
  disk_level?: 'ok' | 'low' | 'full';
  // Why the VPN engine is not running (another program holds one of its ports, usually). The
  // management API, the dashboard and the server commands keep working so it can be fixed;
  // the server tries the engine again every 30 s. Missing while the engine runs, and on
  // servers before 0.8.1.
  engine_error?: string;
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
// asn and operator: the autonomous system an address belongs to and who runs it, when the server's
// provider lookup is on (0.9.0) and the address is somebody's (a private address is not).
export type Client = { user: string; name: string; ip: string; protocol: string; first_unix: number; last_unix: number; asn?: number; operator?: string };
// The provider lookup: off until the owner turns it on, because it downloads a public list from
// source (nothing about clients is sent).
export type ProviderLookup = { enabled: boolean; ready: boolean; updating: boolean; ranges: number; updated_unix?: number; error?: string; source: string };
export type Invite = { id: string; created_unix: number; expires_unix: number; uses_left: number; tags: string[]; relay: boolean; approval: boolean; note?: string };
export type MeshInfo = { enabled: boolean; id: string; name: string; cidr: string; port: number; ping: boolean; url: string; nodes: number; pending: number; rules: number; invites: Invite[] };
export type MeshRule = { from: string; to: string; protocol: 'tcp' | 'udp' | 'icmp' | 'any'; ports: string[] };
export type { Topology };

export class SignedOut extends Error {}

// How the admin views reach a server: the dashboard calls this server's /api over HTTP; the
// desktop app sends typed operations through the local service. Paths and bodies follow the
// server's management API (docs/deployment/ghostlink-server.md).
export type SavedFile = { name: string; extension: 'conf' | 'mobileconfig' | 'html'; content: string; mime: string };
export type Transport = {
  call<T>(method: string, path: string, body?: unknown): Promise<T>;
  // Text answers: QR codes (SVG), connection kits (HTML) and Apple profiles (XML).
  text(path: string): Promise<string>;
  // Saves a file the user asked for; returns where it went, when the app knows.
  save(file: SavedFile): Promise<string | null>;
  // The desktop app can also use a key on this device (it becomes a VPN connection there).
  useHere?: (user: User, key: Key) => Promise<void>;
};

// One server's API, bound to its transport. Each view of a server gets its own (useApi in
// store.tsx) and there is no shared current server, so every step of an action goes to the
// server it started on: leaving server A for server B while A's new client is still being created
// cannot send A's next request, its key, to B (code review 2026-11-09, F2).
export type ServerApi = {
  api: <T>(method: string, path: string, body?: unknown) => Promise<T>;
  apiText: (path: string) => Promise<string>;
  saveFile: (file: SavedFile) => Promise<string | null>;
  canUseHere: boolean;
  useHere: (user: User, key: Key) => Promise<void>;
};

export function bindApi(transport: Transport): ServerApi {
  return {
    api: <T,>(method: string, path: string, body?: unknown) => transport.call<T>(method, path, body),
    apiText: path => transport.text(path),
    saveFile: file => transport.save(file),
    canUseHere: !!transport.useHere,
    useHere: (user, key) => (transport.useHere ? transport.useHere(user, key) : Promise.reject(new Error('Only the desktop app can use a key on this device.'))),
  };
}

// QR codes come back as SVG text; a data: URL shows them under both apps' CSPs.
export const svgURL = (svg: string): string => 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
