// The desktop app talks only to the local Ghostlink service, through the Tauri shell's
// vpn_request command (private IPC). Keys pass through once and are never kept here.
type Invoke = (command: string, args: Record<string, unknown>) => Promise<unknown>;
const invoke = (window as unknown as { __TAURI__?: { core?: { invoke?: Invoke } } }).__TAURI__?.core?.invoke;

export class ServiceUnavailable extends Error {}

type Response<T> = { success: boolean; data: T; error?: { code: string; message: string } };

export async function request<T>(action: Record<string, unknown>): Promise<T> {
  if (!invoke) throw new ServiceUnavailable('Open the installed Ghostlink desktop app to use the local VPN service.');
  let response: Response<T>;
  try {
    response = (await invoke('vpn_request', { action })) as Response<T>;
  } catch {
    throw new ServiceUnavailable('The desktop app could not reach the local VPN service.');
  }
  if (!response.success) throw new Error(response.error?.message || 'The VPN service could not complete this request.');
  return response.data;
}

// Saves a file in Downloads (WebView2 cannot download blob: links from the app's scheme).
export async function saveDownload(name: string, content: string, extension: 'html' | 'mobileconfig' | 'conf'): Promise<string> {
  if (!invoke) throw new Error('Saving files needs the desktop app.');
  return (await invoke('save_download', { name, content, extension })) as string;
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'disconnecting' | 'failed';
export type Connection = {
  status: ConnectionState;
  profile: string | null;
  server: string | null;
  vpn_ip: string | null;
  protocol: string | null;
  connected_duration_seconds: number;
  bytes_received: number;
  bytes_sent: number;
  receive_bytes_per_second: number;
  send_bytes_per_second: number;
  last_error: string | null;
};
export type Info = { connection: Connection; autoconnect: boolean; default_profile: string | null; version: string };
export type Profile = {
  name: string;
  kind: 'outline' | 'wireguard' | 'amneziawg' | 'vless' | 'openvpn' | string;
  display_name: string;
  remotes: { host: string; port: number }[];
  tunnel_mode: string;
  certificate_expires_unix?: number | null;
  is_default: boolean;
};
export type SplitMode = 'full' | 'bypass' | 'only';
export type RoutingPolicy = { mode: SplitMode; domains: string[]; ip_ranges: string[]; apps: string[]; lan_direct: boolean };
export type ManagedServer = { name: string; endpoint: string; server_name: string; version: string; added_unix: number };

export const KINDS: Record<string, string> = { outline: 'Shadowsocks', wireguard: 'WireGuard', amneziawg: 'AmneziaWG', vless: 'VLESS', openvpn: 'OpenVPN' };
export const KIND_DETAIL: Record<string, string> = {
  outline: 'Outline-compatible Shadowsocks',
  wireguard: 'WireGuard',
  amneziawg: 'AmneziaWG (obfuscated WireGuard)',
  vless: 'VLESS with REALITY or TLS',
  openvpn: 'OpenVPN',
};
export const KEY_PREFIXES = ['ss://', 'ssconf://', 'vless://', 'vpn://'];
export const stateLabel: Record<ConnectionState, string> = {
  connected: 'Connected',
  connecting: 'Connecting…',
  reconnecting: 'Reconnecting…',
  disconnecting: 'Disconnecting…',
  failed: 'Connection failed',
  disconnected: 'Disconnected',
};
export const isActive = (s?: ConnectionState) => s === 'connected' || s === 'connecting' || s === 'reconnecting';

export function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 45) || 'server';
}
export function uniqueName(base: string, taken: string[]): string {
  return taken.includes(base) ? `${base}-${Date.now().toString(36)}` : base;
}
