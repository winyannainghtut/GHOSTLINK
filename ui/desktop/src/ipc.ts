// The desktop app talks only to the local Ghostlink service, through the Tauri shell's
// vpn_request command (private IPC). Keys pass through once and are never kept here.
// (globalThis is the window in the app; tests import this file in Node, where there is none.)
type Invoke = (command: string, args: Record<string, unknown>) => Promise<unknown>;
const invoke = (globalThis as unknown as { __TAURI__?: { core?: { invoke?: Invoke } } }).__TAURI__?.core?.invoke;

export class ServiceUnavailable extends Error {}

type Response<T> = { success: boolean; data: T; error?: { code: string; message: string } };

// vpn_request answers every service error itself, so a rejected call means the shell refused the
// request before sending it: usually a value the request's fields cannot hold, such as 1.5 where
// a whole number belongs or a negative size (Tauri reports "invalid args …").
export function rejectionError(reason: unknown): Error {
  if (typeof reason === 'string' && reason.startsWith('invalid args')) return new Error('One of the values is not accepted here: use whole numbers, and none below zero.');
  return new ServiceUnavailable('The desktop app could not reach the local VPN service.');
}

export async function request<T>(action: Record<string, unknown>): Promise<T> {
  if (!invoke) throw new ServiceUnavailable('Open the installed Ghostlink desktop app to use the local VPN service.');
  let response: Response<T>;
  try {
    response = (await invoke('vpn_request', { action })) as Response<T>;
  } catch (reason) {
    throw rejectionError(reason);
  }
  if (!response.success) throw new Error(response.error?.message || 'The VPN service could not complete this request.');
  return response.data;
}

// Saves a file in Downloads (WebView2 cannot download blob: links from the app's scheme).
export async function saveDownload(name: string, content: string, extension: 'html' | 'mobileconfig' | 'conf'): Promise<string> {
  if (!invoke) throw new Error('Saving files needs the desktop app.');
  try {
    return (await invoke('save_download', { name, content, extension })) as string;
  } catch (reason) {
    // The shell's errors arrive as plain text, not Error objects.
    throw new Error(typeof reason === 'string' && reason ? reason : 'The file could not be saved in Downloads.');
  }
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
// label: the name its owner gave it on this device (empty for a server added before 0.8.7 or by
// the CLI without one: the ID is shown then). server_name is the name the server itself reports.
export type ManagedServer = { name: string; label?: string; endpoint: string; server_name: string; version: string; added_unix: number };

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

// The local ID for a key from a managed server ("Use on this device"). The client's name is
// shortened first, so a long one cannot cut off the protocol and key ID, and an ID already on
// this device (the same key, or the same user, protocol and key ID on another server) gets a
// suffix: the service refuses to reuse one.
export function localKeyId(user: string, protocol: string, id: string, taken: string[]): string {
  return uniqueName(slug(`${slug(slug(user).slice(0, 24))}-${protocol}-${id}`), taken);
}
