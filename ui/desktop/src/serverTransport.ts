// The admin views speak the server's REST paths; here they become the typed operations the
// local service accepts (server_call), which it sends over its pinned connection with the
// sealed management key. Anything not listed is refused here.
import type { Key, Transport, User } from '@admin/api';
import { request, saveDownload, slug } from './ipc';

type Op = Record<string, unknown> & { op: string };
type Route = { method: string; pattern: RegExp; op: (m: string[], body: any, query: URLSearchParams) => Op };

const ID = '(\\d+)';
const routes: Route[] = [
  { method: 'GET', pattern: /^\/server$/, op: () => ({ op: 'info' }) },
  { method: 'PATCH', pattern: /^\/server$/, op: (_m, body) => ({ op: 'update', patch: body }) },
  { method: 'GET', pattern: /^\/users$/, op: () => ({ op: 'users_list' }) },
  { method: 'POST', pattern: /^\/users$/, op: (_m, body) => ({ op: 'user_create', change: body }) },
  { method: 'PATCH', pattern: new RegExp(`^/users/${ID}$`), op: (m, body) => ({ op: 'user_update', user: m[1], change: body }) },
  { method: 'DELETE', pattern: new RegExp(`^/users/${ID}$`), op: m => ({ op: 'user_delete', user: m[1] }) },
  { method: 'GET', pattern: new RegExp(`^/users/${ID}/keys$`), op: m => ({ op: 'keys_list', user: m[1] }) },
  { method: 'POST', pattern: new RegExp(`^/users/${ID}/keys$`), op: (m, body) => ({ op: 'key_create', user: m[1], ...body }) },
  { method: 'DELETE', pattern: new RegExp(`^/users/${ID}/keys/${ID}$`), op: m => ({ op: 'key_delete', user: m[1], key: m[2] }) },
  { method: 'GET', pattern: new RegExp(`^/users/${ID}/keys/${ID}/qr$`), op: (m, _b, q) => ({ op: 'key_qr', user: m[1], key: m[2], format: q.get('format') || 'svg', content: q.get('content') || 'auto' }) },
  { method: 'GET', pattern: new RegExp(`^/users/${ID}/keys/${ID}/profile$`), op: (m, _b, q) => ({ op: 'key_profile', user: m[1], key: m[2], prompt_password: q.get('prompt_password') === '1', on_demand: q.get('on_demand') === '1' }) },
  { method: 'GET', pattern: new RegExp(`^/users/${ID}/kit$`), op: m => ({ op: 'kit', user: m[1] }) },
  { method: 'GET', pattern: /^\/rules$/, op: () => ({ op: 'rules_get' }) },
  { method: 'PUT', pattern: /^\/rules$/, op: (_m, body) => ({ op: 'rules_set', rules: body }) },
  { method: 'GET', pattern: /^\/metrics$/, op: () => ({ op: 'metrics' }) },
  { method: 'GET', pattern: /^\/live$/, op: () => ({ op: 'live' }) },
  { method: 'GET', pattern: /^\/stats$/, op: (_m, _b, q) => ({ op: 'stats', range: q.get('range') || '7d', ...(q.get('user') ? { user: q.get('user') } : {}) }) },
  { method: 'GET', pattern: /^\/clients$/, op: (_m, _b, q) => ({ op: 'clients', ...(q.get('user') ? { user: q.get('user') } : {}) }) },
  { method: 'GET', pattern: /^\/mesh$/, op: () => ({ op: 'mesh_info' }) },
  { method: 'PATCH', pattern: /^\/mesh$/, op: (_m, body) => ({ op: 'mesh_update', patch: body }) },
  { method: 'POST', pattern: /^\/mesh\/invites$/, op: (_m, body) => ({ op: 'mesh_invite_create', invite: body }) },
  { method: 'GET', pattern: /^\/mesh\/invites$/, op: () => ({ op: 'mesh_invite_list' }) },
  { method: 'DELETE', pattern: new RegExp(`^/mesh/invites/${ID}$`), op: m => ({ op: 'mesh_invite_delete', invite: m[1] }) },
  { method: 'PATCH', pattern: new RegExp(`^/mesh/nodes/${ID}$`), op: (m, body) => ({ op: 'mesh_node_update', node: m[1], change: body }) },
  { method: 'DELETE', pattern: new RegExp(`^/mesh/nodes/${ID}$`), op: m => ({ op: 'mesh_node_delete', node: m[1] }) },
  { method: 'GET', pattern: /^\/mesh\/rules$/, op: () => ({ op: 'mesh_rules_get' }) },
  { method: 'PUT', pattern: /^\/mesh\/rules$/, op: (_m, body) => ({ op: 'mesh_rules_set', rules: body.rules }) },
  { method: 'GET', pattern: /^\/mesh\/topology$/, op: () => ({ op: 'mesh_topology' }) },
];

export function toOp(method: string, path: string, body?: unknown): Op {
  const url = new URL(path, 'https://server.invalid');
  for (const route of routes) {
    const m = route.method === method ? url.pathname.match(route.pattern) : null;
    if (m) return route.op(m, body ?? {}, url.searchParams);
  }
  throw new Error(`The app cannot do ${method} ${url.pathname} on a managed server`);
}

export function serverTransport(server: string, onImported: () => void): Transport {
  const call = <T,>(op: Op) => request<T>({ type: 'server_call', server, op });
  return {
    call: (method, path, body) => call(toOp(method, path, body)),
    text: async path => {
      const answer = await call<unknown>(toOp('GET', path));
      return typeof answer === 'string' ? answer : JSON.stringify(answer);
    },
    save: async file => saveDownload(file.name, file.content, file.extension),
    // The key becomes a VPN connection on this device (it never leaves the local service).
    useHere: async (user: User, key: Key) => {
      await request({ type: 'access_key_import', name: slug(`${user.name}-${key.protocol}-${key.id}`), access_key: key.access_key });
      onImported();
    },
  };
}
