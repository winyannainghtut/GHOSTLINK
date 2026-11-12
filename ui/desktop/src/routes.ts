// The admin views speak the server's REST paths; the local service accepts typed operations
// (server_call). This table is the whole mapping: anything not listed is refused here. It has no
// imports, so tests run it directly (node --experimental-strip-types).
export type Op = Record<string, unknown> & { op: string };
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
  { method: 'POST', pattern: /^\/asn\/update$/, op: () => ({ op: 'asn_update' }) },
];

export function toOp(method: string, path: string, body?: unknown): Op {
  // Only plain paths: no dot segments, empty segments, escapes or backslashes (which URL parsing
  // would quietly normalize into another path).
  const raw = path.split('?')[0];
  if (!raw.startsWith('/') || raw.includes('..') || raw.includes('//') || raw.includes('%') || raw.includes('\\')) {
    throw new Error(`The app cannot do ${method} ${raw} on a managed server`);
  }
  const url = new URL(path, 'https://server.invalid');
  for (const route of routes) {
    const m = route.method === method ? url.pathname.match(route.pattern) : null;
    if (m) return route.op(m, body ?? {}, url.searchParams);
  }
  throw new Error(`The app cannot do ${method} ${url.pathname} on a managed server`);
}

