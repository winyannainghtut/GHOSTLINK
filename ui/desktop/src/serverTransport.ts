// A managed server for the admin views: their requests become typed operations (routes.ts) that
// the local service sends over its pinned connection with the sealed management key.
import type { Key, Transport, User } from '@admin/api';
import { request, saveDownload, slug } from './ipc';
import { toOp, type Op } from './routes';

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
