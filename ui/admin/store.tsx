// Shared dashboard data: the server, users (clients), live telemetry and where each client last
// connected from. Live data is polled every second; the rest on change and every 15 s.
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { usePoll } from '@shared/hooks';
import type { Status } from '@shared/glass';
import { api, SignedOut, type Client, type Live, type LiveUser, type Server, type User } from './api';

type Store = {
  server: Server;
  users: User[];
  live: Live | null;
  liveById: Record<string, LiveUser>;
  lastClient: Record<string, Client>;
  reloadUsers: () => Promise<void>;
  reloadServer: () => Promise<Server>;
  setServer: (server: Server) => void;
  loaded: boolean;
};

const StoreContext = createContext<Store | null>(null);

export function useStore(): Store {
  const store = useContext(StoreContext);
  if (!store) throw new Error('useStore outside StoreProvider');
  return store;
}

export function clientStatus(user: User, live?: LiveUser): Status {
  if (!user.enabled) return 'paused';
  if (user.over_limit) return 'limit';
  return live?.online ? 'online' : 'idle';
}

export const statusLabel: Record<Status, string> = { online: 'Online', idle: 'Idle', paused: 'Paused', limit: 'Limit reached', pending: 'Waiting', offline: 'Offline' };

export function StoreProvider({ initial, onSignedOut, children }: { initial: Server; onSignedOut: (message: string) => void; children: ReactNode }) {
  const [server, setServer] = useState(initial);
  const [users, setUsers] = useState<User[]>([]);
  const [live, setLive] = useState<Live | null>(null);
  const [clients, setClients] = useState<Client[]>([]);
  const [loaded, setLoaded] = useState(false);
  const signedOut = useRef(onSignedOut);
  signedOut.current = onSignedOut;

  const guard = useCallback(async <T,>(work: () => Promise<T>): Promise<T | undefined> => {
    try {
      return await work();
    } catch (error) {
      if (error instanceof SignedOut) signedOut.current(error.message);
      throw error;
    }
  }, []);

  const reloadUsers = useCallback(async () => {
    const list = await guard(() => api<User[]>('GET', '/users'));
    if (list) setUsers(list);
    setLoaded(true);
  }, [guard]);
  const reloadServer = useCallback(async () => {
    const next = (await guard(() => api<Server>('GET', '/server')))!;
    setServer(next);
    return next;
  }, [guard]);

  usePoll(async () => {
    const next = await guard(() => api<Live>('GET', '/live'));
    if (next) setLive(next);
  }, 1000);
  usePoll(reloadUsers, 15000);
  usePoll(async () => {
    const result = await guard(() => api<{ clients: Client[] }>('GET', '/clients'));
    if (result) setClients(result.clients);
  }, 20000);
  usePoll(reloadServer, 30000);

  const liveById = useMemo(() => Object.fromEntries((live?.users ?? []).map(u => [u.id, u])), [live]);
  const lastClient = useMemo(() => {
    const out: Record<string, Client> = {};
    for (const c of clients) if (!out[c.user] || c.last_unix > out[c.user].last_unix) out[c.user] = c;
    return out;
  }, [clients]);

  const value = useMemo(
    () => ({ server, users, live, liveById, lastClient, reloadUsers, reloadServer, setServer, loaded }),
    [server, users, live, liveById, lastClient, reloadUsers, reloadServer, loaded],
  );
  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}
