// Shared dashboard data: the server, users (clients), live telemetry and where each client last
// connected from. Live data is polled every second; the rest on change and every 15 s.
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { usePoll } from '@shared/hooks';
import type { Status } from '@shared/glass';
import { bindApi, SignedOut, type Client, type Live, type LiveUser, type Server, type ServerApi, type Transport, type User } from './api';

// How long live readings may fail before the views stop showing the last one as current.
const STALE_MS = 5000;

type Store = {
  server: Server;
  users: User[];
  // null until the first reading, and while the server is not answering (stale).
  live: Live | null;
  // The server has not answered the live poll for a while: the live readouts say so instead.
  stale: boolean;
  // While stale, clients keep their last-seen time but are no longer shown as online or moving data.
  liveById: Record<string, LiveUser>;
  lastClient: Record<string, Client>;
  reloadUsers: () => Promise<void>;
  reloadServer: () => Promise<Server>;
  setServer: (server: Server) => void;
  loaded: boolean;
};

const StoreContext = createContext<Store | null>(null);
const ApiContext = createContext<ServerApi | null>(null);

export function useStore(): Store {
  const store = useContext(StoreContext);
  if (!store) throw new Error('useStore outside StoreProvider');
  return store;
}

// The API of the server this view shows (see bindApi). A function that keeps it, as an action
// with several requests does, keeps talking to that server.
export function useApi(): ServerApi {
  const api = useContext(ApiContext);
  if (!api) throw new Error('useApi outside StoreProvider');
  return api;
}

export function clientStatus(user: User, live?: LiveUser): Status {
  if (!user.enabled) return 'paused';
  if (user.over_limit) return 'limit';
  return live?.online ? 'online' : 'idle';
}

export const statusLabel: Record<Status, string> = { online: 'Online', idle: 'Idle', paused: 'Paused', limit: 'Limit reached', pending: 'Waiting', offline: 'Offline' };

export function StoreProvider({ transport, initial, onSignedOut, children }: { transport: Transport; initial: Server; onSignedOut: (message: string) => void; children: ReactNode }) {
  const bound = useMemo(() => bindApi(transport), [transport]);
  const { api } = bound;
  const [server, setServer] = useState(initial);
  const [users, setUsers] = useState<User[]>([]);
  const [live, setLive] = useState<Live | null>(null);
  const [stale, setStale] = useState(false);
  const [clients, setClients] = useState<Client[]>([]);
  const [loaded, setLoaded] = useState(false);
  const signedOut = useRef(onSignedOut);
  signedOut.current = onSignedOut;
  // When the live poll last worked (0: never, as on servers before 0.4.0, which have no /live).
  const answered = useRef(0);

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
  }, [guard, api]);
  const reloadServer = useCallback(async () => {
    const next = (await guard(() => api<Server>('GET', '/server')))!;
    setServer(next);
    return next;
  }, [guard, api]);

  usePoll(async () => {
    try {
      const next = await guard(() => api<Live>('GET', '/live'));
      if (next) setLive(next);
      answered.current = Date.now();
      setStale(false);
    } catch (error) {
      // A failed poll would otherwise leave the last reading on screen, looking live.
      if (answered.current && Date.now() - answered.current > STALE_MS) setStale(true);
      throw error;
    }
  }, 1000);
  usePoll(reloadUsers, 15000);
  usePoll(async () => {
    const result = await guard(() => api<{ clients: Client[] }>('GET', '/clients'));
    if (result) setClients(result.clients);
  }, 20000);
  usePoll(reloadServer, 30000);

  const liveById = useMemo(
    () => Object.fromEntries((live?.users ?? []).map(u => [u.id, stale ? { ...u, online: false, up_bps: 0, down_bps: 0, active: 0 } : u])),
    [live, stale],
  );
  const lastClient = useMemo(() => {
    const out: Record<string, Client> = {};
    for (const c of clients) if (!out[c.user] || c.last_unix > out[c.user].last_unix) out[c.user] = c;
    return out;
  }, [clients]);

  const value = useMemo(
    () => ({ server, users, live: stale ? null : live, stale, liveById, lastClient, reloadUsers, reloadServer, setServer, loaded }),
    [server, users, live, stale, liveById, lastClient, reloadUsers, reloadServer, loaded],
  );
  return (
    <ApiContext.Provider value={bound}>
      <StoreContext.Provider value={value}>{children}</StoreContext.Provider>
    </ApiContext.Provider>
  );
}
