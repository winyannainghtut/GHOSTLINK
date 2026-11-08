// The local service's state: the connection (with live rates) every second, and the servers saved
// on this device every few seconds. Changes go through `act`, which refreshes both afterwards.
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { useUI } from '@shared/glass';
import { usePoll } from '@shared/hooks';
import { request, type Info, type Profile } from './ipc';

// The saved servers change only when someone changes them, and this app refreshes them after its
// own changes. The service writes every request to its audit log, which keeps about 1 MiB, so the
// list is not asked for every second along with the connection.
const PROFILES_MS = 5000;

type Service = {
  available: boolean;
  error: string;
  info: Info | null;
  profiles: Profile[];
  busy: boolean;
  refresh: () => Promise<void>;
  act: (action: Record<string, unknown>, message?: string) => Promise<boolean>;
};

const ServiceContext = createContext<Service | null>(null);
export const useService = (): Service => {
  const s = useContext(ServiceContext);
  if (!s) throw new Error('useService outside ServiceProvider');
  return s;
};

export function ServiceProvider({ children }: { children: ReactNode }) {
  const { toast } = useUI();
  const [info, setInfo] = useState<Info | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [available, setAvailable] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const listed = useRef(0);

  const load = useCallback(async (withProfiles: boolean) => {
    try {
      const [list, next] = await Promise.all([withProfiles ? request<{ profiles: Profile[] }>({ type: 'profile_list' }) : null, request<Info>({ type: 'info' })]);
      if (list) {
        setProfiles(list.profiles);
        listed.current = Date.now();
      }
      setInfo(next);
      setAvailable(true);
      setError('');
    } catch (e) {
      setAvailable(false);
      setError((e as Error).message);
    }
  }, []);
  const refresh = useCallback(() => load(true), [load]);
  usePoll(() => load(Date.now() - listed.current >= PROFILES_MS), 1000);

  const act = useCallback(
    async (action: Record<string, unknown>, message?: string) => {
      // One change at a time; say so rather than dropping a second one without a word.
      if (busyRef.current) {
        toast('Another change is still in progress. Try again in a moment.', 'info');
        return false;
      }
      busyRef.current = true;
      setBusy(true);
      try {
        await request(action);
        if (message) toast(message);
        await refresh();
        return true;
      } catch (e) {
        toast((e as Error).message, 'bad');
        return false;
      } finally {
        busyRef.current = false;
        setBusy(false);
      }
    },
    [refresh, toast],
  );

  const value = useMemo(() => ({ available, error, info, profiles, busy, refresh, act }), [available, error, info, profiles, busy, refresh, act]);
  return <ServiceContext.Provider value={value}>{children}</ServiceContext.Provider>;
}
