// The local service's state, polled every second: the connection (with live rates) and the
// servers saved on this device. Changes go through `act`, which refreshes afterwards.
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { useUI } from '@shared/glass';
import { usePoll } from '@shared/hooks';
import { request, type Info, type Profile } from './ipc';

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

  const refresh = useCallback(async () => {
    try {
      const [list, next] = await Promise.all([request<{ profiles: Profile[] }>({ type: 'profile_list' }), request<Info>({ type: 'info' })]);
      setProfiles(list.profiles);
      setInfo(next);
      setAvailable(true);
      setError('');
    } catch (e) {
      setAvailable(false);
      setError((e as Error).message);
    }
  }, []);
  usePoll(refresh, 1000);

  const act = useCallback(
    async (action: Record<string, unknown>, message?: string) => {
      if (busyRef.current) return false;
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
