import { useCallback, useEffect, useRef, useState } from 'react';

// A preference kept in localStorage (finish, motion, view mode). Unknown stored values fall back.
export function useStoredState<T extends string>(key: string, fallback: T, allowed: readonly T[]): [T, (value: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key) as T | null;
      return stored && allowed.includes(stored) ? stored : fallback;
    } catch {
      return fallback;
    }
  });
  const set = useCallback(
    (next: T) => {
      setValue(next);
      try {
        localStorage.setItem(key, next);
      } catch {
        /* storage off */
      }
    },
    [key],
  );
  return [value, set];
}

// Runs fn every `ms` milliseconds while mounted (and once at once). A slow call never overlaps
// the next: the timer waits for it. While the page is hidden (a background tab, or a window the
// system reports as hidden) nothing is fetched, and the next call comes as soon as it is shown.
export function usePoll(fn: () => Promise<unknown> | void, ms: number, deps: unknown[] = []): void {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    let stopped = false;
    let running = false;
    let timer: number | undefined;
    const tick = async () => {
      window.clearTimeout(timer);
      if (running) return;
      running = true;
      if (!document.hidden) {
        try {
          await saved.current();
        } catch {
          /* the caller reports errors */
        }
      }
      running = false;
      if (!stopped) timer = window.setTimeout(tick, ms);
    };
    const shown = () => {
      if (!document.hidden && !stopped) tick();
    };
    tick();
    document.addEventListener('visibilitychange', shown);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', shown);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, ...deps]);
}

// The current time in seconds, refreshed every `ms` (for "12 s ago" labels).
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now() / 1000), ms);
    return () => window.clearInterval(id);
  }, [ms]);
  return now;
}

export function prefersReducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}
