// Full-screen mode for the desktop window: F11 or the navigation bar's button toggles it, and
// Escape leaves it when no sheet is open. (Tauri windows have no built-in full-screen key.)
import { useCallback, useEffect, useState } from 'react';

type TauriWindow = { isFullscreen(): Promise<boolean>; setFullscreen(on: boolean): Promise<void> };
const current = (): TauriWindow | undefined =>
  (window as unknown as { __TAURI__?: { window?: { getCurrentWindow?: () => TauriWindow } } }).__TAURI__?.window?.getCurrentWindow?.();

export function useFullscreen() {
  const [full, setFull] = useState(false);
  const set = useCallback(async (on: boolean) => {
    const w = current();
    if (!w) return;
    try {
      await w.setFullscreen(on);
      setFull(await w.isFullscreen());
    } catch {
      /* not allowed in this build */
    }
  }, []);
  const toggle = useCallback(async () => {
    const w = current();
    if (w) await set(!(await w.isFullscreen()));
  }, [set]);
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.key === 'F11') {
        event.preventDefault();
        toggle();
      } else if (event.key === 'Escape' && full && !document.querySelector('dialog[open]')) {
        set(false);
      }
    };
    // The window can also leave full screen without us (the system, another shortcut).
    const sync = () => current()?.isFullscreen().then(setFull).catch(() => {});
    window.addEventListener('keydown', key);
    window.addEventListener('resize', sync);
    return () => {
      window.removeEventListener('keydown', key);
      window.removeEventListener('resize', sync);
    };
  }, [toggle, set, full]);
  return { full, toggle, available: !!current() };
}
