// The Ghostlink desktop app: My servers (connect), Servers I run (manage your own servers with
// the same views as the server dashboard) and Settings, under the glass navigation bar.
import { KeyRound, Plus, Power } from 'lucide-react';
import { useRef, useState } from 'react';
import { Popover } from '@shared/Popover';
import { WaveBackground } from '@shared/WaveBackground';
import { FinishPicker, Mark, MotionButton, useAppearance } from '@shared/appearance';
import { Button, Segmented, StatusDot, UIProvider, cx } from '@shared/glass';
import { useStoredState } from '@shared/hooks';
import { megabits } from '@shared/format';
import { KINDS, isActive, stateLabel, type Profile } from './ipc';
import { ServiceProvider, useService } from './service';
import { VERSION } from './version';
import { MyServers } from './views/MyServers';
import { ServersIRun } from './views/ServersIRun';
import { Settings } from './views/Settings';

const VIEWS = ['servers', 'manage', 'settings'] as const;
export type View = (typeof VIEWS)[number];

export function App() {
  return (
    <UIProvider>
      <WaveBackground />
      <ServiceProvider>
        <div className="relative z-10 min-h-screen">
          <Shell />
        </div>
      </ServiceProvider>
    </UIProvider>
  );
}

function Shell() {
  const appearance = useAppearance();
  const { available, info } = useService();
  const [view, setView] = useStoredState<View>('ghostlink-desktop-view', 'servers', VIEWS);
  const [addKey, setAddKey] = useState(0);
  const [addServer, setAddServer] = useState(0);
  return (
    <>
      <header className="sticky top-0 z-30 px-3 pt-3 sm:px-5 sm:pt-4">
        <nav className="glass mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-4 gap-y-3 rounded-[28px] px-4 py-3 lg:flex-nowrap">
          <div className="flex min-w-0 items-center gap-3 lg:w-[290px]">
            <Mark className="size-9 shrink-0" />
            <div className="min-w-0 leading-tight">
              <div className="text-[15px] font-semibold tracking-[-0.02em]">GHOSTLINK</div>
              <div className="flex items-center gap-1.5 truncate text-[11.5px] text-fg-3">
                <span className={cx('size-1.5 rounded-full', available ? 'bg-ok' : 'bg-bad')} />
                {available ? `Local service · v${info?.version ?? VERSION}` : 'Service unavailable'}
              </div>
            </div>
          </div>
          <div className="order-3 flex w-full flex-wrap items-center justify-center gap-3 lg:order-none lg:w-auto lg:flex-1">
            <Segmented
              label="Section"
              value={view}
              onChange={setView}
              options={[
                { value: 'servers', label: 'My servers' },
                { value: 'manage', label: 'Servers I run' },
                { value: 'settings', label: 'Settings' },
              ]}
            />
            <ConnectionIsland />
          </div>
          <div className="ml-auto flex items-center gap-1.5 lg:w-[290px] lg:justify-end">
            <MotionButton motion={appearance.motion} onChange={appearance.setMotion} />
            <FinishPicker value={appearance.finish} onChange={appearance.setFinish} />
            {view === 'manage' ? (
              <Button variant="cta" className="ml-1" icon={<Plus size={16} strokeWidth={2.4} />} onClick={() => setAddServer(n => n + 1)}>
                Add server
              </Button>
            ) : (
              <Button variant="cta" className="ml-1" icon={<KeyRound size={15} />} onClick={() => (setView('servers'), setAddKey(n => n + 1))}>
                Add key
              </Button>
            )}
          </div>
        </nav>
      </header>
      <main className="mx-auto max-w-[1440px] px-3 pt-5 pb-24 sm:px-5">
        {view === 'servers' && <MyServers addKeySignal={addKey} />}
        {view === 'manage' && <ServersIRun addServerSignal={addServer} />}
        {view === 'settings' && <Settings appearance={appearance} />}
      </main>
    </>
  );
}

function clock(seconds: number): string {
  return [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60].map(n => String(n).padStart(2, '0')).join(':');
}

// The connection at a glance; opening it switches servers or disconnects.
function ConnectionIsland() {
  const { info, profiles, act, available, busy } = useService();
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLButtonElement>(null);
  const c = info?.connection;
  const current = profiles.find(p => p.name === c?.profile);
  const dot = !available ? 'bg-white/30' : c?.status === 'connected' ? 'bg-[#30d158]' : c?.status === 'failed' ? 'bg-[#ff6961]' : isActive(c?.status) ? 'bg-[#ffd60a]' : 'bg-white/40';
  const connect = (p: Profile) => {
    setOpen(false);
    if (c && isActive(c.status) && c.profile === p.name) return act({ type: 'disconnect' }, 'Disconnected.');
    if (c && c.status !== 'disconnected' && c.status !== 'failed') return act({ type: 'switch', profile: p.name });
    return act({ type: 'connect', profile: p.name });
  };
  return (
    <>
      <button
        ref={anchor}
        type="button"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className="flex h-10 items-center gap-2.5 rounded-full bg-black px-4 text-[12.5px] text-white shadow-[0_10px_30px_-12px_rgb(0_0_0/0.8),inset_0_1px_0_rgb(255_255_255/0.12)] transition-all duration-500 hover:px-5"
      >
        <span className="relative inline-flex size-2">
          {c?.status === 'connected' && <span className="absolute inset-0 animate-ping rounded-full bg-[#30d158] opacity-50 motion-reduce:animate-none" />}
          <span className={cx('relative size-2 rounded-full', dot)} />
        </span>
        <span className="font-medium">{!available ? 'Service off' : c ? stateLabel[c.status] : '…'}</span>
        {c?.status === 'connected' && (
          <>
            <span className="max-w-[140px] truncate text-white/70">{current?.display_name || current?.name}</span>
            <span className="mono text-white/80">{clock(c.connected_duration_seconds)}</span>
            <span className="num hidden text-white/55 sm:inline">
              ↓ {megabits(c.receive_bytes_per_second)} ↑ {megabits(c.send_bytes_per_second)} Mbit/s
            </span>
          </>
        )}
      </button>
      <Popover anchor={anchor} open={open} onClose={() => setOpen(false)} width={320} align="center">
        <p className="px-3 pt-1.5 pb-2 text-[12.5px] text-fg-3">{profiles.length ? 'Connect through' : 'No servers on this device yet'}</p>
        <ul className="grid gap-0.5">
          {profiles.map(p => {
            const here = c?.profile === p.name;
            const status = here ? c!.status : 'disconnected';
            return (
              <li key={p.name}>
                <button type="button" disabled={busy || !available} onClick={() => connect(p)} className="flex w-full items-center gap-3 rounded-[18px] px-3 py-2 text-left transition hover:bg-glass-strong">
                  <StatusDot status={status === 'connected' ? 'online' : isActive(status) ? 'pending' : 'offline'} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13.5px] text-fg">{p.display_name || p.name}</span>
                    <span className="block text-[11.5px] text-fg-3">{KINDS[p.kind] ?? p.kind}</span>
                  </span>
                  <span className={cx('inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[12px]', here && isActive(status) ? 'bg-bad/15 text-bad' : 'bg-glass-strong text-fg-2')}>
                    <Power size={12} /> {here && isActive(status) ? 'Disconnect' : 'Connect'}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </Popover>
    </>
  );
}
