// The dashboard shell: glass waves behind a floating navigation bar, three views and the sheets.
import { LogOut, Plus, Settings2, Waves } from 'lucide-react';
import { useEffect, useState } from 'react';
import { WaveBackground } from '@shared/WaveBackground';
import { Button, Card, IconButton, Segmented, UIProvider, cx } from '@shared/glass';
import { prefersReducedMotion, useStoredState } from '@shared/hooks';
import { signIn, signOut, type Server } from './api';
import { Island } from './Island';
import { StoreProvider, useStore } from './store';
import { Clients } from './views/Clients';
import { NewClient } from './views/NewClient';
import { Network } from './views/Network';
import { Overview } from './views/Overview';
import { SettingsSheet } from './views/Settings';

export const FINISHES = ['obsidian', 'titanium', 'daylight'] as const;
export type Finish = (typeof FINISHES)[number];
const MOTIONS = ['subtle', 'calm', 'still'] as const;
type Motion = (typeof MOTIONS)[number];
const VIEWS = ['overview', 'clients', 'network'] as const;
type View = (typeof VIEWS)[number];

export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 40" className={className} aria-hidden="true">
      <rect width="40" height="40" rx="12" className="fill-fg" />
      <path d="M12 29.5V19a8 8 0 0 1 16 0v10.5l-2.67-2-2.66 2-2.67-2-2.67 2-2.66-2z" fill="none" className="stroke-canvas" strokeWidth="2.6" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx="17" cy="19.5" r="1.6" className="fill-canvas" />
      <circle cx="23" cy="19.5" r="1.6" className="fill-canvas" />
    </svg>
  );
}

function useAppearance() {
  const [finish, setFinish] = useStoredState<Finish>('ghostlink-finish', 'obsidian', FINISHES);
  const [motion, setMotion] = useStoredState<Motion>('ghostlink-motion', prefersReducedMotion() ? 'still' : 'subtle', MOTIONS);
  useEffect(() => {
    document.documentElement.dataset.finish = finish;
    document.documentElement.dataset.motion = motion;
  }, [finish, motion]);
  return { finish, setFinish, motion, setMotion };
}

export function App() {
  const appearance = useAppearance();
  const [server, setServer] = useState<Server | null>(null);
  const [phase, setPhase] = useState<'loading' | 'signin' | 'ready'>('loading');
  const [message, setMessage] = useState('');

  useEffect(() => {
    signIn().then(result => {
      if (result.server) {
        setServer(result.server);
        setPhase('ready');
      } else {
        setMessage(result.error);
        setPhase('signin');
      }
    });
  }, []);

  return (
    <UIProvider>
      <WaveBackground />
      <div className="relative z-10 min-h-screen">
        {phase === 'loading' && <div className="grid min-h-screen place-items-center text-[13px] text-fg-3">Connecting to the server…</div>}
        {phase === 'signin' && <SignIn message={message} />}
        {phase === 'ready' && server && (
          <StoreProvider
            initial={server}
            onSignedOut={text => {
              setMessage(text);
              setPhase('signin');
            }}
          >
            <Shell appearance={appearance} onSignOut={() => signOut().then(() => (setMessage('Signed out.'), setPhase('signin')))} />
          </StoreProvider>
        )}
      </div>
    </UIProvider>
  );
}

function SignIn({ message }: { message: string }) {
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <Card className="w-full max-w-md text-center">
        <Mark className="mx-auto mb-5 size-12" />
        <h1 className="text-[24px]">Ghostlink server</h1>
        <p className="mt-2 text-[13.5px] text-fg-2">
          Open the login link printed by <code className="mono rounded-md bg-field px-1.5 py-0.5 text-[12.5px]">sudo ghostlink-server dashboard</code> on the server.
        </p>
        {message && <p className="mt-4 text-[13px] text-bad">{message}</p>}
      </Card>
    </div>
  );
}

function Shell({ appearance, onSignOut }: { appearance: ReturnType<typeof useAppearance>; onSignOut: () => void }) {
  const { server } = useStore();
  const [view, setView] = useStoredState<View>('ghostlink-view', 'overview', VIEWS);
  const [newClient, setNewClient] = useState(false);
  const [settings, setSettings] = useState(false);
  const { finish, setFinish, motion, setMotion } = appearance;
  const nextMotion: Record<Motion, Motion> = { subtle: 'calm', calm: 'still', still: 'subtle' };

  return (
    <>
      <header className="sticky top-0 z-30 px-3 pt-3 sm:px-5 sm:pt-4">
        <nav className="glass mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-4 gap-y-3 rounded-[28px] px-4 py-3 lg:flex-nowrap">
          <div className="flex min-w-0 items-center gap-3 lg:w-[300px]">
            <Mark className="size-9 shrink-0" />
            <div className="min-w-0 leading-tight">
              <div className="text-[15px] font-semibold tracking-[-0.02em]">GHOSTLINK</div>
              <div className="mono truncate text-[11.5px] text-fg-3" title={`${server.name} · version ${server.version}`}>
                {server.hostname} · v{server.version}
              </div>
            </div>
          </div>
          <div className="order-3 flex w-full flex-wrap items-center justify-center gap-3 lg:order-none lg:w-auto lg:flex-1">
            <Segmented
              label="View"
              value={view}
              onChange={setView}
              options={[
                { value: 'overview', label: 'Overview' },
                { value: 'clients', label: 'Clients' },
                { value: 'network', label: 'Network' },
              ]}
            />
            <Island />
          </div>
          <div className="ml-auto flex items-center gap-1.5 lg:w-[300px] lg:justify-end">
            <button
              type="button"
              onClick={() => setMotion(nextMotion[motion])}
              title="Background motion"
              className="inline-flex h-9 items-center gap-1.5 rounded-full px-3 text-[12.5px] text-fg-2 transition hover:bg-glass-strong hover:text-fg"
            >
              <Waves size={16} />
              <span className="w-[42px] text-left capitalize">{motion}</span>
            </button>
            <FinishPicker value={finish} onChange={setFinish} />
            <IconButton label="Server settings" onClick={() => setSettings(true)}>
              <Settings2 size={17} />
            </IconButton>
            <Button variant="cta" icon={<Plus size={16} strokeWidth={2.4} />} onClick={() => setNewClient(true)} className="ml-1">
              New client
            </Button>
          </div>
        </nav>
      </header>
      <main className="mx-auto max-w-[1440px] px-3 pt-5 pb-24 sm:px-5">
        {view === 'overview' && <Overview onNewClient={() => setNewClient(true)} />}
        {view === 'clients' && <Clients onNewClient={() => setNewClient(true)} />}
        {view === 'network' && <Network />}
      </main>
      <NewClient open={newClient} onClose={() => setNewClient(false)} />
      <SettingsSheet open={settings} onClose={() => setSettings(false)} footer={<Button variant="ghost" icon={<LogOut size={15} />} onClick={onSignOut}>Sign out</Button>} />
    </>
  );
}

const swatch: Record<Finish, string> = {
  obsidian: 'bg-[#090a0d]',
  titanium: 'bg-[#2a2e37]',
  daylight: 'bg-[#f2f4f8]',
};

function FinishPicker({ value, onChange }: { value: Finish; onChange: (f: Finish) => void }) {
  return (
    <div role="radiogroup" aria-label="Finish" className="inset-glass flex items-center gap-1 rounded-full p-1">
      {FINISHES.map(f => (
        <button
          key={f}
          type="button"
          role="radio"
          aria-checked={value === f}
          title={f[0].toUpperCase() + f.slice(1)}
          onClick={() => onChange(f)}
          className={cx('size-6 rounded-full border transition', swatch[f], value === f ? 'border-fg ring-2 ring-fg/25' : 'border-line hover:scale-110')}
        />
      ))}
    </div>
  );
}
