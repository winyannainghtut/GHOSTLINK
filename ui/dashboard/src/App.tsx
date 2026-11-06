// The dashboard shell: glass waves behind a floating navigation bar, three views and the sheets.
import { LogOut, Plus, Settings2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { Server } from '@admin/api';
import { Island } from '@admin/Island';
import { StoreProvider, useStore } from '@admin/store';
import { Clients } from '@admin/views/Clients';
import { NewClient } from '@admin/views/NewClient';
import { Network } from '@admin/views/Network';
import { Overview } from '@admin/views/Overview';
import { SettingsSheet } from '@admin/views/Settings';
import { WaveBackground } from '@shared/WaveBackground';
import { FinishPicker, Mark, MotionButton, useAppearance, type Appearance } from '@shared/appearance';
import { Button, Card, IconButton, Segmented, UIProvider } from '@shared/glass';
import { useStoredState } from '@shared/hooks';
import { signIn, signOut } from './session';

const VIEWS = ['overview', 'clients', 'network'] as const;
type View = (typeof VIEWS)[number];

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

function Shell({ appearance, onSignOut }: { appearance: Appearance; onSignOut: () => void }) {
  const { server } = useStore();
  const [view, setView] = useStoredState<View>('ghostlink-view', 'overview', VIEWS);
  const [newClient, setNewClient] = useState(false);
  const [settings, setSettings] = useState(false);

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
            <MotionButton motion={appearance.motion} onChange={appearance.setMotion} />
            <FinishPicker value={appearance.finish} onChange={appearance.setFinish} />
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
      <SettingsSheet
        open={settings}
        onClose={() => setSettings(false)}
        footer={
          <Button variant="ghost" icon={<LogOut size={15} />} onClick={onSignOut}>
            Sign out
          </Button>
        }
      />
    </>
  );
}
