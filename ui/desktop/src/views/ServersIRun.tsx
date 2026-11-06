// Servers I run: Ghostlink servers this device manages with their management keys (sealed in
// the local service). Opening one shows the same views as the server's own dashboard.
import { ArrowLeft, BookOpen, Eye, EyeOff, Plus, Server as ServerIcon, Settings2, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { setTransport, type Server } from '@admin/api';
import { Island } from '@admin/Island';
import { StoreProvider, useStore } from '@admin/store';
import { Clients } from '@admin/views/Clients';
import { NewClient } from '@admin/views/NewClient';
import { Network } from '@admin/views/Network';
import { Overview } from '@admin/views/Overview';
import { SettingsSheet } from '@admin/views/Settings';
import { dateTime } from '@shared/format';
import { Button, Card, Empty, Field, IconButton, Note, Segmented, Sheet, useUI } from '@shared/glass';
import { useStoredState } from '@shared/hooks';
import { request, slug, type ManagedServer } from '../ipc';
import { serverTransport } from '../serverTransport';
import { useService } from '../service';

export function ServersIRun({ addServerSignal }: { addServerSignal: number }) {
  const { toast } = useUI();
  const [servers, setServers] = useState<ManagedServer[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [help, setHelp] = useState(false);
  const [open, setOpen] = useState<ManagedServer | null>(null);
  const load = () =>
    request<{ servers: ManagedServer[] }>({ type: 'managed_server_list' })
      .then(r => setServers(r.servers))
      .catch(e => (toast(e.message, 'bad'), setServers([])));
  useEffect(() => void load(), []);
  useEffect(() => {
    if (addServerSignal) {
      setOpen(null);
      setAdding(true);
    }
  }, [addServerSignal]);

  if (open) return <Workspace server={open} onBack={() => (setOpen(null), load())} />;
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3 px-1">
        <div>
          <h1 className="text-[26px] tracking-[-0.03em]">Servers I run</h1>
          <p className="text-[13.5px] text-fg-2">Create clients and keys, set rules and watch usage on your Ghostlink servers.</p>
        </div>
        <Button icon={<BookOpen size={15} />} onClick={() => setHelp(true)}>
          Set up a server
        </Button>
      </div>
      {servers && !servers.length ? (
        <Card>
          <Empty icon={<ServerIcon size={22} />} title="Run your own server">
            <p>Install Ghostlink server on a Linux machine with one command, then paste the management key it prints.</p>
            <div className="mt-4 flex justify-center gap-2">
              <Button onClick={() => setHelp(true)}>Show me how</Button>
              <Button variant="cta" icon={<Plus size={15} />} onClick={() => setAdding(true)}>
                Add server
              </Button>
            </div>
          </Empty>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(servers ?? []).map(s => (
            <Card as="article" key={s.name} className="flex flex-col gap-4 sm:p-5">
              <div className="flex items-start gap-3">
                <div className="grid size-11 shrink-0 place-items-center rounded-[16px] bg-glass-strong text-fg-2">
                  <ServerIcon size={18} />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="truncate text-[16px]">{s.server_name}</h3>
                  <div className="mono truncate text-[12px] text-fg-3">{s.endpoint}</div>
                </div>
              </div>
              <div className="flex items-center justify-between gap-3 border-t border-line pt-3 text-[12.5px] text-fg-3">
                <span>
                  {s.version ? `Ghostlink server ${s.version}` : 'Ghostlink server'} · added {dateTime(s.added_unix)}
                </span>
                <Button size="sm" variant="cta" onClick={() => setOpen(s)}>
                  Manage
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
      <AddServerSheet open={adding} onClose={() => setAdding(false)} onAdded={load} />
      <SetupHelp open={help} onClose={() => setHelp(false)} />
    </div>
  );
}

const VIEWS = ['overview', 'clients', 'network'] as const;
type View = (typeof VIEWS)[number];

function Workspace({ server, onBack }: { server: ManagedServer; onBack: () => void }) {
  const { refresh } = useService();
  const [info, setInfo] = useState<Server | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const transport = serverTransport(server.name, refresh);
    setTransport(transport);
    setInfo(null);
    setError('');
    transport.call<Server>('GET', '/server').then(setInfo).catch(e => setError(e.message));
  }, [server.name, refresh]);
  if (error)
    return (
      <Card>
        <Empty icon={<ServerIcon size={22} />} title={`${server.server_name} did not answer`}>
          <p>{error}</p>
          <Button className="mt-4" icon={<ArrowLeft size={15} />} onClick={onBack}>
            All servers I run
          </Button>
        </Empty>
      </Card>
    );
  if (!info) return <p className="py-16 text-center text-[13px] text-fg-3">Connecting to {server.server_name}…</p>;
  return (
    <StoreProvider initial={info} onSignedOut={() => {}}>
      <WorkspaceBody server={server} onBack={onBack} />
    </StoreProvider>
  );
}

function WorkspaceBody({ server, onBack }: { server: ManagedServer; onBack: () => void }) {
  const { server: info } = useStore();
  const { confirm, toast } = useUI();
  const [view, setView] = useStoredState<View>('ghostlink-desktop-admin-view', 'overview', VIEWS);
  const [newClient, setNewClient] = useState(false);
  const [settings, setSettings] = useState(false);
  const forget = async () => {
    if (!(await confirm({ title: 'Forget this server?', text: 'Ghostlink removes its management key from this device. The server, its clients and their keys keep working. You need the key to add it again.', action: 'Forget server', danger: true }))) return;
    try {
      await request({ type: 'managed_server_remove', name: server.name });
      toast(`${info.name} forgotten on this device.`);
      onBack();
    } catch (e) {
      toast((e as Error).message, 'bad');
    }
  };
  return (
    <div className="grid gap-4">
      <Card className="flex flex-wrap items-center gap-3 py-3 sm:py-3">
        <IconButton label="All servers I run" onClick={onBack}>
          <ArrowLeft size={18} />
        </IconButton>
        <div className="min-w-0">
          <h1 className="truncate text-[17px]">{info.name}</h1>
          <div className="mono truncate text-[11.5px] text-fg-3">
            {info.hostname} · v{info.version}
          </div>
        </div>
        <div className="mx-auto flex flex-wrap items-center justify-center gap-3">
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
        <IconButton label="Server settings" onClick={() => setSettings(true)}>
          <Settings2 size={17} />
        </IconButton>
        <Button variant="cta" icon={<Plus size={15} strokeWidth={2.4} />} onClick={() => setNewClient(true)}>
          New client
        </Button>
      </Card>
      {view === 'overview' && <Overview onNewClient={() => setNewClient(true)} />}
      {view === 'clients' && <Clients onNewClient={() => setNewClient(true)} />}
      {view === 'network' && <Network />}
      <NewClient open={newClient} onClose={() => setNewClient(false)} />
      <SettingsSheet
        open={settings}
        onClose={() => setSettings(false)}
        footer={
          <Button variant="danger" icon={<Trash2 size={14} />} onClick={() => (setSettings(false), forget())}>
            Forget server
          </Button>
        }
      />
    </div>
  );
}

function AddServerSheet({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: () => void }) {
  const { toast } = useUI();
  const [name, setName] = useState('');
  const [key, setKey] = useState('');
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!open) setKey('');
    else {
      setName('');
      setError('');
      setReveal(false);
    }
  }, [open]);
  const add = async () => {
    setBusy(true);
    setError('');
    try {
      await request({ type: 'managed_server_add', name: slug(name.trim()).slice(0, 40), management_key: key.trim() });
      setKey('');
      toast('Server added. Its management key is sealed in the local service.');
      onAdded();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="Add a server"
      subtitle="Paste the management key printed by sudo ghostlink-server show-key."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="cta" disabled={busy || !name.trim() || !key.trim()} onClick={add}>
            {busy ? 'Checking the server…' : 'Add server'}
          </Button>
        </>
      }
    >
      <form
        className="grid gap-4"
        onSubmit={e => {
          e.preventDefault();
          add();
        }}
      >
        <Field label="Name on this device">
          <input className="field" maxLength={40} value={name} onChange={e => setName(e.target.value)} placeholder="For example home" autoComplete="off" autoFocus />
        </Field>
        <Field label="Management key">
          <div className="relative">
            <input className="field mono pr-12" type={reveal ? 'text' : 'password'} value={key} onChange={e => setKey(e.target.value)} placeholder='{"apiUrl":"https://…","certSha256":"…"}' autoComplete="off" spellCheck={false} />
            <IconButton label={reveal ? 'Hide key' : 'Show key'} className="absolute top-0.5 right-1" onClick={() => setReveal(!reveal)}>
              {reveal ? <EyeOff size={16} /> : <Eye size={16} />}
            </IconButton>
          </div>
        </Field>
        <Note>The key gives full control of the server. Ghostlink seals it in the local service and never shows it again.</Note>
        {error && <Note tone="bad">{error}</Note>}
        <button type="submit" hidden />
      </form>
    </Sheet>
  );
}

function SetupHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { toast } = useUI();
  const command = 'curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash';
  return (
    <Sheet open={open} onClose={onClose} size="medium" title="Set up a Ghostlink server" subtitle="A Linux machine (Debian, Ubuntu, Fedora, RHEL and similar) reachable from the internet" footer={<Button variant="cta" onClick={onClose}>Done</Button>}>
      <ol className="grid list-none gap-4 p-0 text-[13.5px] text-fg-2">
        <li>
          <span className="text-fg">1. Install it with one command</span> on the server. It installs Docker if needed, verifies the package and starts the server:
          <button type="button" onClick={() => navigator.clipboard.writeText(command).then(() => toast('Command copied.'))} className="inset-glass mono mt-2 block w-full rounded-[18px] px-4 py-3 text-left text-[12px] break-all text-fg hover:bg-glass-strong" title="Copy">
            {command}
          </button>
          <span className="mt-1.5 block text-[12.5px] text-fg-3">
            Add <span className="mono">-s -- --hostname YOUR_PUBLIC_IP</span>, <span className="mono">--ipsec</span> for iPhone/iPad/Mac, or <span className="mono">--mesh</span> for a mesh of your Linux servers.
          </span>
        </li>
        <li>
          <span className="text-fg">2. Copy the management key</span> it prints. Show it again with <span className="mono">sudo ghostlink-server show-key</span>.
        </li>
        <li>
          <span className="text-fg">3. Add server here</span> and paste the key.
        </li>
        <li>
          <span className="text-fg">4. Open the ports</span> the installer lists in the server's firewall and your cloud security group.
        </li>
      </ol>
    </Sheet>
  );
}
