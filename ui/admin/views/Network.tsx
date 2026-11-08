// Network: the protocols this server offers (on/off and ports), its address pools, the rules for
// everyone and the mesh of Linux servers.
import { Pencil } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Button, Card, CardTitle, Meter, Note, Switch, useUI } from '@shared/glass';
import { APPLE, PROTOCOLS, PROTOCOL_HINTS, api, protocolName, type ProtocolId, type Rules, type Server } from '../api';
import { turnedOn } from '../protocols';
import { RulesEditor } from '../RulesEditor';
import { useStore } from '../store';
import { MeshCard } from './Mesh';

const ORDER: ProtocolId[] = ['amneziawg', 'wireguard', 'vless', 'shadowsocks', 'ikev2', 'ipsec'];
const TRANSPORT: Record<ProtocolId, string> = { amneziawg: 'UDP', wireguard: 'UDP', vless: 'TCP', shadowsocks: 'TCP + UDP', ikev2: 'UDP', ipsec: 'UDP' };

export function Network() {
  const { server, setServer } = useStore();
  const { toast, confirm } = useUI();
  const [rules, setRules] = useState<Rules | null>(null);
  useEffect(() => {
    api<Rules>('GET', '/rules').then(setRules).catch(() => {});
  }, []);

  // The message can depend on the server after the change (the port of a protocol turned on).
  const patch = async (body: Record<string, unknown>, message: string | ((next: Server) => string)) => {
    try {
      await api('PATCH', '/server', body);
      const next = await api<Server>('GET', '/server');
      setServer(next);
      toast(typeof message === 'string' ? message : message(next));
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };
  const toggle = async (p: ProtocolId, on: boolean) => {
    if (!on && !(await confirm({ title: `Pause ${PROTOCOLS[p]}?`, text: `Everyone connected with ${PROTOCOLS[p]} is disconnected until you turn it on again.`, action: 'Pause', danger: true }))) return;
    await patch({ protocols: { [p]: { enabled: on } } }, next => (on ? turnedOn(PROTOCOLS[p], p, next.protocols[p]?.port ?? 0) : `${PROTOCOLS[p]} paused.`));
  };
  // The tunnel address pools of WireGuard and AmneziaWG, only while they are on: a protocol that
  // is off gets no keys (a new server has neither on).
  const pools = (server.address_pools ?? []).filter(pool => server.protocols[pool.protocol]?.enabled);
  const poolsOff = !server.protocols.amneziawg?.enabled && !server.protocols.wireguard?.enabled;

  return (
    <div className="grid grid-cols-1 gap-4">
      <Card>
        <CardTitle title="Protocols" detail="A new server runs only Shadowsocks; turn on the others you need. Allow the port of each protocol that is on in this server's firewall and your cloud security group. Clients reconnect automatically after a change." />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3 min-[112.5rem]:grid-cols-6">
          {ORDER.map(p => (
            <ProtocolTile key={p} protocol={p} server={server} onToggle={on => toggle(p, on)} onPort={port => patch({ protocols: { [p]: { port } } }, `${PROTOCOLS[p]} now uses port ${port}. Keys already shared keep the old port.`)} />
          ))}
        </div>
        {!server.ipsec_component?.running && <div className="mt-4"><Note>IKEv2 and IPsec (the built-in VPN of iPhone, iPad and Mac) need the IPsec component: run sudo ghostlink-server ipsec enable on the server.</Note></div>}
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardTitle title="Address pool" detail="Tunnel addresses for WireGuard and AmneziaWG keys" />
          {poolsOff ? (
            <Note>WireGuard and AmneziaWG are off. Their pools show here when one is on.</Note>
          ) : (
            <ul className="grid grid-cols-1 gap-4">
              {pools.map(pool => (
                <li key={pool.protocol} className="grid grid-cols-1 gap-2">
                  <div className="flex items-baseline justify-between gap-3 text-[13px]">
                    <span>{protocolName(pool.protocol)}</span>
                    <span className="mono text-fg-2">{pool.cidr}</span>
                  </div>
                  <Meter fraction={pool.capacity ? pool.used / pool.capacity : 0} tone="ok" />
                  <div className="flex justify-between text-[12px] text-fg-3">
                    <span className="num">
                      {pool.used} of {pool.capacity.toLocaleString()} in use
                    </span>
                    <span>
                      Next <span className="mono text-fg-2">{pool.next ?? 'none free'}</span>
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="lg:col-span-2">
          <CardTitle title="Rules for everyone" detail="Blocked traffic is refused on the server. Changes apply at once." />
          {rules ? (
            <RulesEditor
              rules={rules}
              onSave={async next => {
                await api('PUT', '/rules', next);
                setRules(next);
                toast('Rules for everyone saved.');
              }}
            />
          ) : (
            <Note>Loading…</Note>
          )}
        </Card>
      </div>

      <MeshCard />
    </div>
  );
}

function ProtocolTile({ protocol, server, onToggle, onPort }: { protocol: ProtocolId; server: Server; onToggle: (on: boolean) => void; onPort: (port: number) => void }) {
  const info = server.protocols[protocol] ?? { enabled: false, port: 0 };
  const apple = APPLE.includes(protocol);
  const [editing, setEditing] = useState(false);
  const [port, setPort] = useState(String(info.port));
  useEffect(() => setPort(String(info.port)), [info.port]);
  const ipsec = server.ipsec_component;
  const unavailable = apple && !ipsec?.running && !info.enabled;
  // Keys imported from Outline that kept their own port have their own Shadowsocks listeners.
  const extraPorts = protocol === 'shadowsocks' ? (server.shadowsocks_extra_ports ?? []) : [];
  return (
    <div className="inset-glass grid grid-cols-1 gap-3 rounded-[24px] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-[15px]">{PROTOCOLS[protocol]}</h3>
          <p className="text-[12px] text-fg-3">{PROTOCOL_HINTS[protocol]}</p>
        </div>
        <Switch checked={info.enabled} disabled={unavailable} onChange={onToggle} label={`${PROTOCOLS[protocol]} on or off`} />
      </div>
      <div className="flex items-center justify-between gap-2 text-[12.5px]">
        <span className="text-fg-3">{TRANSPORT[protocol]}</span>
        {apple ? (
          <span className="mono text-fg-2">500, 4500</span>
        ) : editing ? (
          <form
            className="flex items-center gap-1.5"
            onSubmit={event => {
              event.preventDefault();
              const n = Number(port);
              if (n >= 1024 && n <= 65535 && n !== info.port) onPort(n);
              setEditing(false);
            }}
          >
            <input className="field mono h-8 w-24 px-3 py-0 text-[12.5px]" type="number" min={1024} max={65535} value={port} onChange={e => setPort(e.target.value)} autoFocus aria-label={`${PROTOCOLS[protocol]} port`} />
            <Button size="sm" type="submit" variant="cta">
              Save
            </Button>
          </form>
        ) : (
          <button type="button" className="mono inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-fg-2 hover:bg-glass-strong hover:text-fg" onClick={() => setEditing(true)} title="Change port">
            {info.port} <Pencil size={12} />
          </button>
        )}
      </div>
      {extraPorts.length > 0 && (
        <p className="text-[12px] text-fg-3">
          Also <span className="mono text-fg-2">{extraPorts.join(', ')}</span> for keys imported from Outline
        </p>
      )}
      {apple && ipsec?.running && (
        <p className="text-[12px] text-fg-3">
          IPsec component running · <span className="num">{ipsec.connections} connected</span>
          {ipsec.error ? ` · ${ipsec.error}` : ''}
        </p>
      )}
    </div>
  );
}
