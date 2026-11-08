// A Dynamic Island-style capsule: the server's live state at a glance. Opening it shows each
// protocol with its own switch: the server's equivalent of pausing or resuming the tunnel.
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { LiveRates, Switch, cx, useUI } from '@shared/glass';
import { APPLE, PROTOCOLS, PROTOCOL_HINTS, api, type ProtocolId, type Server } from './api';
import { turnedOn } from './protocols';
import { useStore } from './store';

const ORDER: ProtocolId[] = ['amneziawg', 'wireguard', 'vless', 'shadowsocks', 'ikev2', 'ipsec'];

export function Island() {
  const { server, live, stale, setServer } = useStore();
  const { toast, confirm } = useUI();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  // The panel is rendered at the page level (a frosted element can't blur through its frosted
  // parent, the nav), positioned under the capsule.
  const [anchor, setAnchor] = useState<{ top: number; left: number } | null>(null);
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = box.current?.getBoundingClientRect();
      if (rect) setAnchor({ top: rect.bottom + 10, left: Math.min(window.innerWidth - 182, Math.max(182, rect.left + rect.width / 2)) });
    };
    place();
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [open]);
  const enabled = ORDER.filter(p => server.protocols[p]?.enabled);
  const active = enabled.length > 0;

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!box.current?.contains(event.target as Node) && !panel.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => event.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);

  const toggle = async (protocol: ProtocolId, on: boolean) => {
    if (!on) {
      const ok = await confirm({
        title: `Pause ${PROTOCOLS[protocol]}?`,
        text: `Everyone connected with ${PROTOCOLS[protocol]} is disconnected until you turn it on again. Keys stay as they are.`,
        action: 'Pause',
        danger: true,
      });
      if (!ok) return;
    }
    try {
      await api('PATCH', '/server', { protocols: { [protocol]: { enabled: on } } });
      const next = await api<Server>('GET', '/server');
      setServer(next);
      toast(on ? turnedOn(PROTOCOLS[protocol], protocol, next.protocols[protocol]?.port ?? 0) : `${PROTOCOLS[protocol]} paused.`);
    } catch (error) {
      toast((error as Error).message, 'bad');
    }
  };

  return (
    <div ref={box} className="relative">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className="flex h-10 items-center gap-2.5 rounded-full bg-black px-4 text-[12.5px] text-white shadow-[0_10px_30px_-12px_rgb(0_0_0/0.8),inset_0_1px_0_rgb(255_255_255/0.12)] transition-all duration-500 hover:px-5"
      >
        <span className={cx('relative inline-flex size-2', stale ? 'text-[#ff6961]' : active ? 'text-[#30d158]' : 'text-white/40')}>
          {active && !stale && <span className="absolute inset-0 animate-ping rounded-full bg-current opacity-50 motion-reduce:animate-none" />}
          <span className="relative size-2 rounded-full bg-current" />
        </span>
        {stale ? (
          <span className="font-medium">Server not answering</span>
        ) : (
          <>
            <span className="font-medium">{active ? 'Live' : 'Paused'}</span>
            <span className="text-white/45">·</span>
            <span className="num text-white/80">{live ? `${live.online_users} online` : '—'}</span>
            <LiveRates down={live?.down_bps ?? 0} up={live?.up_bps ?? 0} className="hidden text-white/55 sm:inline-flex" />
          </>
        )}
      </button>
      {open && anchor && createPortal(
        <div ref={panel} style={{ top: anchor.top, left: anchor.left }} className="glass-strong fixed z-40 w-[340px] -translate-x-1/2 rounded-[28px] p-3 animate-[sheet-in_0.25s_cubic-bezier(0.2,0.9,0.25,1)]">
          <p className="px-2 pt-1 pb-2 text-[12.5px] text-fg-3">Protocols on this server</p>
          {/* grid-cols-1 (minmax(0, 1fr)) keeps rows to the panel's width, so long hints are cut
              short instead of widening every row and pushing the switches out of the panel. */}
          <ul className="grid grid-cols-1 gap-1">
            {ORDER.map(p => {
              const info = server.protocols[p];
              const apple = APPLE.includes(p);
              const unavailable = apple && !server.ipsec_component?.running && !info?.enabled;
              // Keys imported from Outline can keep their own Shadowsocks ports.
              const ports = [info?.port, ...(p === 'shadowsocks' ? (server.shadowsocks_extra_ports ?? []) : [])].join(', ');
              return (
                <li key={p} className="flex items-center gap-3 rounded-[20px] px-3 py-2 hover:bg-glass">
                  <div className="min-w-0 flex-1">
                    <div className="text-[13.5px] text-fg">{PROTOCOLS[p]}</div>
                    <div className="truncate text-[11.5px] text-fg-3">
                      {apple ? (unavailable ? 'Needs the IPsec component' : 'UDP 500 and 4500') : <span className="mono">{p === 'vless' ? 'TCP' : p === 'shadowsocks' ? 'TCP+UDP' : 'UDP'} {ports}</span>}
                      {!apple && ` · ${PROTOCOL_HINTS[p]}`}
                    </div>
                  </div>
                  <Switch checked={!!info?.enabled} disabled={unavailable} onChange={on => toggle(p, on)} label={`${PROTOCOLS[p]} on or off`} />
                </li>
              );
            })}
          </ul>
        </div>,
        document.body,
      )}
    </div>
  );
}
