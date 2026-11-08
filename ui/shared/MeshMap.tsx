// The mesh map: nodes on a ring (relays first), every link between them, relayed links bent
// through the relay, shared subnets beside their node. Nodes can be dragged; positions are kept
// per mesh in localStorage. Shared by the dashboard and (next) the desktop app.
import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { cx } from './glass';
import { speed } from './format';

export type MeshNode = {
  id: string;
  name: string;
  address: string;
  tags: string[] | null;
  status: 'active' | 'pending' | 'disabled' | string;
  relay: boolean;
  relay_in_use: boolean;
  online: boolean;
  last_seen_unix: number;
  endpoint: string;
  seen_from: string;
  listen_port: number;
  advertised_routes: string[] | null;
  approved_routes: string[] | null;
  masquerade: boolean;
  version: string;
  os: string;
  error?: string;
  in_sync: boolean;
  rx_bps: number;
  tx_bps: number;
};

export type MeshLink = { a: string; b: string; path: 'direct' | 'relay' | 'down'; via?: string; rtt_ms: number; handshake_age_s: number; rx_bps: number; tx_bps: number };

export type Topology = { id: string; name: string; cidr: string; enabled: boolean; nodes: MeshNode[]; links: MeshLink[]; rule_count: number; updated_unix: number };

const W = 760, H = 480, R = 24;
type Position = { x: number; y: number; pinned: boolean };

function ring(nodes: MeshNode[], saved: Record<string, { x: number; y: number }>): Record<string, Position> {
  const rank = (n: MeshNode) => (n.relay ? 0 : n.status === 'active' ? 1 : 2);
  const ordered = [...nodes].sort((a, b) => rank(a) - rank(b) || Number(a.id) - Number(b.id));
  const out: Record<string, Position> = {};
  const twoRings = ordered.length > 14;
  ordered.forEach((n, i) => {
    if (saved[n.id]) {
      out[n.id] = { ...saved[n.id], pinned: true };
      return;
    }
    if (ordered.length === 1) {
      out[n.id] = { x: W / 2, y: H / 2 - 20, pinned: false };
      return;
    }
    const scale = twoRings && i % 2 ? 0.6 : 1;
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / ordered.length;
    out[n.id] = { x: W / 2 + (W / 2 - 130) * scale * Math.cos(angle), y: H / 2 - 12 + (H / 2 - 85) * scale * Math.sin(angle), pinned: false };
  });
  return out;
}

const storageKey = (id: string) => 'ghostlink-mesh-layout:' + id;

function loadSaved(id: string): Record<string, { x: number; y: number }> {
  try {
    return JSON.parse(localStorage.getItem(storageKey(id)) || '{}');
  } catch {
    return {};
  }
}

export function MeshMap({ topology, selected, onSelect, resetToken = 0, className }: {
  topology: Topology;
  selected: string | null;
  onSelect: (id: string | null) => void;
  resetToken?: number;
  className?: string;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const ids = useMemo(() => topology.nodes.map(n => n.id).sort().join(','), [topology.nodes]);
  const [positions, setPositions] = useState<Record<string, Position>>({});
  const drag = useRef<{ id: string; start: { x: number; y: number }; origin: Position; moved: boolean } | null>(null);
  const latest = useRef(positions);
  latest.current = positions;
  const handledReset = useRef(resetToken);

  // Lay out again only when nodes come or go (or on "Rearrange"); dragged nodes keep their place.
  // Only a new "Rearrange" forgets the saved layout: the token stays set after it, and nodes
  // dragged since then must survive the next node that joins or leaves.
  useEffect(() => {
    const reset = resetToken !== handledReset.current;
    handledReset.current = resetToken;
    if (reset) {
      try {
        localStorage.removeItem(storageKey(topology.id));
      } catch {
        /* storage off */
      }
    }
    setPositions(ring(topology.nodes, reset ? {} : loadSaved(topology.id)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids, topology.id, resetToken]);

  const point = (event: ReactPointerEvent) => {
    const element = svg.current!;
    const matrix = element.getScreenCTM();
    if (!matrix) return { x: 0, y: 0 };
    const p = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
    return { x: p.x, y: p.y };
  };

  const save = (next: Record<string, Position>) => {
    const out: Record<string, { x: number; y: number }> = {};
    for (const [id, p] of Object.entries(next)) if (p.pinned) out[id] = { x: Math.round(p.x), y: Math.round(p.y) };
    try {
      localStorage.setItem(storageKey(topology.id), JSON.stringify(out));
    } catch {
      /* storage off */
    }
  };

  const byId = Object.fromEntries(topology.nodes.map(n => [n.id, n]));
  const labelAll = topology.links.length <= 6;

  if (!topology.nodes.length) {
    return (
      <svg className={cx('mesh-map w-full', className)} viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Mesh map">
        <text className="empty" x={W / 2} y={H / 2} textAnchor="middle">
          No nodes yet. Add one to see the map.
        </text>
      </svg>
    );
  }

  return (
    <svg
      ref={svg}
      className={cx('mesh-map w-full', className)}
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label="Mesh map: nodes and the links between them"
      onPointerDown={event => {
        if (event.target === svg.current) onSelect(null);
      }}
      onPointerMove={event => {
        const d = drag.current;
        if (!d) return;
        const now = point(event);
        const dx = now.x - d.start.x, dy = now.y - d.start.y;
        if (!d.moved && Math.hypot(dx, dy) < 4) return;
        d.moved = true;
        setPositions(current => ({ ...current, [d.id]: { x: Math.min(W - 30, Math.max(30, d.origin.x + dx)), y: Math.min(H - 45, Math.max(30, d.origin.y + dy)), pinned: true } }));
      }}
      onPointerUp={() => {
        const d = drag.current;
        drag.current = null;
        if (!d) return;
        if (d.moved) save(latest.current);
        else onSelect(d.id);
      }}
      onPointerCancel={() => (drag.current = null)}
    >
      <g>
        {topology.links.map(link => {
          const a = positions[link.a], b = positions[link.b];
          if (!a || !b) return null;
          const busy = (link.rx_bps || 0) + (link.tx_bps || 0);
          const width = 1.5 + Math.min(4.5, Math.log10(1 + busy / 1000));
          const isSelected = !!selected && (link.a === selected || link.b === selected);
          const relay = link.path === 'relay' && link.via ? positions[link.via] : undefined;
          const cls = cx('link', link.path, isSelected && 'selected');
          let d: string, mid: { x: number; y: number };
          if (relay) {
            // This control point makes the curve pass through the relay at its middle.
            const cx2 = 2 * relay.x - (a.x + b.x) / 2, cy2 = 2 * relay.y - (a.y + b.y) / 2;
            d = `M${a.x},${a.y} Q${cx2},${cy2} ${b.x},${b.y}`;
            mid = { x: 0.5625 * a.x + 0.375 * cx2 + 0.0625 * b.x, y: 0.5625 * a.y + 0.375 * cy2 + 0.0625 * b.y };
          } else {
            d = `M${a.x},${a.y} L${b.x},${b.y}`;
            mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
          }
          const via = relay && link.via ? ` via ${byId[link.via]?.name}` : '';
          return (
            <g key={link.a + '-' + link.b}>
              <path className={cls} d={d} strokeWidth={width.toFixed(1)}>
                <title>{`${byId[link.a]?.name} ↔ ${byId[link.b]?.name}: ${link.path}${via}, ${link.rtt_ms > 0 ? link.rtt_ms.toFixed(1) + ' ms' : 'no ping yet'}, ${speed(busy)}`}</title>
              </path>
              {link.rtt_ms > 0 && (labelAll || isSelected) && (
                <text className="label" x={mid.x} y={mid.y - 5} textAnchor="middle">
                  {link.rtt_ms < 10 ? link.rtt_ms.toFixed(1) : Math.round(link.rtt_ms)} ms
                </text>
              )}
            </g>
          );
        })}
      </g>
      <g>
        {topology.nodes.map(node => {
          const p = positions[node.id];
          if (!p) return null;
          const routes = node.approved_routes || [];
          const right = p.x >= W / 2;
          const state = node.status !== 'active' ? node.status : node.online ? 'online' : 'offline';
          const tip = [`${node.name} (${node.address}) · ${state}`];
          if (node.relay_in_use) tip.push('Relay for nodes that cannot connect directly');
          if (node.tags?.length) tip.push('Tags: ' + node.tags.join(', '));
          if (node.error) tip.push('Problem: ' + node.error);
          return (
            <g key={node.id}>
              {routes.map((route, i) => {
                const w = route.length * 6.4 + 14;
                const ry = Math.min(H - 22, Math.max(4, p.y - 9 + (i - (routes.length - 1) / 2) * 22));
                const rx = right ? Math.min(W - w - 4, p.x + R + 22) : Math.max(4, p.x - R - 22 - w);
                return (
                  <g key={route}>
                    <line className="subnet-link" x1={p.x + (right ? R : -R)} y1={p.y} x2={right ? rx : rx + w} y2={ry + 9} />
                    <g className="subnet">
                      <rect x={rx} y={ry} width={w} height={18} rx={9} />
                      <text x={rx + 7} y={ry + 13}>
                        {route}
                      </text>
                    </g>
                  </g>
                );
              })}
              <g
                className={cx('node', state, node.id === selected && 'selected')}
                transform={`translate(${p.x} ${p.y})`}
                tabIndex={0}
                role="button"
                aria-label={`${node.name}, ${state}`}
                onPointerDown={event => {
                  event.preventDefault();
                  event.stopPropagation();
                  drag.current = { id: node.id, start: point(event), origin: { ...p }, moved: false };
                  try {
                    svg.current?.setPointerCapture(event.pointerId);
                  } catch {
                    /* synthetic pointer */
                  }
                }}
                onKeyDown={event => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    onSelect(node.id);
                  }
                }}
              >
                <title>{tip.join('\n')}</title>
                {node.relay_in_use && <circle className="relay-ring" r={R + 6} />}
                {routes.length ? <rect className="shape" x={-R} y={-R} width={2 * R} height={2 * R} rx={9} /> : <circle className="shape" r={R} />}
                <text className="glyph" y={5} textAnchor="middle">
                  {node.name.slice(0, 1).toUpperCase()}
                </text>
                <text className="name" y={R + 16} textAnchor="middle">
                  {node.name}
                </text>
                <text className="address" y={R + 29} textAnchor="middle">
                  {node.status === 'pending' ? 'waiting for approval' : node.address}
                </text>
              </g>
            </g>
          );
        })}
      </g>
    </svg>
  );
}
