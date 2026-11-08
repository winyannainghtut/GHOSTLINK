// Stacked usage bars per hour or day (download below upload), sized to the element.
import { useEffect, useRef, useState } from 'react';
import { bucketLabel, bytes } from './format';

export type UsageBucket = { t: number; down: number; up: number };

// The server returns only buckets that saw traffic; fill the whole period with empty ones so a
// single busy hour is one bar among 24 (or 168, 30, 90), not the whole chart. Buckets keep the
// server's alignment (its day starts), taken from the newest bucket.
export function fillBuckets(buckets: UsageBucket[], step: number, count: number, now = Date.now() / 1000): UsageBucket[] {
  const offset = buckets.length ? ((buckets[buckets.length - 1].t % step) + step) % step : 0;
  const end = Math.floor((now - offset) / step) * step + offset;
  const byT = new Map(buckets.map(b => [b.t, b]));
  const out: UsageBucket[] = [];
  for (let i = count - 1; i >= 0; i--) {
    const t = end - i * step;
    out.push(byT.get(t) ?? { t, down: 0, up: 0 });
  }
  return out;
}

export function BarChart({ buckets, unit, height = 170 }: { buckets: UsageBucket[]; unit: 'hour' | 'day'; height?: number }) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    const element = box.current;
    if (!element) return;
    const observer = new ResizeObserver(entries => setWidth(Math.max(240, Math.floor(entries[0].contentRect.width))));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const top = 10, bottom = 22, plotH = height - top - bottom;
  const max = Math.max(1, ...buckets.map(b => b.down + b.up));
  const slot = width / Math.max(buckets.length, 1);
  // More than a day of hourly bars (7 days is 168): an hour alone would not say which day.
  const label = (t: number) => bucketLabel(t, unit, unit === 'hour' && buckets.length > 24);
  const at = hover !== null ? buckets[hover] : null;
  return (
    <div ref={box} className="relative">
      <svg className="chart block w-full" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Usage over time" onPointerLeave={() => setHover(null)}>
        <defs>
          <linearGradient id="bar-down" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="stop-down" stopOpacity="0.95" />
            <stop offset="1" className="stop-down" stopOpacity="0.45" />
          </linearGradient>
          <linearGradient id="bar-up" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="stop-up" stopOpacity="0.95" />
            <stop offset="1" className="stop-up" stopOpacity="0.5" />
          </linearGradient>
        </defs>
        <line className="gridline" x1={0} x2={width} y1={top + plotH} y2={top + plotH} />
        {buckets.map((b, i) => {
          const down = (b.down / max) * plotH, up = (b.up / max) * plotH, w = Math.max(1, slot - Math.min(4, slot * 0.3));
          const x = i * slot + (slot - w) / 2;
          return (
            <g key={b.t} onPointerEnter={() => setHover(i)} opacity={hover === null || hover === i ? 1 : 0.55}>
              <rect x={i * slot} y={top} width={slot} height={plotH} fill="transparent" />
              <rect x={x} y={top + plotH - down} width={w} height={down} rx={Math.min(3, w / 2)} fill="url(#bar-down)" />
              <rect x={x} y={top + plotH - down - up} width={w} height={up} rx={Math.min(3, w / 2)} fill="url(#bar-up)" />
            </g>
          );
        })}
        {buckets.length > 0 && (
          <>
            <text className="axis-label" x={2} y={height - 6}>
              {label(buckets[0].t)}
            </text>
            <text className="axis-label" x={width - 2} y={height - 6} textAnchor="end">
              {label(buckets[buckets.length - 1].t)}
            </text>
            <text className="axis-label" x={width - 2} y={top + 2} textAnchor="end" dominantBaseline="hanging">
              {bytes(max)} per {unit}
            </text>
          </>
        )}
      </svg>
      {!buckets.some(b => b.down + b.up > 0) && <p className="pointer-events-none absolute inset-0 grid place-items-center text-[13px] text-fg-3">No traffic recorded in this period</p>}
      {at && (
        <div className="glass-strong pointer-events-none absolute top-1 left-2 flex gap-3 rounded-full px-3 py-1.5 text-[12px]">
          <span className="text-fg-3">{label(at.t)}</span>
          <span className="num text-down">↓ {bytes(at.down)}</span>
          <span className="num text-up">↑ {bytes(at.up)}</span>
        </div>
      )}
    </div>
  );
}
