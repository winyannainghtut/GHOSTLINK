// A two-series area chart (download and upload) drawn at the element's real pixel size, with
// monotone curves (no overshoot below zero) and a hover readout.
import { useEffect, useRef, useState } from 'react';
import { speed } from './format';

export type RatePoint = { t: number; down: number; up: number };

function monotone(points: [number, number][]): string {
  const n = points.length;
  if (n === 0) return '';
  if (n === 1) return `M${points[0][0]},${points[0][1]}`;
  const dx: number[] = [], slope: number[] = [];
  for (let i = 0; i < n - 1; i++) {
    dx.push(points[i + 1][0] - points[i][0]);
    slope.push((points[i + 1][1] - points[i][1]) / (dx[i] || 1));
  }
  const m: number[] = [slope[0]];
  for (let i = 1; i < n - 1; i++) m.push(slope[i - 1] * slope[i] <= 0 ? 0 : (3 * (dx[i - 1] + dx[i])) / ((2 * dx[i] + dx[i - 1]) / slope[i - 1] + (dx[i] + 2 * dx[i - 1]) / slope[i]));
  m.push(slope[n - 2]);
  let d = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const [x0, y0] = points[i], [x1, y1] = points[i + 1], h = dx[i] / 3;
    d += ` C${(x0 + h).toFixed(1)},${(y0 + m[i] * h).toFixed(1)} ${(x1 - h).toFixed(1)},${(y1 - m[i + 1] * h).toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
  }
  return d;
}

function niceMax(value: number): number {
  if (value <= 0) return 125_000; // 1 Mbit/s
  const bits = value * 8 * 1.15;
  const power = 10 ** Math.floor(Math.log10(bits));
  const step = [1, 2, 2.5, 5, 10].find(s => s * power >= bits) ?? 10;
  return (step * power) / 8;
}

export function AreaChart({ points, height = 220, timeLabel, empty }: {
  points: RatePoint[];
  height?: number;
  timeLabel: (t: number) => string;
  empty?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    const element = box.current;
    if (!element) return;
    const observer = new ResizeObserver(entries => setWidth(Math.max(240, Math.floor(entries[0].contentRect.width))));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const left = 4, right = 4, top = 12, bottom = 26;
  const plotW = width - left - right, plotH = height - top - bottom;
  const max = niceMax(Math.max(0, ...points.flatMap(p => [p.down, p.up])));
  const x = (i: number) => left + (points.length > 1 ? (i / (points.length - 1)) * plotW : plotW);
  const y = (v: number) => top + plotH - (Math.min(v, max) / max) * plotH;
  const series = (key: 'down' | 'up') => points.map((p, i) => [x(i), y(p[key])] as [number, number]);
  const line = (key: 'down' | 'up') => monotone(series(key));
  const area = (key: 'down' | 'up') => (points.length ? `${line(key)} L${x(points.length - 1).toFixed(1)},${top + plotH} L${x(0).toFixed(1)},${top + plotH} Z` : '');
  const quiet = points.every(p => p.down + p.up === 0);
  const ticks = [0.25, 0.5, 0.75, 1].map(f => f * max);
  const at = hover !== null && points[hover] ? points[hover] : null;

  return (
    <div ref={box} className="relative w-full">
      <svg
        className="chart block w-full"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="Throughput over time"
        onPointerMove={event => {
          if (points.length < 2) return;
          const rect = event.currentTarget.getBoundingClientRect();
          const i = Math.round(((event.clientX - rect.left - left) / plotW) * (points.length - 1));
          setHover(Math.min(points.length - 1, Math.max(0, i)));
        }}
        onPointerLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id="fill-down" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="stop-down" stopOpacity="0.32" />
            <stop offset="1" className="stop-down" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="fill-up" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="stop-up" stopOpacity="0.26" />
            <stop offset="1" className="stop-up" stopOpacity="0" />
          </linearGradient>
        </defs>
        {ticks.map(v => (
          <g key={v}>
            <line className="gridline" x1={left} x2={width - right} y1={y(v)} y2={y(v)} strokeDasharray="2 4" />
            <text className="axis-label" x={width - right} y={y(v) - 4} textAnchor="end">
              {speed(v)}
            </text>
          </g>
        ))}
        <line className="gridline" x1={left} x2={width - right} y1={top + plotH} y2={top + plotH} />
        {points.length > 0 && (
          <>
            <path className="area-down" d={area('down')} />
            <path className="area-up" d={area('up')} />
            <path className="line-down" d={line('down')} />
            <path className="line-up" d={line('up')} />
            <text className="axis-label" x={left} y={height - 8}>
              {timeLabel(points[0].t)}
            </text>
            <text className="axis-label" x={width - right} y={height - 8} textAnchor="end">
              {timeLabel(points[points.length - 1].t)}
            </text>
          </>
        )}
        {at && hover !== null && (
          <g>
            <line className="gridline" x1={x(hover)} x2={x(hover)} y1={top} y2={top + plotH} />
            <circle cx={x(hover)} cy={y(at.down)} r="3.5" className="line-down" />
            <circle cx={x(hover)} cy={y(at.up)} r="3.5" className="line-up" />
          </g>
        )}
      </svg>
      {(quiet || !points.length) && empty && (
        <p className="pointer-events-none absolute inset-0 grid place-items-center text-[13px] text-fg-3">{empty}</p>
      )}
      {at && (
        <div className="glass-strong pointer-events-none absolute top-2 left-3 flex items-center gap-3 rounded-full px-3 py-1.5 text-[12px]">
          <span className="text-fg-3">{timeLabel(at.t)}</span>
          <span className="num text-down">↓ {speed(at.down)}</span>
          <span className="num text-up">↑ {speed(at.up)}</span>
        </div>
      )}
    </div>
  );
}
