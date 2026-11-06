// Three ultra-subtle glass ribbons behind the interface. Each is a band between two smooth
// curves with a faint cool-silver gradient and a razor-thin crest, drifting sideways on its own
// slow ease-in-out loop (paused in "Still" and for reduced motion). Frosted cards above soften them.
import { memo } from 'react';

const WIDTH = 2880; // twice the design width: the ribbons drift by a quarter of it
const HEIGHT = 900;

type Point = [number, number];

// Catmull-Rom through the points, as cubic Bézier segments.
function smooth(points: Point[]): string {
  let d = `M${points[0][0]},${points[0][1].toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[Math.max(0, i - 1)], p1 = points[i], p2 = points[i + 1], p3 = points[Math.min(points.length - 1, i + 2)];
    const c1: Point = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
    const c2: Point = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
    d += ` C${c1[0].toFixed(1)},${c1[1].toFixed(1)} ${c2[0].toFixed(1)},${c2[1].toFixed(1)} ${p2[0]},${p2[1].toFixed(1)}`;
  }
  return d;
}

function curve(base: number, amplitude: number, period: number, phase: number, wobble: number): Point[] {
  const points: Point[] = [];
  for (let x = 0; x <= WIDTH; x += 160) {
    const t = (x / period) * Math.PI * 2 + phase;
    points.push([x, base + Math.sin(t) * amplitude + Math.sin(t * 0.47 + phase * 2) * wobble]);
  }
  return points;
}

type Ribbon = { base: number; amplitude: number; period: number; phase: number; thickness: number; opacity: number };

const RIBBONS: Ribbon[] = [
  { base: 300, amplitude: 70, period: 1440, phase: 0.4, thickness: 170, opacity: 0.07 },
  { base: 470, amplitude: 90, period: 1920, phase: 2.1, thickness: 210, opacity: 0.05 },
  { base: 640, amplitude: 60, period: 1200, phase: 4.0, thickness: 240, opacity: 0.035 },
];

function shapes(r: Ribbon) {
  const top = curve(r.base, r.amplitude, r.period, r.phase, r.amplitude * 0.25);
  const bottom = curve(r.base + r.thickness, r.amplitude * 0.8, r.period, r.phase + 0.6, r.amplitude * 0.2).reverse();
  const crest = smooth(top);
  const band = `${crest} L${bottom[0][0]},${bottom[0][1].toFixed(1)} ${smooth(bottom).slice(1)} Z`;
  return { crest, band };
}

const PATHS = RIBBONS.map(shapes);

export const WaveBackground = memo(function WaveBackground() {
  return (
    <div className="waves" aria-hidden="true">
      {RIBBONS.map((ribbon, i) => (
        <svg key={i} className={`wave wave-${i + 1} top-0`} viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none">
          <defs>
            <linearGradient id={`wave-fill-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" className="wave-stop-a" stopOpacity={ribbon.opacity} />
              <stop offset="0.55" className="wave-stop-b" stopOpacity={ribbon.opacity * 0.55} />
              <stop offset="1" className="wave-stop-b" stopOpacity="0" />
            </linearGradient>
            <linearGradient id={`wave-crest-${i}`} x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" className="wave-stop-a" stopOpacity="0" />
              <stop offset="0.3" className="wave-stop-a" stopOpacity="1" />
              <stop offset="0.7" className="wave-stop-a" stopOpacity="0.6" />
              <stop offset="1" className="wave-stop-a" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={PATHS[i].band} fill={`url(#wave-fill-${i})`} />
          <path d={PATHS[i].crest} className="wave-crest" fill="none" stroke={`url(#wave-crest-${i})`} strokeWidth="0.75" vectorEffect="non-scaling-stroke" />
        </svg>
      ))}
    </div>
  );
});
