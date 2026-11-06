// Appearance shared by both apps: the brand mark, the three finishes and the wave motion.
import { Waves } from 'lucide-react';
import { useEffect } from 'react';
import { cx } from './glass';
import { prefersReducedMotion, useStoredState } from './hooks';

export const FINISHES = ['obsidian', 'titanium', 'daylight'] as const;
export type Finish = (typeof FINISHES)[number];
export const MOTIONS = ['subtle', 'calm', 'still'] as const;
export type Motion = (typeof MOTIONS)[number];

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

export function useAppearance() {
  const [finish, setFinish] = useStoredState<Finish>('ghostlink-finish', 'obsidian', FINISHES);
  const [motion, setMotion] = useStoredState<Motion>('ghostlink-motion', prefersReducedMotion() ? 'still' : 'subtle', MOTIONS);
  useEffect(() => {
    document.documentElement.dataset.finish = finish;
    document.documentElement.dataset.motion = motion;
  }, [finish, motion]);
  return { finish, setFinish, motion, setMotion };
}
export type Appearance = ReturnType<typeof useAppearance>;

const nextMotion: Record<Motion, Motion> = { subtle: 'calm', calm: 'still', still: 'subtle' };

export function MotionButton({ motion, onChange }: { motion: Motion; onChange: (m: Motion) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(nextMotion[motion])}
      title="Background motion: Subtle, Calm or Still"
      className="inline-flex h-9 items-center gap-1.5 rounded-full px-3 text-[12.5px] text-fg-2 transition hover:bg-glass-strong hover:text-fg"
    >
      <Waves size={16} />
      <span className="w-[42px] text-left capitalize">{motion}</span>
    </button>
  );
}

const swatch: Record<Finish, string> = {
  obsidian: 'bg-[#090a0d]',
  titanium: 'bg-[#2a2e37]',
  daylight: 'bg-[#f2f4f8]',
};

export function FinishPicker({ value, onChange }: { value: Finish; onChange: (f: Finish) => void }) {
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
