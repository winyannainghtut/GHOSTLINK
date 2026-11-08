// The glass component kit: surfaces, pill controls, an iOS-style switch, sheets, toasts and
// confirmations. Everything is styled with classes (no inline style attributes) for the CSP.
import { X } from 'lucide-react';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ComponentProps,
  type ReactNode,
} from 'react';
import { speed } from './format';

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ');
}

// Live download and upload for a compact readout such as the Island, each in bytes per second
// with its own unit. Each value has room for its usual widest form, so the capsule keeps its
// width as the numbers change. className must set the display (`inline-flex`, or for example
// `hidden sm:inline-flex`): a display class here would win over the caller's.
export function LiveRates({ down, up, className }: { down: number; up: number; className: string }) {
  // The arrow stays with its number; the pair is right-aligned in its slot, so spare room falls
  // between the two rates rather than inside one.
  const rate = (arrow: string, label: string, value: number) => (
    <span className="inline-flex min-w-[9ch] items-baseline justify-end gap-1 whitespace-nowrap">
      <span aria-hidden="true">{arrow}</span>
      <span className="sr-only">{label}</span>
      <span>{speed(value)}</span>
    </span>
  );
  return (
    <span className={cx('num items-baseline gap-1.5', className)}>
      {rate('↓', 'Download', down)}
      {rate('↑', 'Upload', up)}
    </span>
  );
}

export function Card({ className, children, as: Tag = 'section' }: { className?: string; children: ReactNode; as?: 'section' | 'div' | 'article' }) {
  return <Tag className={cx('glass rounded-[28px] p-5 sm:p-6', className)}>{children}</Tag>;
}

export function Inner({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cx('inset-glass rounded-[24px] p-4', className)}>{children}</div>;
}

export function CardTitle({ title, detail, action }: { title: ReactNode; detail?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="text-[15px] text-fg">{title}</h2>
        {detail && <p className="mt-0.5 text-[12.5px] text-fg-3">{detail}</p>}
      </div>
      {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
    </div>
  );
}

type Variant = 'cta' | 'glass' | 'ghost' | 'danger';
type ButtonProps = ComponentProps<'button'> & { variant?: Variant; size?: 'sm' | 'md'; icon?: ReactNode };

export function Button({ variant = 'glass', size = 'md', icon, className, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={cx(
        'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-full font-medium whitespace-nowrap transition duration-200 select-none active:scale-[0.97]',
        size === 'sm' ? 'h-8 px-3.5 text-[12.5px]' : 'h-10 px-4.5 text-[13.5px]',
        variant === 'cta' && 'bg-cta text-cta-fg shadow-[0_8px_24px_-12px_rgb(0_0_0/0.6)] hover:opacity-90',
        variant === 'glass' && 'inset-glass text-fg hover:bg-glass-strong',
        variant === 'ghost' && 'text-fg-2 hover:bg-glass hover:text-fg',
        variant === 'danger' && 'bg-bad/15 text-bad hover:bg-bad/25',
        className,
      )}
      {...rest}
    >
      {icon}
      {children}
    </button>
  );
}

export function IconButton({ label, className, children, ...rest }: ComponentProps<'button'> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cx('inline-flex size-9 shrink-0 items-center justify-center rounded-full text-fg-2 transition hover:bg-glass-strong hover:text-fg active:scale-95', className)}
      {...rest}
    >
      {children}
    </button>
  );
}

export type SegmentOption<T extends string> = { value: T; label: ReactNode; icon?: ReactNode; title?: string };

export function Segmented<T extends string>({ value, options, onChange, size = 'md', label, className }: {
  value: T;
  options: SegmentOption<T>[];
  onChange: (value: T) => void;
  size?: 'sm' | 'md';
  label: string;
  className?: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className={cx('inset-glass inline-flex items-center gap-0.5 rounded-full p-1', className)}>
      {options.map(o => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            title={o.title}
            onClick={() => onChange(o.value)}
            className={cx(
              'inline-flex items-center gap-1.5 rounded-full font-medium whitespace-nowrap transition duration-300',
              size === 'sm' ? 'h-7 px-3 text-[12px]' : 'h-8 px-4 text-[13px]',
              active ? 'bg-glass-strong text-fg shadow-[inset_0_1px_0_var(--highlight),0_4px_14px_-8px_rgb(0_0_0/0.5)]' : 'text-fg-2 hover:text-fg',
            )}
          >
            {o.icon}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (next: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={event => {
        event.stopPropagation();
        onChange(!checked);
      }}
      className={cx(
        'relative inline-flex h-[26px] w-[44px] shrink-0 items-center rounded-full border border-line transition-colors duration-300',
        checked ? 'bg-ok' : 'bg-switch-off',
      )}
    >
      <span
        className={cx(
          'absolute top-[2px] left-[2px] size-5 rounded-full bg-white shadow-[0_2px_6px_rgb(0_0_0/0.35)] transition-transform duration-300 ease-[cubic-bezier(0.3,1.4,0.5,1)]',
          checked && 'translate-x-[18px]',
        )}
      />
    </button>
  );
}

export type Status = 'online' | 'idle' | 'paused' | 'limit' | 'pending' | 'offline';

const statusColor: Record<Status, string> = {
  online: 'bg-ok',
  idle: 'bg-idle',
  paused: 'bg-fg-3',
  limit: 'bg-bad',
  pending: 'bg-idle',
  offline: 'bg-fg-3',
};

export function StatusDot({ status, className }: { status: Status; className?: string }) {
  return (
    <span className={cx('relative inline-flex size-2.5 shrink-0', className)} aria-hidden="true">
      {status === 'online' && <span className="absolute inset-0 animate-ping rounded-full bg-ok opacity-40 motion-reduce:animate-none" />}
      <span className={cx('relative inline-flex size-2.5 rounded-full', statusColor[status])} />
    </span>
  );
}

const meterWidths = ['w-0', 'w-[5%]', 'w-[10%]', 'w-[15%]', 'w-[20%]', 'w-[25%]', 'w-[30%]', 'w-[35%]', 'w-[40%]', 'w-[45%]', 'w-[50%]', 'w-[55%]', 'w-[60%]', 'w-[65%]', 'w-[70%]', 'w-[75%]', 'w-[80%]', 'w-[85%]', 'w-[90%]', 'w-[95%]', 'w-full'];

// A thin progress bar. Widths step in 5 % so they stay classes (no inline styles).
export function Meter({ fraction, tone = 'fg', className }: { fraction: number; tone?: 'fg' | 'ok' | 'bad' | 'down'; className?: string }) {
  const step = Math.min(20, Math.max(0, Math.round((Number.isFinite(fraction) ? fraction : 0) * 20)));
  const width = fraction > 0 && step === 0 ? 'w-[2%]' : meterWidths[step];
  return (
    <div className={cx('h-1.5 overflow-hidden rounded-full bg-field', className)}>
      <div className={cx('h-full rounded-full transition-[width] duration-700', width, tone === 'fg' ? 'bg-fg/70' : tone === 'ok' ? 'bg-ok' : tone === 'bad' ? 'bg-bad' : 'bg-down')} />
    </div>
  );
}

export function Field({ label, hint, children, className }: { label: ReactNode; hint?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <label className={cx('grid gap-1.5', className)}>
      <span className="text-[12.5px] font-medium text-fg-2">
        {label}
        {hint && <span className="font-normal text-fg-3"> · {hint}</span>}
      </span>
      {children}
    </label>
  );
}

export function Check({ checked, onChange, children }: { checked: boolean; onChange: (next: boolean) => void; children: ReactNode }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4 py-1.5">
      <span className="text-[13.5px] text-fg">{children}</span>
      <Switch checked={checked} onChange={onChange} label={typeof children === 'string' ? children : 'Toggle'} />
    </label>
  );
}

export function Note({ children, tone = 'muted' }: { children: ReactNode; tone?: 'muted' | 'warn' | 'bad' }) {
  return <p className={cx('text-[12.5px] leading-relaxed', tone === 'muted' && 'text-fg-3', tone === 'warn' && 'text-idle', tone === 'bad' && 'text-bad')}>{children}</p>;
}

export function Facts({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-[13px]">
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-fg-3">{k}</dt>
          <dd className="m-0 min-w-0 text-right break-words text-fg">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="grid place-items-center gap-2 px-6 py-12 text-center">
      {icon && <div className="mb-1 grid size-12 place-items-center rounded-full bg-glass-strong text-fg-2">{icon}</div>}
      <h3 className="text-[15px]">{title}</h3>
      {children && <div className="max-w-sm text-[13px] text-fg-3">{children}</div>}
    </div>
  );
}

// A modal sheet built on <dialog> (focus, Escape and the top layer come from the browser).
export function Sheet({ open, onClose, title, subtitle, size = 'normal', children, footer }: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  size?: 'normal' | 'medium' | 'wide';
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className={cx('sheet m-auto', size === 'wide' && 'sheet-wide', size === 'medium' && 'sheet-medium')}
      onClose={onClose}
      onCancel={event => {
        event.preventDefault();
        onClose();
      }}
      onMouseDown={event => {
        if (event.target === ref.current) onClose();
      }}
    >
      {open && (
        <div className="glass-strong flex max-h-[calc(100vh-48px)] flex-col overflow-hidden rounded-[28px]">
          <header className="flex items-start justify-between gap-4 px-6 pt-6 pb-3">
            <div className="min-w-0">
              <h2 className="text-[19px]">{title}</h2>
              {subtitle && <p className="mt-1 text-[13px] text-fg-3">{subtitle}</p>}
            </div>
            <IconButton label="Close" onClick={onClose}>
              <X size={18} />
            </IconButton>
          </header>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 pb-6">{children}</div>
          {footer && <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-line px-6 py-4">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}

// --- toasts and confirmations ---------------------------------------------------------------

type Toast = { id: number; message: string; tone: 'ok' | 'bad' | 'info' };
type Ask = { title: string; text: string; action: string; danger?: boolean };
type UI = {
  toast: (message: string, tone?: Toast['tone']) => void;
  confirm: (ask: Ask) => Promise<boolean>;
};

const UIContext = createContext<UI>({ toast: () => {}, confirm: async () => false });

export function useUI(): UI {
  return useContext(UIContext);
}

export function UIProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [ask, setAsk] = useState<(Ask & { resolve: (yes: boolean) => void }) | null>(null);
  const next = useRef(1);
  const toast = useCallback((message: string, tone: Toast['tone'] = 'ok') => {
    const id = next.current++;
    setToasts(list => [...list.slice(-2), { id, message, tone }]);
    window.setTimeout(() => setToasts(list => list.filter(t => t.id !== id)), tone === 'bad' ? 6000 : 3200);
  }, []);
  const confirm = useCallback((question: Ask) => new Promise<boolean>(resolve => setAsk({ ...question, resolve })), []);
  const answer = (yes: boolean) => {
    ask?.resolve(yes);
    setAsk(null);
  };
  return (
    <UIContext.Provider value={{ toast, confirm }}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex flex-col items-center gap-2 px-4" aria-live="polite">
        {toasts.map(t => (
          <div
            key={t.id}
            className={cx(
              'glass-strong pointer-events-auto flex max-w-[min(560px,100%)] items-center gap-2.5 rounded-[22px] px-4.5 py-2.5 text-[13px] text-fg',
              'animate-[sheet-in_0.3s_cubic-bezier(0.2,0.9,0.25,1)]',
            )}
          >
            <span className={cx('size-2 shrink-0 rounded-full', t.tone === 'ok' ? 'bg-ok' : t.tone === 'bad' ? 'bg-bad' : 'bg-down')} />
            {t.message}
          </div>
        ))}
      </div>
      <Sheet
        open={ask !== null}
        onClose={() => answer(false)}
        title={ask?.title ?? ''}
        footer={
          <>
            <Button variant="ghost" onClick={() => answer(false)}>
              Cancel
            </Button>
            <Button variant={ask?.danger ? 'danger' : 'cta'} onClick={() => answer(true)}>
              {ask?.action}
            </Button>
          </>
        }
      >
        <p className="text-[13.5px] text-fg-2">{ask?.text}</p>
      </Sheet>
    </UIContext.Provider>
  );
}
