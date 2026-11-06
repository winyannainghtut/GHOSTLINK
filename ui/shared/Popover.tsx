// A small frosted panel anchored to a button. It renders at the page level: a frosted element
// cannot blur through a frosted parent (the card or nav it opens from).
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { cx } from './glass';

export function Popover({ anchor, open, onClose, children, width = 240, align = 'end', className }: {
  anchor: RefObject<HTMLElement | null>;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  width?: number;
  align?: 'start' | 'center' | 'end';
  className?: string;
}) {
  const panel = useRef<HTMLDivElement>(null);
  const [place, setPlace] = useState<{ top: number; left: number } | null>(null);
  useLayoutEffect(() => {
    if (!open) return;
    const update = () => {
      const r = anchor.current?.getBoundingClientRect();
      if (!r) return;
      const x = align === 'start' ? r.left : align === 'center' ? r.left + r.width / 2 - width / 2 : r.right - width;
      setPlace({ top: r.bottom + 8, left: Math.min(window.innerWidth - width - 8, Math.max(8, x)) });
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [open, anchor, width, align]);
  useEffect(() => {
    if (!open) return;
    const outside = (e: MouseEvent) => {
      if (!panel.current?.contains(e.target as Node) && !anchor.current?.contains(e.target as Node)) onClose();
    };
    const escape = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('mousedown', outside);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('mousedown', outside);
      document.removeEventListener('keydown', escape);
    };
  }, [open, onClose, anchor]);
  if (!open || !place) return null;
  return createPortal(
    <div ref={panel} style={{ top: place.top, left: place.left, width }} className={cx('glass-strong fixed z-40 rounded-[24px] p-2 animate-[sheet-in_0.22s_cubic-bezier(0.2,0.9,0.25,1)]', className)}>
      {children}
    </div>,
    document.body,
  );
}

export function MenuItem({ children, onClick, danger, icon }: { children: ReactNode; onClick: () => void; danger?: boolean; icon?: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className={cx('flex w-full items-center gap-2.5 rounded-[16px] px-3 py-2 text-left text-[13.5px] transition hover:bg-glass-strong', danger ? 'text-bad' : 'text-fg')}>
      {icon && <span className="text-fg-3">{icon}</span>}
      {children}
    </button>
  );
}
