import { bytes } from './format';
import { Meter } from './glass';

// Horizontal bars for byte totals (traffic types, protocols, services, users).
export function Bars({ items, empty, label }: { items: { label: string; bytes: number }[] | undefined; empty: string; label?: (raw: string) => string }) {
  if (!items || !items.length) return <p className="py-6 text-center text-[13px] text-fg-3">{empty}</p>;
  const top = Math.max(1, ...items.map(i => i.bytes));
  return (
    <ul className="grid gap-3">
      {items.slice(0, 8).map(item => (
        <li key={item.label} className="grid gap-1.5">
          <div className="flex items-baseline justify-between gap-3 text-[13px]">
            <span className="truncate text-fg">{label ? label(item.label) : item.label}</span>
            <span className="num shrink-0 text-fg-2">{bytes(item.bytes)}</span>
          </div>
          <Meter fraction={item.bytes / top} tone="down" />
        </li>
      ))}
    </ul>
  );
}
