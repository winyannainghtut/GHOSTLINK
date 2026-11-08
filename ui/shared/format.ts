// Number and time formatting. Live numbers are shown with tabular figures (the `num` class), so
// these keep a stable shape: fixed decimals per unit. No imports, so the tests run it directly.

type Unit = { unit: string; size: number; decimals: number };

// The largest unit the value reaches, with that unit's fixed decimals. Rounding can reach 1000
// of a unit (999,700 B/s would read "1000 KB/s"): the next unit is used then.
function scaled(n: number, units: Unit[]): { value: string; unit: string } {
  let i = units.length - 1;
  while (i > 0 && n < units[i].size) i--;
  if (i < units.length - 1 && Number((n / units[i].size).toFixed(units[i].decimals)) >= 1000) i++;
  return { value: (n / units[i].size).toFixed(units[i].decimals), unit: units[i].unit };
}

const RATE_UNITS: Unit[] = [
  { unit: 'B/s', size: 1, decimals: 0 },
  { unit: 'KB/s', size: 1e3, decimals: 0 },
  { unit: 'MB/s', size: 1e6, decimals: 1 },
  { unit: 'GB/s', size: 1e9, decimals: 2 },
];

const SIZE_UNITS: Unit[] = [
  { unit: 'B', size: 1, decimals: 0 },
  { unit: 'KB', size: 1e3, decimals: 0 },
  { unit: 'MB', size: 1e6, decimals: 1 },
  { unit: 'GB', size: 1e9, decimals: 1 },
  { unit: 'TB', size: 1e12, decimals: 2 },
];

// Speeds are shown in bytes per second, with the same decimal units as data (1 MB = 10^6 bytes).
export function byteRate(bytesPerSecond: number): { value: string; unit: string } {
  return scaled(Math.max(0, Number(bytesPerSecond) || 0), RATE_UNITS);
}

export function speed(bytesPerSecond: number): string {
  const { value, unit } = byteRate(bytesPerSecond);
  return `${value} ${unit}`;
}

export function bytes(n: number): string {
  const { value, unit } = scaled(Math.max(0, Number(n) || 0), SIZE_UNITS);
  return `${value} ${unit}`;
}

// The start of a usage bucket. The server starts daily buckets at midnight UTC, so a day is
// named by its UTC date: in the local time zone, west of UTC, it would read one day early.
// Hourly buckets are shown in local time, with the date when the chart spans several days.
export function bucketLabel(t: number, unit: 'hour' | 'day', withDate = false, locale?: string): string {
  const date = new Date(t * 1000);
  if (unit === 'day') return date.toLocaleDateString(locale, { month: 'short', day: 'numeric', timeZone: 'UTC' });
  return date.toLocaleString(locale, withDate ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' } : { hour: '2-digit', minute: '2-digit' });
}

export function ago(unix: number | undefined, now = Date.now() / 1000): string {
  if (!unix) return 'Never';
  const s = Math.max(0, now - unix);
  if (s < 10) return 'Just now';
  if (s < 60) return `${Math.floor(s)} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function duration(seconds: number): string {
  seconds = Math.max(0, Math.floor(seconds));
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} min`;
  if (m > 0) return `${m} min`;
  return `${seconds} s`;
}

export function plural(count: number, word: string, many = word + 's'): string {
  return `${count} ${count === 1 ? word : many}`;
}

export function dateTime(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function lines(text: string): string[] {
  return text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
}

export function words(text: string): string[] {
  return text.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
}

export function fileSafe(name: string): string {
  return name.replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '') || 'ghostlink';
}

// The name of a downloaded .conf, without the extension. WireGuard for Windows and AmneziaWG
// name the tunnel after the file and refuse more than 32 characters (or any outside A-Z a-z
// 0-9 _ = + . -), so the client's name is shortened to keep the protocol and key ID. Three
// characters are left for the desktop app's "-1" to "-99" when Downloads has the name already.
export const CONF_NAME_MAX = 29;
export function confName(user: string, protocol: string, id: string): string {
  const suffix = `-${protocol}-${id}`.slice(0, CONF_NAME_MAX - 1);
  const room = CONF_NAME_MAX - suffix.length;
  const base = fileSafe(user).slice(0, room).replace(/[-.]+$/, '') || 'ghostlink'.slice(0, room);
  return base + suffix;
}

export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
