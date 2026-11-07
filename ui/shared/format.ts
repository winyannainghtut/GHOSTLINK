// Number and time formatting. Live numbers are shown with tabular figures (the `num` class), so
// these keep a stable shape: fixed decimals per unit.

// Speeds are shown in bytes per second, with the same decimal units as data (1 MB = 10^6 bytes).
export function byteRate(bytesPerSecond: number): { value: string; unit: string } {
  const b = Math.max(0, Number(bytesPerSecond) || 0);
  if (b >= 1e9) return { value: (b / 1e9).toFixed(2), unit: 'GB/s' };
  if (b >= 1e6) return { value: (b / 1e6).toFixed(1), unit: 'MB/s' };
  if (b >= 1e3) return { value: (b / 1e3).toFixed(0), unit: 'KB/s' };
  return { value: b.toFixed(0), unit: 'B/s' };
}

export function speed(bytesPerSecond: number): string {
  const { value, unit } = byteRate(bytesPerSecond);
  return `${value} ${unit}`;
}

// MB/s with two significant decimals, for compact live readouts such as the Island.
export function megabytes(bytesPerSecond: number): string {
  const mb = Math.max(0, Number(bytesPerSecond) || 0) / 1e6;
  return mb.toFixed(mb >= 100 ? 0 : mb >= 10 ? 1 : 2);
}

export function bytes(n: number): string {
  n = Math.max(0, Number(n) || 0);
  if (n >= 1e12) return (n / 1e12).toFixed(2) + ' TB';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + ' GB';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return Math.round(n / 1e3) + ' KB';
  return n + ' B';
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
