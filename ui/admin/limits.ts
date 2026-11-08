// Speed and data limits as typed in the admin views, and what to send for them. Speeds are in
// megabytes per second (bytes, like every speed shown) and data in gigabytes. No imports, so the
// tests run it directly (node --experimental-strip-types).

export type SpeedMode = 'default' | 'none' | 'custom';
export type SpeedChoice = { mode: SpeedMode; mb: string };

// The API's speed_limit_bps: 0 follows the server's default, -1 means no limit.
export function speedChoice(bps: number | undefined): SpeedChoice {
  if (!bps) return { mode: 'default', mb: '' };
  if (bps < 0) return { mode: 'none', mb: '' };
  return { mode: 'custom', mb: String(bps / 1e6) };
}

// The value to send, or an error to show.
export function speedValue(choice: SpeedChoice): number | Error {
  if (choice.mode === 'default') return 0;
  if (choice.mode === 'none') return -1;
  const mb = Number(choice.mb);
  if (!choice.mb.trim() || !Number.isFinite(mb) || mb < 0.001 || mb > 1250) return new Error('A speed limit is 0.001 to 1250 MB/s.');
  return Math.round(mb * 1e6);
}

// A client's speed limit when its settings are saved: undefined to leave it out (unchanged), the
// new value, or an error. An unchanged limit is not checked again: the server's CLI can set
// limits below 0.001 MB/s, which must not block saving the client's other settings. Leaving it
// out also keeps saving working on servers before 0.8.0, which refuse the field.
export function speedChange(choice: SpeedChoice, stored: number): number | undefined | Error {
  const same = speedChoice(stored);
  if (choice.mode === same.mode && (choice.mode !== 'custom' || choice.mb.trim() === same.mb)) return undefined;
  const bps = speedValue(choice);
  return bps instanceof Error || bps !== stored ? bps : undefined;
}

// The server's default speed limit as typed (MB/s, empty for none).
export function defaultSpeedText(bps: number | undefined): string {
  return bps ? String(bps / 1e6) : '';
}

// The default speed limit to send: undefined when unchanged (so a default below 0.001 MB/s set
// on the server does not block the other settings), the new value (0 for none), or an error.
export function defaultSpeedChange(text: string, stored: number): number | undefined | Error {
  if (text.trim() === defaultSpeedText(stored)) return undefined;
  const mb = text.trim() ? Number(text) : 0;
  if (!Number.isFinite(mb) || (mb !== 0 && (mb < 0.001 || mb > 1250))) return new Error('The default speed limit is 0.001 to 1250 MB/s, or empty for none.');
  const bps = Math.round(mb * 1e6);
  return bps === stored ? undefined : bps;
}

// A data limit typed in GB, empty for none: the bytes to send, or an error to show. badInput is
// the field's validity.badInput: a number field reports half-typed text such as "2e" as empty,
// which would otherwise remove the limit.
export function dataLimitValue(text: string, badInput = false): number | Error {
  const gb = text.trim() ? Number(text) : 0;
  if (badInput || !Number.isFinite(gb) || gb < 0 || gb > 1e9) return new Error('The data limit is a number of GB, or empty for no limit.');
  return Math.round(gb * 1e9);
}
