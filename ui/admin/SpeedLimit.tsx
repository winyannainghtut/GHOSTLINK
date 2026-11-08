// A client's speed limit, entered in megabytes per second (bytes, like every speed shown): the
// server's default, no limit, or a cap of its own. One cap covers download and upload alike, across all of the
// client's keys and devices.
import { Field, Segmented } from '@shared/glass';
import { speed } from '@shared/format';

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

// What a limit reads as on cards and in lists ("" for none).
export function speedLabel(effectiveBps: number): string {
  return effectiveBps > 0 ? speed(effectiveBps) : '';
}

export function SpeedLimitField({ value, onChange, defaultBps }: { value: SpeedChoice; onChange: (next: SpeedChoice) => void; defaultBps: number }) {
  const fallback = defaultBps > 0 ? speed(defaultBps) : 'none';
  return (
    <div className="grid gap-2">
      <Field label="Speed limit" hint="download and upload alike, for all of this client's devices">
        <Segmented
          label="Speed limit"
          size="sm"
          className="justify-self-start"
          value={value.mode}
          onChange={mode => onChange({ ...value, mode })}
          options={[
            { value: 'default', label: `Server default (${fallback})` },
            { value: 'none', label: 'No limit' },
            { value: 'custom', label: 'Custom' },
          ]}
        />
      </Field>
      {value.mode === 'custom' && (
        <label className="flex items-center gap-2">
          <input
            className="field num w-32"
            type="number"
            min="0.001"
            max="1250"
            step="any"
            inputMode="decimal"
            aria-label="Speed limit in MB/s"
            value={value.mb}
            onChange={e => onChange({ ...value, mb: e.target.value })}
          />
          <span className="text-[13px] text-fg-2">MB/s</span>
        </label>
      )}
    </div>
  );
}
