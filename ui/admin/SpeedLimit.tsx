// A client's speed limit, entered in megabytes per second (bytes, like every speed shown): the
// server's default, no limit, or a cap of its own. One cap covers download and upload alike, across all of the
// client's keys and devices.
import { Segmented } from '@shared/glass';
import { speed } from '@shared/format';
import type { SpeedChoice } from './limits';

export { speedChange, speedChoice, speedValue, type SpeedChoice, type SpeedMode } from './limits';

// What a limit reads as on cards and in lists ("" for none).
export function speedLabel(effectiveBps: number): string {
  return effectiveBps > 0 ? speed(effectiveBps) : '';
}

export function SpeedLimitField({ value, onChange, defaultBps }: { value: SpeedChoice; onChange: (next: SpeedChoice) => void; defaultBps: number }) {
  const fallback = defaultBps > 0 ? speed(defaultBps) : 'none';
  return (
    <div className="grid gap-2">
      {/* Not a Field: its <label> would pass a click on the caption to the first choice, Server default. */}
      <div className="grid gap-1.5">
        <span className="text-[12.5px] font-medium text-fg-2">
          Speed limit<span className="font-normal text-fg-3"> · download and upload alike, for all of this client's devices</span>
        </span>
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
      </div>
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
