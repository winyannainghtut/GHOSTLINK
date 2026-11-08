import { Activity, ArrowDown, ArrowUp, Clock, Gauge, Network as NetworkIcon, UserPlus } from 'lucide-react';
import { useMemo, useState, type ReactNode } from 'react';
import { AreaChart, type RatePoint } from '@shared/AreaChart';
import { fillBuckets } from '@shared/BarChart';
import { Bars } from '@shared/Bars';
import { byteRate, bytes, duration, plural, speed } from '@shared/format';
import { Button, Card, CardTitle, Facts, Meter, Note, Segmented, cx } from '@shared/glass';
import { usePoll } from '@shared/hooks';
import { api, protocolName, type Stats } from '../api';
import { useStore } from '../store';

// The day and week totals change as traffic is recorded: fetch them again while the page is open.
const STATS_MS = 60_000;

type Range = 'live' | 'hour' | 'day';

function Kpi({ label, icon, children, detail }: { label: string; icon: ReactNode; children: ReactNode; detail?: ReactNode }) {
  return (
    <Card className="flex min-h-[156px] flex-col justify-between">
      <div className="flex items-center justify-between text-[13px] text-fg-2">
        <span>{label}</span>
        <span className="text-fg-3">{icon}</span>
      </div>
      <div className="mt-4">{children}</div>
      {detail && <div className="mt-2 text-[12.5px] text-fg-3">{detail}</div>}
    </Card>
  );
}

function BigNumber({ value, unit }: { value: ReactNode; unit?: string }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="num text-[38px] leading-none font-semibold tracking-[-0.035em]">{value}</span>
      {unit && <span className="text-[14px] text-fg-2">{unit}</span>}
    </div>
  );
}

export function Overview({ onNewClient }: { onNewClient: () => void }) {
  const { server, users, live, stale } = useStore();
  const [range, setRange] = useState<Range>('live');
  const [day, setDay] = useState<Stats | null>(null);
  const [week, setWeek] = useState<Stats | null>(null);

  usePoll(async () => {
    const [d, w] = await Promise.all([api<Stats>('GET', '/stats?range=24h'), api<Stats>('GET', '/stats?range=7d')]);
    setDay(d);
    setWeek(w);
  }, STATS_MS);

  const total = byteRate((live?.down_bps ?? 0) + (live?.up_bps ?? 0));
  const health = live?.health;
  const pools = server.address_pools ?? [];
  const used = pools.reduce((n, p) => n + p.used, 0), capacity = pools.reduce((n, p) => n + p.capacity, 0);

  const points: RatePoint[] = useMemo(() => {
    if (range === 'live') return (live?.series ?? []).slice(-60).map(s => ({ t: s.t, down: s.down, up: s.up }));
    if (range === 'hour') return (live?.minutes ?? []).map(s => ({ t: s.t, down: s.down, up: s.up }));
    // The current hour is still filling up: average it over the time gone so far, not a full hour.
    const now = Date.now() / 1000;
    return fillBuckets((day?.series ?? []).map(s => ({ t: s.t, down: s.down, up: s.up })), 3600, 24, now).map(s => {
      const seconds = Math.min(3600, Math.max(60, now - s.t));
      return { t: s.t, down: s.down / seconds, up: s.up / seconds };
    });
  }, [range, live, day]);

  const timeLabel = (t: number) => {
    if (range === 'live') {
      const s = Math.round((live?.time_unix ?? t) - t);
      return s <= 1 ? 'Now' : `${s} s ago`;
    }
    return new Date(t * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="grid gap-4">
      {stale && (
        <Card className="border-bad/40">
          <Note tone="bad">The server is not answering, so live data is paused. It continues when the server answers again.</Note>
        </Card>
      )}
      {health?.detail_paused && (
        <Card className="border-idle/40">
          <Note tone="warn">The disk is nearly full, so detailed traffic recording is paused until space is freed. Live data and totals continue.</Note>
        </Card>
      )}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Active tunnels" icon={<Activity size={17} />} detail={<span className="num">{`of ${plural(users.length, 'client')}${live ? ` · ${plural(live.active, 'open connection')}` : ''}`}</span>}>
          <BigNumber value={live?.online_users ?? '—'} unit="online" />
        </Kpi>
        <Kpi
          label="Live throughput"
          icon={<Gauge size={17} />}
          detail={
            live && (
              <span className="num flex gap-3">
                <span className="text-down">↓ {speed(live.down_bps)}</span>
                <span className="text-up">↑ {speed(live.up_bps)}</span>
              </span>
            )
          }
        >
          <BigNumber value={live ? total.value : '—'} unit={live ? total.unit : undefined} />
        </Kpi>
        <Kpi
          label="Server uptime"
          icon={<Clock size={17} />}
          detail={
            health && (
              <span className="num">
                {health.cpu_percent !== undefined && `CPU ${health.cpu_percent.toFixed(0)} %`}
                {health.memory_total_bytes ? ` · Memory ${bytes(health.memory_used_bytes ?? 0)} of ${bytes(health.memory_total_bytes)}` : ''}
              </span>
            )
          }
        >
          <BigNumber value={health ? duration(health.uptime_seconds) : '—'} />
        </Kpi>
        <Kpi
          label="Address pool"
          icon={<NetworkIcon size={17} />}
          detail={
            <span className="flex flex-wrap gap-x-3">
              {pools.map(p => (
                <span key={p.protocol}>
                  {protocolName(p.protocol)} <span className="mono">{p.cidr}</span>
                </span>
              ))}
            </span>
          }
        >
          <div className="flex items-baseline justify-between">
            <BigNumber value={used} unit={`of ${capacity.toLocaleString()} used`} />
            <span className="num text-[13px] text-fg-2">{capacity ? ((used / capacity) * 100).toFixed(capacity > 2000 ? 2 : 1) : 0} %</span>
          </div>
          <Meter className="mt-3" fraction={capacity ? used / capacity : 0} tone="ok" />
        </Kpi>
      </div>

      <Card>
        <CardTitle
          title="Throughput"
          detail={range === 'live' ? 'Every second, all clients together' : range === 'hour' ? 'Average per minute, last hour' : 'Average per hour, last 24 hours'}
          action={
            <Segmented
              size="sm"
              label="Range"
              value={range}
              onChange={setRange}
              options={[
                { value: 'live', label: 'Live 60 s' },
                { value: 'hour', label: '1 h' },
                { value: 'day', label: '24 h' },
              ]}
            />
          }
        />
        <div className="mb-3 flex flex-wrap gap-2">
          <Legend tone="down" icon={<ArrowDown size={13} />} label="Download" value={live ? speed(live.down_bps) : '—'} />
          <Legend tone="up" icon={<ArrowUp size={13} />} label="Upload" value={live ? speed(live.up_bps) : '—'} />
        </div>
        <AreaChart
          points={points}
          timeLabel={timeLabel}
          empty={stale && range !== 'day' ? 'Waiting for the server to answer' : range === 'live' ? 'No traffic in the last minute' : 'No traffic in this period'}
        />
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardTitle title="Server health" detail={`${server.name} · version ${server.version}`} />
          {health ? (
            <Facts
              rows={[
                ['Uptime', <span className="num">{duration(health.uptime_seconds)}</span>],
                ...(health.cpu_percent !== undefined ? [['CPU', <span className="num">{health.cpu_percent.toFixed(0)} %{health.load_1m !== undefined ? ` · load ${health.load_1m.toFixed(2)}` : ''}</span>] as [string, ReactNode]] : []),
                ...(health.memory_total_bytes ? [['Memory', <span className="num">{bytes(health.memory_used_bytes ?? 0)} of {bytes(health.memory_total_bytes)}</span>] as [string, ReactNode]] : []),
                ...(health.disk_total_bytes ? [['Disk free', <span className="num">{bytes(health.disk_free_bytes ?? 0)} of {bytes(health.disk_total_bytes)}</span>] as [string, ReactNode]] : []),
                ...(health.network_rx_bps !== undefined ? [['Host network', <span className="num">↓ {speed(health.network_rx_bps)} · ↑ {speed(health.network_tx_bps ?? 0)}</span>] as [string, ReactNode]] : []),
                ['History file', <span className="num">{bytes(health.history_bytes)}</span>],
                ['Engine restarts', <span className="num">{health.engine_reloads}</span>],
              ]}
            />
          ) : (
            <Note>Waiting for the first reading…</Note>
          )}
        </Card>
        <Card>
          <CardTitle title="Today by client" detail="Last 24 hours" />
          {users.length ? (
            <Bars items={(day?.users ?? []).filter(u => u.up + u.down > 0).map(u => ({ label: u.name, bytes: u.up + u.down }))} empty="No traffic in the last 24 hours." />
          ) : (
            <div className="grid place-items-center gap-3 py-6 text-center">
              <p className="text-[13px] text-fg-3">No clients yet.</p>
              <Button variant="cta" size="sm" icon={<UserPlus size={15} />} onClick={onNewClient}>
                New client
              </Button>
            </div>
          )}
        </Card>
        <Card>
          <CardTitle title="Traffic types" detail="Last 7 days" />
          <Bars items={week?.types} empty="Nothing recorded yet." />
        </Card>
        <Card>
          <CardTitle title="Protocols used" detail="Last 7 days" />
          <Bars items={week?.protocols} empty="Nothing recorded yet." label={protocolName} />
        </Card>
        <Card className="lg:col-span-2">
          <CardTitle title="Top services" detail="Last 7 days, totals per service" />
          <Bars items={week?.sites} empty={week && !week.site_stats ? 'Top services are off. Turn them on in Server settings.' : 'No services recorded yet.'} />
        </Card>
      </div>
    </div>
  );
}

function Legend({ tone, icon, label, value }: { tone: 'down' | 'up'; icon: ReactNode; label: string; value: string }) {
  return (
    <span className="inset-glass inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-[12.5px]">
      <span className={cx('inline-flex size-5 items-center justify-center rounded-full', tone === 'down' ? 'bg-down/20 text-down' : 'bg-up/20 text-up')}>{icon}</span>
      <span className="text-fg-2">{label}</span>
      <span className="num text-fg">{value}</span>
    </span>
  );
}
