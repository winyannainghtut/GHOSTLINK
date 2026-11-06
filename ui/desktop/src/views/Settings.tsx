// Settings: everyday preferences, appearance, diagnostics and about.
import { Activity, Info as InfoIcon } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { FinishPicker, type Appearance } from '@shared/appearance';
import { Button, Card, Note, Segmented, Sheet, Switch, useUI } from '@shared/glass';
import { request, type RoutingPolicy } from '../ipc';
import { useService } from '../service';
import { VERSION } from '../version';
import { SplitSheet, splitSummary } from './SplitSheet';

function Row({ title, detail, children }: { title: string; detail: string; children: ReactNode }) {
  return (
    <Card className="flex flex-wrap items-center justify-between gap-4">
      <div className="min-w-0 max-w-2xl">
        <h2 className="text-[15px]">{title}</h2>
        <p className="mt-1 text-[13px] text-fg-3">{detail}</p>
      </div>
      <div className="flex items-center gap-2">{children}</div>
    </Card>
  );
}

export function Settings({ appearance }: { appearance: Appearance }) {
  const { info, act, available } = useService();
  const { toast } = useUI();
  const [summary, setSummary] = useState('');
  const [split, setSplit] = useState<null | undefined>(undefined);
  const [doctor, setDoctor] = useState<string | null>(null);
  const [about, setAbout] = useState(false);
  const loadSummary = () =>
    request<{ policy: RoutingPolicy | null }>({ type: 'routing_policy_get' })
      .then(d => setSummary(splitSummary(d.policy)))
      .catch(() => {});
  useEffect(() => void loadSummary(), []);

  return (
    <div className="grid max-w-[1000px] gap-4">
      <div className="px-1">
        <h1 className="text-[26px] tracking-[-0.03em]">Settings</h1>
        <p className="text-[13.5px] text-fg-2">A few preferences for your everyday connection.</p>
      </div>
      <Row title="Connect when the service starts" detail="Use your default server whenever the Ghostlink service starts.">
        <Switch checked={!!info?.autoconnect} disabled={!available} onChange={on => act({ type: 'autoconnect', enabled: on }, on ? 'Ghostlink connects when the service starts.' : 'Automatic connection is off.')} label="Connect when the service starts" />
      </Row>
      <Row title="Split tunneling" detail={summary || 'Everything uses the VPN.'}>
        <Button onClick={() => setSplit(null)}>Edit</Button>
      </Row>
      <Row title="Finish" detail="Obsidian, Titanium or Daylight.">
        <FinishPicker value={appearance.finish} onChange={appearance.setFinish} />
      </Row>
      <Row title="Background motion" detail="The glass waves drift slowly behind the app. Still stops them; your system's reduced-motion setting does too.">
        <Segmented
          size="sm"
          label="Background motion"
          value={appearance.motion}
          onChange={appearance.setMotion}
          options={[
            { value: 'subtle', label: 'Subtle' },
            { value: 'calm', label: 'Calm' },
            { value: 'still', label: 'Still' },
          ]}
        />
      </Row>
      <Row title="Diagnostics" detail="What the local service reports about engines, permissions and the last connection.">
        <Button
          icon={<Activity size={15} />}
          onClick={async () => {
            try {
              setDoctor(JSON.stringify(await request({ type: 'doctor' }), null, 2));
            } catch (e) {
              toast((e as Error).message, 'bad');
            }
          }}
        >
          Run diagnostics
        </Button>
      </Row>
      <Row title="About Ghostlink" detail={`Personal VPN · version ${info?.version ?? VERSION}`}>
        <Button icon={<InfoIcon size={15} />} onClick={() => setAbout(true)}>
          About
        </Button>
      </Row>
      <Note>Ghostlink uses your own server or one shared with you. An access key does not include a subscription or create a server. Connecting needs the installed Ghostlink service.</Note>

      <SplitSheet profile={split} onClose={() => setSplit(undefined)} onSaved={loadSummary} />
      <Sheet open={doctor !== null} onClose={() => setDoctor(null)} size="medium" title="Connection diagnostics" footer={<Button variant="cta" onClick={() => setDoctor(null)}>Done</Button>}>
        <pre className="inset-glass mono max-h-[60vh] overflow-auto rounded-[20px] p-4 text-[12px] leading-relaxed whitespace-pre-wrap text-fg-2">{doctor}</pre>
      </Sheet>
      <Sheet open={about} onClose={() => setAbout(false)} title="Private by choice" subtitle={`Ghostlink ${info?.version ?? VERSION}`} footer={<Button variant="cta" onClick={() => setAbout(false)}>Done</Button>}>
        <div className="grid gap-3 text-[13.5px] text-fg-2">
          <p>Ghostlink is an independent personal VPN for keys from Outline, Amnezia and VLESS servers, and for WireGuard and AmneziaWG files, plus your own Ghostlink servers.</p>
          <p>Keys are kept by the local service, never in this window. Closing the app leaves the service running; disconnect to stop your connection.</p>
          <p className="text-fg-3">Open source: MIT for the app and service, GPL-3.0-or-later for the tunnel worker and server.</p>
        </div>
      </Sheet>
    </div>
  );
}
