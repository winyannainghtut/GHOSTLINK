// Split tunneling for all servers, or for one server (which can follow the setting for all).
import { useEffect, useState } from 'react';
import { lines } from '@shared/format';
import { Button, Check, Field, Note, Segmented, Sheet, useUI } from '@shared/glass';
import { isActive, request, type Profile, type RoutingPolicy, type SplitMode } from '../ipc';
import { useService } from '../service';

export function splitSummary(policy: RoutingPolicy | null): string {
  const lan = policy?.lan_direct && policy.mode !== 'only' ? ' Local network stays direct.' : '';
  if (!policy || policy.mode === 'full') return 'Everything uses the VPN.' + lan;
  const count = policy.domains.length + policy.ip_ranges.length + policy.apps.length;
  const items = `${count} item${count === 1 ? '' : 's'}`;
  return (policy.mode === 'bypass' ? `${items} skip the VPN.` : `Only ${items} use the VPN.`) + lan;
}

// profile: undefined = closed, null = all servers, a profile = that server.
export function SplitSheet({ profile, onClose, onSaved }: { profile: Profile | null | undefined; onClose: () => void; onSaved?: () => void }) {
  const { info } = useService();
  const { toast } = useUI();
  const [follow, setFollow] = useState(false);
  const [mode, setMode] = useState<SplitMode>('full');
  const [sites, setSites] = useState('');
  const [ips, setIps] = useState('');
  const [apps, setApps] = useState('');
  const [lan, setLan] = useState(false);
  const [error, setError] = useState('');
  const open = profile !== undefined;

  useEffect(() => {
    if (!open) return;
    setError('');
    request<{ policy: RoutingPolicy | null; follows_global?: boolean }>(profile ? { type: 'routing_policy_get', profile: profile.name } : { type: 'routing_policy_get' })
      .then(data => {
        const p = data.policy ?? { mode: 'full', domains: [], ip_ranges: [], apps: [], lan_direct: false };
        setFollow(!!profile && !!data.follows_global);
        setMode(p.mode);
        setSites(p.domains.join('\n'));
        setIps(p.ip_ranges.join('\n'));
        setApps(p.apps.join('\n'));
        setLan(p.lan_direct);
      })
      .catch(e => setError(e.message));
  }, [open, profile]);

  const save = async () => {
    const policy = profile && follow ? null : { mode, domains: lines(sites), ip_ranges: lines(ips), apps: lines(apps), lan_direct: lan };
    try {
      await request({ type: 'routing_policy_set', policy, ...(profile ? { profile: profile.name } : {}) });
      toast(isActive(info?.connection.status) ? 'Split tunneling saved. Disconnect and connect again to apply it.' : 'Split tunneling saved. It applies the next time you connect.');
      onSaved?.();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const editing = !(profile && follow);
  return (
    <Sheet
      open={open}
      onClose={onClose}
      size="medium"
      title="Split tunneling"
      subtitle={profile ? `For ${profile.display_name || profile.name}` : 'For all servers'}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="cta" onClick={save}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid gap-5">
        {profile && (
          <Check checked={follow} onChange={setFollow}>
            Use the settings for all servers
          </Check>
        )}
        {editing && (
          <>
            <Segmented
              label="Mode"
              value={mode}
              onChange={setMode}
              options={[
                { value: 'full', label: 'Everything uses the VPN' },
                { value: 'bypass', label: 'Listed items skip it' },
                { value: 'only', label: 'Only listed items use it' },
              ]}
            />
            {mode !== 'full' && (
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Sites" hint="subdomains included">
                  <textarea className="field min-h-[120px]" spellCheck={false} value={sites} onChange={e => setSites(e.target.value)} placeholder="example.com" />
                </Field>
                <Field label="IP ranges">
                  <textarea className="field min-h-[120px]" spellCheck={false} value={ips} onChange={e => setIps(e.target.value)} placeholder="192.168.1.0/24" />
                </Field>
                <Field label="Apps" hint="executable name or path">
                  <textarea className="field min-h-[120px]" spellCheck={false} value={apps} onChange={e => setApps(e.target.value)} placeholder="chrome.exe" />
                </Field>
              </div>
            )}
            {mode !== 'only' && (
              <Check checked={lan} onChange={setLan}>
                Keep local network devices off the VPN
              </Check>
            )}
            <Note>Sites are matched by name, so a few apps that hide it can still use the VPN. Changes apply the next time you connect.</Note>
          </>
        )}
        {error && <Note tone="bad">{error}</Note>}
      </div>
    </Sheet>
  );
}
