// Traffic rules for everyone or for one client: blocked sites, addresses and ports, BitTorrent and
// outgoing mail. Saving replaces the rules.
import { useEffect, useState } from 'react';
import { lines } from '@shared/format';
import { Button, Check, Field, Note } from '@shared/glass';
import type { Rules } from './api';

export function RulesEditor({ rules, onSave, saveLabel = 'Save rules' }: { rules: Rules; onSave: (rules: Rules) => Promise<void>; saveLabel?: string }) {
  const [sites, setSites] = useState(rules.blocked_domains.join('\n'));
  const [ips, setIps] = useState(rules.blocked_ips.join('\n'));
  const [ports, setPorts] = useState(rules.blocked_ports.join('\n'));
  const [torrent, setTorrent] = useState(rules.block_bittorrent);
  const [smtp, setSmtp] = useState(rules.block_smtp);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // Follow the saved rules only when they change: a client's rules arrive as a new object with
  // every 15 s poll, which must not throw away what is being typed.
  const saved = JSON.stringify(rules);
  useEffect(() => {
    setSites(rules.blocked_domains.join('\n'));
    setIps(rules.blocked_ips.join('\n'));
    setPorts(rules.blocked_ports.join('\n'));
    setTorrent(rules.block_bittorrent);
    setSmtp(rules.block_smtp);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [saved]);
  return (
    <form
      className="grid grid-cols-1 gap-4"
      onSubmit={async event => {
        event.preventDefault();
        setBusy(true);
        setError('');
        try {
          await onSave({ blocked_domains: lines(sites), blocked_ips: lines(ips), blocked_ports: lines(ports), block_bittorrent: torrent, block_smtp: smtp });
        } catch (e) {
          setError((e as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="grid gap-4 md:grid-cols-3">
        <Field label="Blocked sites" hint="one per line, subdomains included">
          <textarea className="field min-h-[120px]" spellCheck={false} value={sites} onChange={e => setSites(e.target.value)} placeholder="example.com" />
        </Field>
        <Field label="Blocked addresses" hint="IP or CIDR">
          <textarea className="field min-h-[120px]" spellCheck={false} value={ips} onChange={e => setIps(e.target.value)} placeholder="203.0.113.0/24" />
        </Field>
        <Field label="Blocked ports" hint="25 or 6881-6889">
          <textarea className="field min-h-[120px]" spellCheck={false} value={ports} onChange={e => setPorts(e.target.value)} />
        </Field>
      </div>
      <div className="grid gap-x-8 md:grid-cols-2">
        <Check checked={torrent} onChange={setTorrent}>
          Block BitTorrent
        </Check>
        <Check checked={smtp} onChange={setSmtp}>
          Block outgoing mail (port 25)
        </Check>
      </div>
      <Note>Local networks, the server itself and cloud metadata addresses are always blocked for VPN users.</Note>
      {error && <Note tone="bad">{error}</Note>}
      <div className="flex justify-end">
        <Button type="submit" variant="cta" disabled={busy}>
          {saveLabel}
        </Button>
      </div>
    </form>
  );
}
