// The provider (AS and operator) of an address a client connected from, as shown beside it.
// The server fills in `asn` and `operator` only when its provider lookup is on and the address
// belongs to someone (a private address does not).
import type { Client, ProviderLookup } from './api';

// "AS64496 · Example Telecom", just "AS64496" when the operator's name is not known, or '' for an
// address with no provider.
export function providerText(client?: Pick<Client, 'asn' | 'operator'>): string {
  if (!client?.asn) return '';
  return client.operator ? `AS${client.asn} · ${client.operator}` : `AS${client.asn}`;
}

// What the settings say about the lookup: whether its list is ready, being downloaded, or failed.
export function lookupState(lookup: ProviderLookup | undefined, now: number): string {
  if (!lookup?.enabled) return '';
  if (lookup.updating && !lookup.ready) return 'Downloading the list…';
  if (!lookup.ready) return lookup.error ? `The list could not be downloaded: ${lookup.error}` : 'Waiting for the list…';
  const days = lookup.updated_unix ? Math.max(0, Math.floor((now - lookup.updated_unix) / 86400)) : 0;
  const age = days < 1 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`;
  const base = `${lookup.ranges.toLocaleString('en-US')} address ranges from ${lookup.source}, downloaded ${age}.`;
  return lookup.error ? `${base} The last update failed: ${lookup.error}` : base;
}
