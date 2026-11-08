// Which protocol a new client or key starts with, and what turning a protocol on asks of the
// firewall. No imports, so the tests run it directly (node --experimental-strip-types).

// A new server has only Shadowsocks (Outline-compatible) on. New clients and keys start with the
// preferred protocol (Shadowsocks) whenever it is on, else with the first protocol that is on;
// undefined when none is.
export function firstKeyProtocol<P extends string>(available: readonly P[], preferred: P): P | undefined {
  return available.includes(preferred) ? preferred : available[0];
}

// What each protocol listens on, at its own port. IKEv2 and IPsec use UDP 500 and 4500.
const TRANSPORTS: Record<string, string> = { shadowsocks: 'TCP and UDP', vless: 'TCP', wireguard: 'UDP', amneziawg: 'UDP' };

// The message after a protocol was turned on, with the port to allow: the firewall may not allow
// it yet, since a new server's installer lists only the ports of the protocols that are on. With
// no port (0: not reported) it names none.
export function turnedOn(name: string, protocol: string, port: number): string {
  const allow = "in this server's firewall and your cloud security group.";
  if (protocol === 'ikev2' || protocol === 'ipsec') return `${name} is on. Allow UDP 500 and 4500 ${allow}`;
  const transport = TRANSPORTS[protocol];
  return transport && port ? `${name} is on. Allow ${transport} ${port} ${allow}` : `${name} is on.`;
}
