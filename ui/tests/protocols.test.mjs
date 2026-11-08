// The protocol new clients and keys start with, and the firewall hint after turning one on
// (admin/protocols.ts). Run: node --experimental-strip-types --test tests/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { firstKeyProtocol, turnedOn } from '../admin/protocols.ts';

test('new clients and keys start with Shadowsocks whenever it is on', () => {
  // A new server: only Shadowsocks is on.
  assert.equal(firstKeyProtocol(['shadowsocks'], 'shadowsocks'), 'shadowsocks');
  // A server set up before, which kept every protocol on: Shadowsocks too, no longer AmneziaWG.
  assert.equal(firstKeyProtocol(['amneziawg', 'wireguard', 'vless', 'shadowsocks', 'ikev2', 'ipsec'], 'shadowsocks'), 'shadowsocks');
  // Shadowsocks turned off: the first protocol that is on.
  assert.equal(firstKeyProtocol(['amneziawg', 'vless'], 'shadowsocks'), 'amneziawg');
  assert.equal(firstKeyProtocol(['ikev2'], 'shadowsocks'), 'ikev2');
  // Nothing is on: nothing to start with.
  assert.equal(firstKeyProtocol([], 'shadowsocks'), undefined);
});

test('turning a protocol on names the port to allow', () => {
  const allow = "in this server's firewall and your cloud security group.";
  assert.equal(turnedOn('AmneziaWG', 'amneziawg', 20254), `AmneziaWG is on. Allow UDP 20254 ${allow}`);
  assert.equal(turnedOn('WireGuard', 'wireguard', 11234), `WireGuard is on. Allow UDP 11234 ${allow}`);
  assert.equal(turnedOn('VLESS-REALITY', 'vless', 24466), `VLESS-REALITY is on. Allow TCP 24466 ${allow}`);
  assert.equal(turnedOn('Shadowsocks', 'shadowsocks', 12742), `Shadowsocks is on. Allow TCP and UDP 12742 ${allow}`);
  // IKEv2 and IPsec always use UDP 500 and 4500, whatever port the server reports.
  assert.equal(turnedOn('IKEv2', 'ikev2', 500), `IKEv2 is on. Allow UDP 500 and 4500 ${allow}`);
  assert.equal(turnedOn('IPsec', 'ipsec', 0), `IPsec is on. Allow UDP 500 and 4500 ${allow}`);
  // No port reported, or a protocol this version does not know: no port to name.
  assert.equal(turnedOn('WireGuard', 'wireguard', 0), 'WireGuard is on.');
  assert.equal(turnedOn('Hysteria', 'hysteria', 443), 'Hysteria is on.');
});
