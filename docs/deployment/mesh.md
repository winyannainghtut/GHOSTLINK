# Ghostlink mesh: a private network between your Linux servers

The mesh connects your servers to each other privately, as an overlay network:

- every server you add (a **node**) gets its own private mesh address, by default in `100.96.0.0/16`;
- it reaches every other node at that address over WireGuard, whichever cloud, data centre or home network it is in;
- programs need no changes: they use the mesh address or the name `<node>.mesh`.

A Ghostlink server **coordinates** the mesh. It decides addresses, distributes keys and access rules, chooses paths, and collects what nodes report. The Ghostlink app and the server's web dashboard draw it as a live **map**.

> **Linux servers only for now.** Windows servers, and the Ghostlink app on Windows as a mesh node, will follow in a later release. The protocol between the coordinator and nodes is already OS-neutral for that.

This is a layer-3 network in the style of ZeroTier, Tailscale or Nebula. It is not a Kubernetes-style service mesh with sidecars. ZeroTier One was a design reference only: no ZeroTier code is used (see [Licensing](../security/licensing.md)).

## How it works

```
         Ghostlink server = coordinator (in its unprivileged container)
         ├─ the management API, the app and the dashboard: settings, nodes, invites, rules, map
         └─ the mesh API on its own TCP port (TLS 1.3, same certificate pin): join and sync for agents
                  ▲  HTTPS from each node (outbound only), long-poll: changes arrive in about a second
   ┌──────────────┼─────────────────┬─────────────────────┐
 node A (relay)  node B            node C (behind NAT)   node D (behind NAT)
 ghostlink-mesh  ghostlink-mesh    ghostlink-mesh        ghostlink-mesh
 glmesh0 (kernel WireGuard, UDP 51820)
   direct: A–B, A–C, A–D, B–C, B–D        C–D cannot connect directly → through the relay A
```

- **Agent:** each node runs the `ghostlink-mesh` agent, a static Go program with a hardened systemd service.
  - It creates the kernel WireGuard interface `glmesh0`, its peers and routes.
  - It sets up firewall chains (`GHOSTLINK-MESH-*`) and an `/etc/hosts` block with the `<node>.mesh` names.
    - The firewall goes in first, before the interface carries any traffic.
    - Its filter chains see only traffic on `glmesh0`. Its nat and mangle chains only masquerade mesh traffic to shared subnets, clamp TCP on `glmesh0`, and guard what arrives on `glmesh0`: two `mangle` chains apply the access rules to every packet a peer sends that is not a reply, before the filter table, so Docker's accept rules can't come first (since 0.8.5).
    - If a firewall reload removes the chains, the agent puts them back within about 30 seconds, and a connection opened from the mesh in the meantime that the rules don't allow ends then.
  - It reports handshakes, traffic and ping latency to the coordinator. The node's WireGuard private key **never leaves the node**.
- **Paths: direct first, then the relay.** Every pair of nodes connects directly when at least one of them can be reached. The coordinator decides every 5 seconds:
  - A pair with no handshake 90 seconds after both nodes are up goes **through the relay**. So does an established direct pair whose newest handshake is more than 3 minutes old.
  - A pair where neither node has an address for the other goes through the relay at once.
  - While a pair uses the relay, its two nodes keep trying each other directly. The pair goes back to direct as soon as that works.
  - Two nodes behind NAT are first tried at the public address each is seen from. That works only through 1:1 or port-preserving NAT; otherwise they use the relay. There is no deliberate NAT hole punching.
  - One relay is in use at a time: the first node (in join order) marked as a relay that is active and online, or else the first active relay node. Other relay nodes are on standby. Usually the relay is the coordinator's own host, joined with `mesh join-here` or `install-server.sh --mesh`.
- **Addresses the coordinator gives out:**
  - a node's own report of its addresses;
  - the address the coordinator sees it connect from, with its WireGuard port. That covers 1:1 NAT such as AWS EC2 and Lightsail public IPs.
  - Nodes behind the same public address (the same VPC, LAN or NAT) use each other's private addresses.

## Set up

### 1. The coordinator

On a server with Ghostlink server installed (see [Ghostlink server](ghostlink-server.md)), either install with the mesh:

```sh
curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash -s -- --mesh
```

or turn it on later and make the server a node too:

```sh
sudo ghostlink-server mesh enable         # prints the mesh network and the agents' TCP port
curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-mesh.sh | sudo bash   # the agent only
sudo ghostlink-server mesh join-here      # this host joins as the relay
```

In the Ghostlink app, turn it on with **Servers I run → Manage → Network**, then **Turn on mesh** on the **Mesh** card. The dashboard has the same Mesh card in its **Network** view.

Allow the coordinator's **mesh TCP port** (printed by `mesh enable`; `sudo ghostlink-server mesh` shows it again), and **UDP 51820** if this host is a node. Open them in the firewall and in your cloud security group.

### 2. Add a server

On the Mesh card, choose **Add node** and pick:
- **tags**, for access rules;
- how many servers the invite may add, and for how long (by default one server within 24 hours);
- whether the new node may be a relay (its command then ends with `--relay`, the server's consent to forwarding);
- whether it waits for your approval.

Copy the command it shows and run it on the new server:

```sh
curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-mesh.sh | sudo bash -s -- --join 'glmesh1:…'
```

The same invite from the server or the CLI:

```sh
sudo ghostlink-server mesh invite --tags web             # on the coordinator
ghostlink server mesh invite --server home --tags web    # from your computer (CLI)
```

[`scripts/install-mesh.sh`](../../scripts/install-mesh.sh) installs and joins in one go:
- it detects Debian/Ubuntu (.deb) or the Fedora/RHEL family (.rpm) on x86_64 or arm64;
- it checks the kernel has WireGuard;
- it installs the `ghostlink-mesh` package from the newest published release, verified against `SHA256SUMS.txt`;
- it joins with the invite, starts the service, and prints the node's mesh address.

Without `--join` it only installs or upgrades the agent. Running the join command again on a node upgrades the agent and leaves the node in its mesh.

Useful options:

| Option | Effect |
|---|---|
| `--name NAME` | Node name; the default is the machine's host name. |
| `--advertise-routes CIDR,…` | Offer subnets behind the server ([Subnets](#shared-subnets-site-to-site)). |
| `--relay` | Allow this server to relay for nodes behind NAT. |
| `--endpoint IP:PORT` | Its public address, when it can't be detected. |
| `--port N` | WireGuard UDP port (default 51820). |
| `--no-hosts` | Don't add `<node>.mesh` names to `/etc/hosts`. |
| `--open-firewall` | Allow the WireGuard port in an active ufw or firewalld. With firewalld it also puts the mesh interface in the `trusted` zone; otherwise firewalld refuses all mesh traffic but ping and SSH. The mesh's own access rules still apply. Upgrading the agent changes nothing in firewalld, and the coordinator's own node (`install-server.sh --mesh`, `mesh join-here`) gets neither this nor the hint: on such nodes, run the `firewall-cmd` commands under *Troubleshooting*. |
| `--package FILE` | Install a downloaded package instead. |

An invite is a secret until it is used: anyone holding it can add a server. It is stored on the coordinator only as a hash, and shown once.

While the join command runs, the invite also shows in that server's process list and in sudo's log. A single-use invite is used up by then; revoke one that works more than once when your servers have joined (`sudo ghostlink-server mesh revoke ID`). To keep the invite out of both, run the installer from a root shell with the invite in the environment:

```sh
sudo -i
read -rs GHOSTLINK_MESH_INVITE && export GHOSTLINK_MESH_INVITE   # paste the invite, then Enter
curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-mesh.sh | bash
```

### 3. Check it

```sh
sudo ghostlink-mesh status            # on a node: its address, its peers (direct or through the relay), latency
sudo ghostlink-server mesh            # on the coordinator: nodes and links
sudo ghostlink-server mesh map        # links: direct or through the relay, latency, traffic
ping db.mesh                          # from any node
```

## The map

When the mesh is on, the Mesh card shows a map of every node and every link: in the app under **Servers I run → Manage → Network**, and in the dashboard's **Network** view. It updates every 5 seconds.

- **Links:**
  - solid green: direct;
  - dashed amber: through the relay, drawn bending through it;
  - dotted red: down.
  - Thicker lines carry more traffic. Hovering shows latency, path and speed.
- **Nodes:** the relay in use has a dashed ring. A node sharing subnets is a rounded square, with its subnets beside it. Nodes waiting for approval, offline or disabled are drawn faded or dashed.
- **Selecting a node** opens its details:
  - address and name, state, the address it is reached at and seen from, agent version, last report and any problem;
  - its links with latency.
  - From there you can edit tags, share its subnets, make it a relay, and disable or remove it.
- **Dragging** a node moves it; the position is remembered on that device. **Rearrange the map** forgets the positions.
- **Waiting for approval** lists nodes that joined with an approval invite, with **Approve** and **Reject**.

## Access rules

With no rules, every node reaches every node. Once you add a rule, only traffic that matches a rule passes. Replies to allowed connections always pass, and so does ping, so the map can show latency; ping can be turned off in the mesh settings.

A rule is **from → to, protocol, ports**. *From* and *to* are each one of:
- `*`, every node;
- `tag:NAME`, nodes with that tag;
- `node:NAME`, one node.

The protocol is `tcp`, `udp`, `icmp` or `any`; tcp and udp rules can list ports such as `5432` or `8000-8100`.

```sh
sudo ghostlink-server mesh rules add --from tag:web --to tag:db --proto tcp --ports 5432
ghostlink server mesh rules --server home --rule "tag:web tag:db tcp 5432" --rule "tag:ops * any"
```

In the app and the dashboard, the editor is **Access rules** on the Mesh card.

Rules are enforced by the **receiving** node's firewall. The coordinator compiles them into the exact source addresses each node accepts, so a node needs no knowledge of tags.

- **Containers:** ports a node publishes for containers (Docker, Podman, Kubernetes NodePorts) are part of the node. Rules match the port the connection was made to. Docker puts its own accept rules ahead of the agent's `FORWARD` jump when it starts after the agent. Since 0.8.5 that opens nothing: the agent's guard in the `mangle` table checks every packet from the mesh before the `filter` table, where Docker's rules are. The agent also keeps its filter jumps first in Docker's `DOCKER-USER` chain (since 0.8.4). Software that accepts mesh traffic in the `mangle` table's `FORWARD` chain ahead of the guard would get around it; Docker, kube-proxy and Calico don't.
- **Shared subnets:** as a destination (*to*), a node's shared subnets count as part of that node, including its own address in them. As a source (*from*), only nodes' own mesh addresses match: once rules exist, connections that hosts in a shared subnet start are refused by the receiving node, and only replies pass.

## Shared subnets (site-to-site)

A node can make a private network behind it reachable from the mesh, for example an office LAN or a VPC subnet. This takes consent on both sides:

1. **On the node**, offer the subnet when joining, with `--advertise-routes 192.168.50.0/24`. This also allows the node to forward traffic.
2. **The administrator** shares it: tick the subnet in the node's details on the map, or run `sudo ghostlink-server mesh approve NAME --routes 192.168.50.0/24`.

The other nodes then route that subnet through this node, under the access rules. By default the node **masquerades** traffic into the subnet, so its hosts need no route back; `mesh node NAME --masquerade off` turns that off. A subnet that overlaps the mesh network or another node's subnet is refused.

A node never routes a shared subnet into the mesh where that would cut it off from a network it is on, replace a route it already has for that subnet, or send its own traffic to a peer around in a loop. Its status and the map name the subnets it leaves out.

A node only forwards traffic if its own operator allowed it, at join time with `--relay` or `--advertise-routes`. Without that, its agent installs no forwarding rules, even where IPv4 forwarding is already on (Docker hosts, for example). Making a node a relay or a subnet router later from the app therefore also needs, on that node:

```sh
sudo ghostlink-mesh allow-forwarding && sudo systemctl restart ghostlink-mesh
```

Until then its status shows the problem, and so does the map. Pairs that need the relay do not work while such a node is the relay in use.

## Ports

| Where | Port | For |
|---|---|---|
| Coordinator | mesh TCP port (picked when the mesh is turned on; see `sudo ghostlink-server mesh`) | Agents connecting out to join and sync. |
| Every node with a public address | UDP 51820 (or `--port`) inbound | WireGuard from other nodes. |
| Nodes behind NAT | nothing inbound | They connect out; two NAT nodes usually reach each other through the relay. |

VPN users of the Ghostlink server cannot reach the mesh port: it is refused like the management API.

## Commands

On the coordinator, `sudo ghostlink-server mesh …`:

| Command | Effect |
|---|---|
| `mesh` | Status, nodes and links. |
| `mesh enable [--cidr 100.96.0.0/16]` | Turn the mesh on. The network can be chosen until the first node joins. |
| `mesh disable` | Turn it off. Connected nodes take their links down within seconds; a node that is offline at that moment keeps its links until the mesh is on again or its agent restarts. Nothing is deleted. |
| `mesh invite [--tags web,db] [--uses 1] [--hours 24] [--relay] [--approval]` | Print the one-line join command. Up to 1000 uses and 90 days. |
| `mesh invites`, `mesh revoke ID` | List and revoke open invites. |
| `mesh nodes` | Nodes, addresses, tags and status. |
| `mesh approve NAME [--routes CIDR,…]` | Let a waiting node in and share its subnets. |
| `mesh node NAME [--name N] [--tags a,b] [--relay on\|off] [--masquerade on\|off] [--routes CIDR,…\|none] [--disable\|--enable]` | Change a node. |
| `mesh remove NAME` | Remove a node; its agent cleans up and stops. |
| `mesh rules`, `mesh rules add …`, `mesh rules remove N`, `mesh rules clear` | Access rules. |
| `mesh map` | Links: direct or relayed, latency, traffic. |
| `mesh join-here` | Make this host a node and the relay (needs the `ghostlink-mesh` package). |

From your computer, `ghostlink server mesh show|enable|disable|invite|invites|revoke|nodes|node|remove|rules --server NAME` does the same through the management key. `invite --output FILE` writes the join command to a new private file. AI agents with Ghostlink tokens cannot use any mesh command.

On a node, `sudo ghostlink-mesh …`:

| Command | Effect |
|---|---|
| `join` | Join, with the invite in `GHOSTLINK_MESH_INVITE` or on standard input. The installer does this. |
| `status [--json]` | This node and its peers: addresses, endpoint, handshake, latency and traffic. A node reached through the relay is listed as `(through the relay)`, and its address is among the relay peer's. |
| `allow-forwarding` | Consent to relaying and subnet sharing. |
| `leave` | Leave the mesh. The coordinator drops the node; the interface, firewall chains and `/etc/hosts` block are removed. IP forwarding is set back to what it was before the node first forwarded, unless Docker, libvirt or similar software on the machine may need it. |
| `version` | Print the version. |

The node's state is in `/var/lib/ghostlink-mesh`, readable only by root. Removing the package leaves the mesh, and purging it deletes the state.

## Security

- **Coordinator connection:** every agent connection is TLS 1.3, **pinned** to the coordinator's certificate. The pin is in the invite, so no certificate authority is trusted.
- **Credentials:**
  - an invite carries a 128-bit secret;
  - each node gets a 256-bit secret.
  - Both are stored as hashes, compared in constant time, and failed attempts are rate-limited.
  - A node's WireGuard private key is generated on the node and never sent anywhere.
- **The coordinator is trusted** to say which peers, addresses and rules a node uses: it is your Ghostlink server, and whoever holds its management key controls the mesh. Each agent still re-validates everything it receives:
  - keys, endpoints, names and protocols;
  - mesh addresses must be single addresses inside the mesh network; other ranges must be IPv4 subnets of /8 or narrower that don't overlap the mesh. The agent can't tell whether a subnet was approved;
  - peers' allowed addresses must not overlap or claim the node's own address;
  - nothing it receives reaches a shell.
- **A relay can read relayed traffic:** it decrypts and re-encrypts traffic between two nodes that use it. Use your own servers as relays. Direct pairs are end-to-end encrypted between the two nodes.
- **Access rules** are enforced by each receiving node's firewall, not by the coordinator. A compromised node can send anything, but other nodes accept only what the rules allow from its address.

See also the [security model](../security/model.md).

## Limits

- Linux servers only: Windows servers and Windows clients will come later.
- Kernel WireGuard is required (Linux 5.6 or newer, which covers all current server distributions). Container-based VPS types such as OpenVZ and LXC usually lack it; a userspace fallback is planned.
- IPv4 inside the mesh. Peers can be up to 250 per node, and each node can offer up to 16 subnets.
- No deliberate NAT hole punching: two nodes behind NAT connect directly only through 1:1 or port-preserving NAT, and otherwise use the relay.
- The coordinator keeps the paths in memory. After it restarts, pairs that need the relay can be cut off for up to about 90 seconds while it finds that out again.
- The map shows the live state, with no mesh traffic history.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `coordinator unreachable` in `ghostlink-mesh status` | The coordinator's mesh TCP port must be open in its firewall or security group. Existing links keep working meanwhile. |
| A link stays `down` or goes through the relay | Open UDP 51820 on at least one of the two nodes. With `--endpoint IP:51820`, a node can state its public address when the coordinator sees a different one. |
| `this kernel has no WireGuard support` | Use a KVM VPS or dedicated server with Linux 5.6+. |
| A relay or subnet does not work and the status asks for forwarding | Run `sudo ghostlink-mesh allow-forwarding && sudo systemctl restart ghostlink-mesh` on that node. |
| Ping and SSH work over the mesh, other ports don't (Fedora, RHEL, Rocky, Alma) | firewalld refuses mesh traffic until the mesh interface is trusted: `sudo firewall-cmd --permanent --zone=trusted --change-interface=glmesh0 && sudo firewall-cmd --reload`, or install with `--open-firewall`. |
| The status says `/etc/hosts` was replaced by another program | The agent sees the file through a bind mount that ends when a program replaces the file (`sed -i`, Ansible, some editors). Run `sudo systemctl restart ghostlink-mesh`. |
| Logs | `journalctl -u ghostlink-mesh` on a node; `sudo ghostlink-server logs` on the coordinator. |
