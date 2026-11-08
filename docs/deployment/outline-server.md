# Self-host an Outline-compatible server

> This is the earlier, offline server path. For a new server, use the [Ghostlink server](ghostlink-server.md): you manage it from the app, the CLI or a dashboard, and it has more protocols, traffic rules, usage, data and speed limits, and monitoring. To move an existing Outline server, see [Move from Outline](migrate-from-outline.md). This path has none of that: it is a plain proxy with static keys, for x64 Linux only.

This path uses a standard Shadowsocks AEAD server, compatible with supported Outline access keys. It is independent from the optional OpenVPN/CA deployment. It does not require changing the server's default routes, forwarding or NAT. No host or cloud firewall is flushed.

Like the Ghostlink server, the proxy refuses destinations on the host and its networks: loopback, private and CGNAT ranges, link-local addresses including cloud metadata, multicast, and the server's own address when a key gives it as an IP. Names are resolved on the server first, so a name that points inside is refused as well. A `config.json` made by an earlier version has none of these blocks: run `render` and deploy the result.

Generate identities offline on your administration machine:

```text
python server/outline/provision.py --directory PRIVATE_DIRECTORY init
python server/outline/provision.py --directory PRIVATE_DIRECTORY add --name laptop --endpoint vpn.example.com --port 443 --display-name Singapore
python server/outline/provision.py --directory PRIVATE_DIRECTORY add --name phone --endpoint vpn.example.com --port 444 --display-name Singapore-Phone
python server/outline/provision.py --directory PRIVATE_DIRECTORY list
```

Each identity gets a different random credential and listener port. The proxy listens on IPv4 and IPv6 (`init --listen ::`, the default); on a host without IPv6, run `init --listen 0.0.0.0`. A state made by an earlier version listens on IPv4 only, and `add` refuses an IPv6 endpoint there. The tool writes a private `.access-key` file and `config.json`; standard output contains metadata only. Transfer a particular access-key file privately to its intended client. Import it through Ghostlink's GUI or `ghostlink key add --name ID --file FILE`. Keep the authoritative provisioning state and any backup encrypted and private.

Allow TCP **and UDP** on each selected port in your existing server firewall/cloud security group, while retaining restricted SSH administration. Deploy `server/outline/deploy.yml` to a chosen x64 Linux host using an inventory group `outline_vpn` and `-e ghostlink_outline_config=/private/path/config.json`. The playbook downloads/checksums pinned sing-box 1.14.4 and runs it under an unprivileged account with only the low-port binding capability. It does not deploy the offline state or client export files.

Removing a key from the offline configuration does not change a live server until deployed:

```text
python server/outline/provision.py --directory PRIVATE_DIRECTORY remove --name phone
```

Deploy the updated config and restart the proxy to revoke the listener and existing sessions. Use a new identity/port for renewal/rotation, distribute its new key, verify the client, then remove/deploy the old identity. The tool retains the old local export file as operator-owned backup; remove it intentionally after rotation. Until then, `add` refuses that name again. Static Outline keys do not use the OpenVPN CA or certificate expiry system.

Server health: `systemctl status ghostlink-proxy`, validate the private config with the pinned engine, and run an authorized client traffic test. Restore a private configuration backup and restart the service to roll back; a rollback can re-enable revoked credentials, so review identities first. Apply normal host security updates and rebuild/update the pinned engine with fresh compatibility tests.

Current verification covers local generation, config validation, local encrypted traffic fixtures, and a local run of the generated proxy that checks it refuses a loopback-only service, by address and by name. The Ansible/systemd deployment has not run against a Linux VPS in this environment. The supplied AWS draft originally targets OpenVPN UDP 1194; change its ingress explicitly for the Outline listener ports before planning a new instance. No cloud resource creation is authorized or performed automatically by these examples.
