# Self-host an Outline-compatible server

This path uses a standard Shadowsocks AEAD server, compatible with supported Outline access keys. It is independent from the optional OpenVPN/CA deployment. It does not require changing the server's default routes, forwarding or NAT. No host or cloud firewall is flushed.

Generate identities offline on your administration machine:

```text
python server/outline/provision.py --directory PRIVATE_DIRECTORY init
python server/outline/provision.py --directory PRIVATE_DIRECTORY add --name laptop --endpoint vpn.example.com --port 443 --display-name Singapore
python server/outline/provision.py --directory PRIVATE_DIRECTORY add --name phone --endpoint vpn.example.com --port 444 --display-name Singapore-Phone
python server/outline/provision.py --directory PRIVATE_DIRECTORY list
```

Each identity gets a different random credential and listener port. The tool writes a private `.access-key` file and `config.json`; standard output contains metadata only. Transfer a particular access-key file privately to its intended client. Import it through MyVPN's GUI or `myvpn key add --name ID --file FILE`. Keep the authoritative provisioning state and any backup encrypted and private.

Allow TCP **and UDP** on each selected port in your existing server firewall/cloud security group, while retaining restricted SSH administration. Deploy `server/outline/deploy.yml` to a chosen x64 Linux host using an inventory group `outline_vpn` and `-e myvpn_outline_config=/private/path/config.json`. The playbook downloads/checksums pinned sing-box 1.14.4 and runs it under an unprivileged account with only the low-port binding capability. It does not deploy the offline state or client export files.

Removing a key from the offline configuration does not change a live server until deployed:

```text
python server/outline/provision.py --directory PRIVATE_DIRECTORY remove --name phone
```

Deploy the updated config and restart the proxy to revoke the listener and existing sessions. Use a new identity/port for renewal/rotation, distribute its new key, verify the client, then remove/deploy the old identity. The tool retains the old local export file as operator-owned backup; remove it intentionally after rotation. Static Outline keys do not use the OpenVPN CA or certificate expiry system.

Server health: `systemctl status myvpn-proxy`, validate the private config with the pinned engine, and run an authorized client traffic test. Restore a private configuration backup and restart the service to roll back; a rollback can re-enable revoked credentials, so review identities first. Apply normal host security updates and rebuild/update the pinned engine with fresh compatibility tests.

Current verification covers local generation, config validation and local encrypted traffic fixtures. The Ansible/systemd deployment has not run against a Linux VPS in this environment. The supplied AWS draft originally targets OpenVPN UDP 1194; change its ingress explicitly for the Outline listener ports before planning a new instance. No cloud resource creation is authorized or performed automatically by these examples.
