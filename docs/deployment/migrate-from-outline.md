# Move from Outline to Ghostlink

If an Outline server (Jigsaw's `shadowbox`) runs on a Linux machine, Ghostlink can take it over **on the same machine**:

- every Outline access key becomes a Ghostlink client;
- each key keeps its password, port and cipher, so the `ss://` keys people already have **keep working**, with nothing to re-send;
- Outline is stopped and stays off after a reboot, and its files are left as they were, as a backup.

After the move you manage everything with Ghostlink: the app, the dashboard or `sudo ghostlink-server`. You can also give the same people AmneziaWG, WireGuard, VLESS-REALITY or IKEv2 keys, speed limits and traffic rules.

## Check first

This installs Ghostlink next to Outline and only reports what the move would do. Outline keeps running and its clients notice nothing:

```sh
curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash -s -- --migrate-outline --check
```

On a server with under 1 GB of memory and swap, add `--add-swap`: Outline, Docker and the installation together need about 1 GB.

The report looks like this:

```text
Check only: nothing has changed yet. The import would do this:
  12 clients, one per Outline access key; 11 keep their Outline key as it is.
  Shadowsocks: port 41234 (cipher chacha20-ietf-poly1305), plus 9000 for keys on other ports.
  Server: My Outline, address in keys 203.0.113.7.
  VLESS moves off port 9000 to make way for Outline's (to a free port picked during the import).
  These clients get a new key, which you need to send them:
    Office: it uses port 443; Ghostlink cannot serve ports below 1024
```

It never shows a password.

## Move

```sh
curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash -s -- --migrate-outline
```

If Ghostlink is already installed, the same is done by `sudo ghostlink-server migrate-outline` (and `--check`). If Outline is not installed in `/opt/outline`, use `--outline-dir DIR`.

1. Ghostlink reads Outline's `persisted-state/shadowbox_config.json` (access keys) and `shadowbox_server_config.json` (name, address, default data limit). It makes private copies in its own state directory (mode 0600, owned by the server account) and checks them first. If the check fails (for example, the Ghostlink server already has clients), Outline is not touched.
2. Outline's containers (`shadowbox` and `watchtower`) get the restart policy `no` and are stopped, so their ports are free and they do not come back after a reboot.
3. The import runs as **one change**. If it fails (for example, another program holds one of Outline's ports) or is interrupted (Ctrl+C, a lost SSH session), nothing changes in Ghostlink and Outline is put back as it was: each container gets its old restart policy, and those that were running start again.
4. The copies are deleted. The installer then prints the management key and the ports to allow.

Outline's Shadowsocks ports are already open in your firewall and cloud security group, because Outline used them. Ghostlink's management API, VLESS, WireGuard and AmneziaWG ports are new: allow the ones the installer lists.

## What moves, and what doesn't

| Outline | Ghostlink |
|---|---|
| Access key (name, password, port, cipher) | A client with the same name and one Shadowsocks key with the same password, port and cipher. A key with no name becomes "Key ID"; repeated names get " (2)", " (3)" |
| The port most keys use | The server's Shadowsocks port. Keys on other ports keep theirs: each extra port gets its own Shadowsocks listener |
| Ciphers `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm` | Kept. On one port, the cipher most keys use is kept; a key with another cipher on that port gets a new key |
| A key's data limit, or the server's default data limit | The client's data limit. Outline's limit of 0 bytes (a paused key) becomes a client that is turned off |
| Server name and address (`hostname`) | The server's name and the address in keys, so new keys look like the old ones. The management key changes with the address. With the installer's `--hostname`, that address wins |
| Usage | Starts at 0. Outline counts the last 30 days, which Ghostlink cannot rebuild |
| Metrics settings, the Outline Manager connection | Not used. Outline Manager no longer reaches this server |

A client gets a **new** Shadowsocks key, listed in the report, when its Outline key:

- uses a port below 1024 (for example 443). The Ghostlink container runs without capabilities, so it cannot listen there;
- uses a port Ghostlink's management API, dashboard, mesh or IKEv2/IPsec DNS listener already uses;
- shares a port with keys that use another cipher, or uses a cipher Outline does not offer;
- has an empty or unusual password (more than 256 characters, or not plain text).

Show and send their new key with `sudo ghostlink-server keys NAME --show`, the app or the dashboard.

Two Outline keys with the same password on the same port cannot be told apart by any Shadowsocks server. Both keep working, but their traffic counts for the first one, and the report says so.

The import only runs on a Ghostlink server **with no clients yet**, and takes at most 500 keys (the most a server can hold).

## Go back to Outline

The move prints the rollback, with each container's old restart policy (Outline's default is `always`). It works as long as Outline's containers (`shadowbox`, `watchtower`) and its files are still there:

```sh
sudo ghostlink-server stop && sudo docker update --restart=always shadowbox watchtower && sudo docker start shadowbox watchtower
```

Ghostlink stays installed but stopped, and its clients and keys are kept. `sudo ghostlink-server setup` starts it again (after stopping Outline).

## Remove Outline for good

When everything works:

```sh
sudo docker rm -f shadowbox watchtower && sudo rm -rf /opt/outline
```

You can also remove Outline's images (`sudo docker image ls` shows them).

## Over the API

`POST /import/outline` on the [management API](ghostlink-server.md#management-api) takes Outline's two files as they are: `{"access_keys": <shadowbox_config.json>, "server": <shadowbox_server_config.json>, "dry_run": true}`. The body can be up to 4 MiB. The answer is the report: `dry_run`, `clients`, `kept`, `port`, `method`, `extra_ports`, `hostname`, `hostname_changed`, `name`, `new_keys` (client and reason), `moved` (service, from, to), `disabled` and `notes`. It contains no passwords. Inside the container, `ghostlink-server admin import-outline --dir DIR [--check]` posts the two files from a directory the server can read (under its state directory); `sudo ghostlink-server migrate-outline` does that for you.
