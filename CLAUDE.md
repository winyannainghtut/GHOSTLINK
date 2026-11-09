# Ghostlink

A VPN client (Windows and Linux: a privileged Rust service, a CLI, an MCP bridge and a Tauri/React app) and a self-hosted server (Go, in Docker), with a mesh agent and an IKEv2/IPsec component. **The full guide is [agent.md](agent.md): read its *Start here* before changing anything**; its numbered sections are the reference. [CHANGELOG.md](CHANGELOG.md) says what each version changed, and [docs/development/verification.md](docs/development/verification.md) records what was actually tested.

## Map

- **Rust workspace** (`Cargo.toml`):
  - `services/vpn-daemon`: `ghostlinkd`, the privileged service;
  - `cli/ghostlink`: the CLI;
  - `integrations/mcp-server`: the MCP bridge;
  - `core/vpn-engine`: profiles, credentials, worker sessions;
  - `packages/shared-contracts`: IPC types.
- **`apps/desktop/src-tauri`:** the desktop app, a separate Rust workspace.
- **`ui/`:** the React UI of the dashboard and the desktop app; `ui/admin` holds the shared server views. Its build output is committed.
- **`core/outline-worker`:** one Go module:
  - the tunnel worker (`.`);
  - the server (`cmd/ghostlink-server`, `internal/server`);
  - the mesh agent (`cmd/ghostlink-mesh`, `internal/meshagent`);
  - the IPsec agent (`internal/ipsecagent`);
  - shared iptables handling (`internal/hostfw`).
- **Elsewhere:**
  - `packages/linux/`: packages, and the server's host script `server/ghostlink-server.sh`;
  - `scripts/`: installers, builds, `cargo.ps1`;
  - `tests/`: the process suite, and the mesh and IPsec end-to-end tests.

## Commands

On the Windows development machine, in Git Bash:

- **Rust:** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/cargo.ps1 <fmt|clippy|test|build> --locked --workspace`. For the desktop app, add `--manifest-path apps/desktop/src-tauri/Cargo.toml`. CI runs `clippy -- -D warnings`, and the lint table requires a `// SAFETY:` comment on every `unsafe` block.
- **Go:** `cd core/outline-worker && go test -tags with_gvisor,with_utls,with_wireguard ./...`. Without the tags, the gVisor and uTLS tests fail.
  - Debug server: `go build -tags with_gvisor,with_utls,with_wireguard -o ../../target/debug/ghostlink-server.exe ./cmd/ghostlink-server`.
  - Worker: the same build with `-o ../../target/debug/ghostlink-tunnel.exe .`.
- **UI:** `cd ui && npm run build && npm test`. Then commit `core/outline-worker/internal/server/dashboard` and `apps/desktop/ui`, and rebuild the Go server, which embeds the dashboard.
- **Process suite:** root `npm test`, after fresh debug builds, with `GHOSTLINK_TEST_SERVER=<absolute path of ghostlink-server.exe>`.
- **Linux-only tests** run in CI only: Docker, iptables, the mesh and IPsec end-to-end tests, and the packages.
- **`gh` on Windows** may not be on the PATH; use `"/c/Program Files/GitHub CLI/gh.exe"`.

## Rules

The full list is in agent.md, *Rules for contributors and AI agents*.

- **Docs:** update the docs, the README and the CHANGELOG in the same change as the code.
- **Releases:**
  1. Work on a branch and open a PR.
  2. Wait for CI, and run a dry run with `gh workflow run release.yml --ref <branch>`.
  3. Squash-merge.
  4. Push an annotated tag `vX.Y.Z` on the merge commit; the release workflow makes a draft.
  5. Publish only when the maintainer asks, and never edit published notes.
- **Secrets:**
  - never paste or use access keys, management keys or tokens;
  - scan staged files before committing;
  - test fixtures use TEST-NET addresses;
  - real server IPs stay out of the repo.
- **Test environment:**
  - local test servers only, and no cloud resources;
  - don't touch the installed Ghostlink app or service: give development runs their own `--endpoint` / `GHOSTLINK_ENDPOINT` and data directory;
  - don't start Docker Desktop;
  - never bypass UAC.
- **GUI checks:** only through WebView2 DevTools, with an isolated `WEBVIEW2_USER_DATA_FOLDER`. No real mouse clicks, and never a browser profile that could sign in to an account.
- **Agents and MCP:** AI agents and the MCP bridge get no import, policy or server-admin powers. This is a product rule.
- **Units:** every speed is in bytes per second (B/s, KB/s, MB/s), never bits.
- **Clean-up:** delete only your own test artifacts, by exact path, and restore any setting you change. Don't send the code to third-party code-reading services, such as the zread MCP tools.

## Claude Code setup (`.claude/`)

- **Hooks** (`.claude/settings.json`):
  - before any `git commit`, `hooks/staged-secrets.mjs` blocks private keys, management keys, and `ss://`/`vless://` keys with a public IP in what could be committed, and redacts what it reports;
  - after editing a `.go` or `.rs` file, `hooks/format-check.mjs` reports what `gofmt` or `rustfmt` would change.
- **`/release X.Y.Z`** (`.claude/skills/release`): the release flow, step by step, with the checks of the draft. It never publishes unless asked.

## Gotchas

- **Multi-line edits:** use the Edit tool or a script written to a file. Heredocs, `node -e` and multi-line `sed` inserts have broken files.
- **Version bumps** touch eight files and both lockfiles; the list is in agent.md, *Version bump*. Check with `node scripts/release-version.mjs`.
- **Real-engine Rust tests** (`--ignored`) need absolute `GHOSTLINK_TEST_SING_BOX` and `GHOSTLINK_TEST_OUTLINE_WORKER` paths. With relative ones, they fail or pass without testing anything.
- **Changes to how the VPN behaves** (routes, the cleanup barrier, firewalls) need tests through the real service or worker, not only unit tests, and a check that each new test fails on the old behaviour.
- **Subagents** see this file but not agent.md. Restate the agent.md rules a task needs in their prompts.
