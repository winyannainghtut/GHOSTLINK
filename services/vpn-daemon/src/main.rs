mod ipc;
mod remote;
#[cfg(windows)]
mod service;

use anyhow::{Context, Result};
use clap::Parser;
use fs2::FileExt;
use ghostlink_contracts::{
    Action, ConnectionState, Request, Response, RoutingPolicy, SCHEMA_VERSION,
};
use ghostlink_engine::{
    access,
    management::{self, Session, Shared},
    profile::{self, ProfileSummary},
    split, storage, worker_session,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, Mutex};

#[derive(Parser, Clone)]
#[command(
    version,
    about = "Ghostlink local service. Install under a dedicated privileged identity for real tunnels."
)]
pub struct Args {
    #[arg(long, env = "GHOSTLINK_ENDPOINT", default_value_t = ghostlink_contracts::default_endpoint())]
    endpoint: String,
    #[arg(long, default_value_os_t = default_data_dir())]
    data_dir: PathBuf,
    /// Absolute path configured by the administrator; never accepted over IPC.
    #[arg(long, default_value_os_t = default_engine())]
    openvpn: PathBuf,
    #[arg(long = "outline-engine", alias = "sing-box", default_value_os_t = default_outline_engine())]
    sing_box: PathBuf,
    #[arg(long)]
    owner_sid: Option<String>,
    #[arg(long)]
    owner_uid: Option<u32>,
    #[arg(long, default_value = "wintun", value_parser = ["wintun", "tap-windows6", "ovpn-dco"])]
    windows_driver: String,
    /// Linux full tunnel requires an administrator's explicit route-change authorization.
    #[arg(long)]
    allow_full_tunnel: bool,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=600))]
    connection_timeout_seconds: u64,
    /// SCM entrypoint; installation must configure all other arguments explicitly.
    #[arg(long)]
    service: bool,
}

fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()))
            .join("Ghostlink")
    } else {
        "/var/lib/ghostlink".into()
    }
}
fn default_engine() -> PathBuf {
    if cfg!(windows) {
        r"C:\Program Files\OpenVPN\bin\openvpn.exe".into()
    } else {
        "/usr/sbin/openvpn".into()
    }
}
fn default_outline_engine() -> PathBuf {
    if cfg!(windows) {
        r"C:\Program Files\Ghostlink\engine\ghostlink-tunnel.exe".into()
    } else {
        "/usr/local/lib/ghostlink/ghostlink-tunnel".into()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredProfile {
    summary: ProfileSummary,
    sealed_content: Vec<u8>,
    /// Per-server split tunneling; `None` follows the global policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    routing_override: Option<RoutingPolicy>,
}
/// A Ghostlink server this device administers. The management key (URL with its secret path
/// and the certificate pin) is sealed; only the address is kept in the clear.
#[derive(Clone, Serialize, Deserialize)]
struct ManagedServer {
    sealed_key: Vec<u8>,
    host: String,
    port: u16,
    server_name: String,
    #[serde(default)]
    version: String,
    added_unix: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Agent {
    hash: String,
    control: bool,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    profiles: BTreeMap<String, StoredProfile>,
    default_profile: Option<String>,
    autoconnect: bool,
    agents: BTreeMap<String, Agent>,
    /// Per-installation secret mixed into access-key fingerprints. Never returned over IPC.
    #[serde(default)]
    fingerprint_salt: Option<String>,
    #[serde(default)]
    routing_policy: RoutingPolicy,
    #[serde(default)]
    managed_servers: BTreeMap<String, ManagedServer>,
}
#[derive(Serialize, Deserialize)]
struct Audit {
    timestamp_unix: u64,
    actor: String,
    operation: String,
    outcome: String,
}

/// Append-only audit file with its own lock, independent of the daemon state mutex, so engine
/// events can be recorded while a long connect or switch holds the daemon.
struct AuditLog {
    dir: PathBuf,
    lock: std::sync::Mutex<()>,
}
impl AuditLog {
    fn record(&self, actor: &str, operation: &str, outcome: &str) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = self.dir.join("audit.jsonl");
        if fs::metadata(&path)
            .map(|m| m.len() > 1024 * 1024)
            .unwrap_or(false)
        {
            let previous = self.dir.join("audit.previous.jsonl");
            if previous.exists() {
                fs::remove_file(&previous)?;
            }
            fs::rename(&path, previous)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        let entry = Audit {
            timestamp_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            actor: actor.into(),
            operation: operation.into(),
            outcome: outcome.into(),
        };
        serde_json::to_writer(&mut file, &entry)?;
        writeln!(file)?;
        file.sync_data()?;
        Ok(())
    }
}

/// Keyed with the installation salt so the fingerprint shown to read-only agents cannot be used
/// to test guesses of a weak access-key password offline.
fn fingerprint(salt: &str, source: &str) -> String {
    hex::encode(
        Sha256::new()
            .chain_update(b"ghostlink-access-key-fingerprint-v1\0")
            .chain_update(salt.as_bytes())
            .chain_update(source.as_bytes())
            .finalize(),
    )
}

/// Files that exist only while a request or tunnel is in flight. Startup holds the exclusive
/// daemon lock, so any that remain were left by a crash: an uncommitted transaction (the
/// committed state.json is intact) or a plaintext engine configuration. Removing a link
/// removes the link itself, never its target.
fn remove_stale_runtime_files(data_dir: &Path) -> bool {
    let mut removed = fs::remove_file(data_dir.join("state.pending")).is_ok();
    let run = data_dir.join("run");
    for name in [
        "outline.json",
        "outline.pending",
        "active.conf",
        "active.pending",
        "management.auth",
        "management.pending",
        "engine.sock",
    ] {
        removed |= fs::remove_file(run.join(name)).is_ok();
    }
    removed
}

struct Daemon {
    args: Args,
    store: Store,
    state: Shared,
    session: Option<Session>,
    events: mpsc::Sender<&'static str>,
    audit_log: Arc<AuditLog>,
    /// One pinned client per managed server, reused across calls (live polling).
    admin_clients: std::sync::Mutex<
        std::collections::HashMap<String, (String, ghostlink_engine::server_admin::AdminClient)>,
    >,
}
impl Daemon {
    fn commit(&mut self, next: Store) -> Result<()> {
        storage::atomic_write(
            &self.args.data_dir.join("state.json"),
            &serde_json::to_vec(&next)?,
        )?;
        self.store = next;
        Ok(())
    }
    fn audit(&self, actor: &str, operation: &str, outcome: &str) -> Result<()> {
        self.audit_log.record(actor, operation, outcome)
    }
    fn authorize(&self, request: &Request) -> Result<String, Response> {
        if request.schema_version != SCHEMA_VERSION {
            return Err(Response::err(
                "invalid_request",
                "Unsupported schema version",
            ));
        }
        match &request.agent_token {
            None => Ok("os_owner".into()),
            Some(token) => {
                if token.len() != 64 {
                    return Err(Response::err(
                        "permission_denied",
                        "Invalid agent authorization",
                    ));
                }
                let digest = hex::encode(Sha256::digest(token.as_bytes()));
                for (name, agent) in &self.store.agents {
                    if bool::from(digest.as_bytes().ct_eq(agent.hash.as_bytes())) {
                        if !request.action.agent_allowed(agent.control) {
                            return Err(Response::err(
                                "permission_denied",
                                "Agent capability does not permit this operation",
                            ));
                        }
                        return Ok(format!("agent:{name}"));
                    }
                }
                Err(Response::err(
                    "permission_denied",
                    "Unknown or revoked agent authorization",
                ))
            }
        }
    }
    async fn handle(&mut self, request: Request) -> Response {
        let operation = request.action.name();
        let actor = match self.authorize(&request) {
            Ok(actor) => actor,
            Err(response) => {
                let _ = self.audit("unauthorized", operation, "denied");
                return response;
            }
        };
        // Refuse operations if the authorization audit cannot be durably recorded.
        if self.audit(&actor, operation, "accepted").is_err() {
            return Response::err("internal", "Audit storage is unavailable");
        }
        let response = match self.dispatch(request.action).await {
            Ok(response) => response,
            Err(_) => Response::err("internal", "Service storage or engine operation failed; run doctor and inspect the service installation"),
        };
        let outcome = response
            .error
            .as_ref()
            .map(|e| e.code.as_str())
            .unwrap_or("success");
        let _ = self.audit(&actor, operation, outcome);
        response
    }
    async fn disconnect(&mut self) {
        // Keep ownership until teardown completes: if this request is cancelled (for example
        // at service shutdown), the next disconnect still waits for the same engine cleanup.
        if let Some(session) = self.session.as_mut() {
            session.stop().await;
        }
        self.session = None;
    }
    async fn cleanup_failure(&self) -> Option<Response> {
        let state = self.state.read().await;
        matches!(state.status.last_error.as_deref(), Some("forced_stop_network_cleanup_unverified" | "network_cleanup_unverified"))
            .then(|| Response::err("cleanup_unverified", "Network cleanup could not be verified; inspect routing and DNS before another connection"))
    }
    async fn connect(&mut self, name: Option<String>, switching: bool) -> Result<Response> {
        let name = match name.or_else(|| self.store.default_profile.clone()) {
            Some(name) => name,
            None => {
                return Ok(Response::err(
                    "not_found",
                    "No default VPN profile is configured",
                ))
            }
        };
        let stored = match self.store.profiles.get(&name) {
            Some(p) => p,
            None => return Ok(Response::err("not_found", "VPN profile does not exist")),
        };
        let clear = storage::unseal(&stored.sealed_content)?;
        let content = String::from_utf8(clear)?;
        // Every kind except OpenVPN runs in the managed tunnel worker.
        if stored.summary.kind != "openvpn" {
            if !worker_session::worker_available(&self.args.sing_box).await {
                return Ok(Response::err(
                    "engine_unavailable",
                    "Install the pinned managed Ghostlink tunnel worker in the service installation",
                ));
            }
            // A server's own override wins over the global split-tunnel policy.
            let policy = stored
                .routing_override
                .clone()
                .unwrap_or_else(|| self.store.routing_policy.clone());
            let outbound = match access::resolve(&content).await {
                Ok(resolved) => resolved.outbound,
                Err(_) => return Ok(Response::err("invalid_profile", "The saved key is invalid, unsupported or its dynamic configuration is unavailable")),
            };
            #[cfg(unix)]
            if outbound.full_tunnel() && !self.args.allow_full_tunnel {
                return Ok(Response::err("permission_denied", "Full tunnel requires the administrator to authorize route changes with --allow-full-tunnel after protecting SSH access"));
            }
            if let Some(session) = &self.session {
                if !session.finished() {
                    let status = self.state.read().await.status();
                    if status.profile.as_deref() == Some(&name) && !switching {
                        return Ok(Response::ok(status));
                    }
                    if !switching {
                        return Ok(Response::err(
                            "busy",
                            "Another server is active; use switch",
                        ));
                    }
                }
            }
            self.disconnect().await;
            if let Some(error) = self.cleanup_failure().await {
                return Ok(error);
            }
            self.session = Some(
                worker_session::start(
                    &self.args.sing_box,
                    &self.args.data_dir.join("run"),
                    name,
                    outbound,
                    policy,
                    // Management APIs of servers administered here stay outside the tunnel.
                    self.store
                        .managed_servers
                        .values()
                        .map(|m| (m.host.clone(), m.port))
                        .collect(),
                    self.state.clone(),
                    self.events.clone(),
                    Duration::from_secs(self.args.connection_timeout_seconds),
                )
                .await?,
            );
            return Ok(Response::ok(self.state.read().await.status()));
        }
        let profile = match profile::validate(&name, &content) {
            Ok(p) => p,
            Err(_) => {
                return Ok(Response::err(
                    "invalid_profile",
                    "Stored profile is invalid or its certificate is expired or not yet valid",
                ))
            }
        };
        #[cfg(unix)]
        if profile.summary.tunnel_mode == "full" && !self.args.allow_full_tunnel {
            return Ok(Response::err("permission_denied", "Full tunnel is disabled by service policy; the administrator must authorize route changes with --allow-full-tunnel after protecting SSH access"));
        }
        if !self.args.openvpn.is_absolute() || !self.args.openvpn.is_file() {
            return Ok(Response::err("engine_unavailable", "Install OpenVPN Community and configure the service with its absolute executable path"));
        }
        if let Some(session) = &self.session {
            if !session.finished() {
                let status = self.state.read().await.status();
                if status.profile.as_deref() == Some(&name) && !switching {
                    return Ok(Response::ok(status));
                }
                if !switching {
                    return Ok(Response::err(
                        "busy",
                        "Another profile is active; use switch",
                    ));
                }
            }
        }
        self.disconnect().await;
        if let Some(error) = self.cleanup_failure().await {
            return Ok(error);
        }
        let session = management::start(
            &self.args.openvpn,
            &self.args.data_dir.join("run"),
            profile,
            self.state.clone(),
            &self.args.windows_driver,
            self.events.clone(),
            Duration::from_secs(self.args.connection_timeout_seconds),
        )
        .await?;
        self.session = Some(session);
        Ok(Response::ok(self.state.read().await.status()))
    }
    /// Imports any credential the managed worker uses: `ss://`, `ssconf://`, `vless://`,
    /// `vpn://` or WireGuard/AmneziaWG configuration text.
    async fn import_credential(
        &mut self,
        name: String,
        source: String,
        replace: bool,
    ) -> Result<Response> {
        if !profile::valid_name(&name) {
            return Ok(Response::err(
                "invalid_request",
                "Server ID must contain 1-64 letters, digits, hyphens or underscores",
            ));
        }
        if !replace && self.store.profiles.contains_key(&name) {
            return Ok(Response::err(
                "invalid_request",
                "A server with this ID already exists; choose another ID or explicitly replace it",
            ));
        }
        if self.store.profiles.len() >= 32 && !self.store.profiles.contains_key(&name) {
            return Ok(Response::err(
                "invalid_request",
                "At most 32 servers may be saved",
            ));
        }
        if self.session.as_ref().is_some_and(|s| !s.finished())
            && self.state.read().await.status.profile.as_deref() == Some(&name)
        {
            return Ok(Response::err(
                "busy",
                "Disconnect before replacing the active access key",
            ));
        }
        let source = source.trim();
        let resolved = match access::resolve(source).await {
            Ok(resolved) => resolved,
            Err(e) => return Ok(Response::err("invalid_profile", &e.to_string())),
        };
        let mut next = self.store.clone();
        let salt = next
            .fingerprint_salt
            .get_or_insert_with(|| {
                let mut random = [0u8; 32];
                OsRng.fill_bytes(&mut random);
                hex::encode(random)
            })
            .clone();
        let summary = resolved
            .outbound
            .summary(&name, fingerprint(&salt, source), resolved.label);
        next.profiles.insert(
            name.clone(),
            StoredProfile {
                summary: summary.clone(),
                sealed_content: storage::seal(source.as_bytes())?,
                routing_override: self
                    .store
                    .profiles
                    .get(&name)
                    .and_then(|p| p.routing_override.clone()),
            },
        );
        if next.default_profile.is_none() {
            next.default_profile = Some(name);
        }
        self.commit(next)?;
        Ok(Response::ok(summary))
    }
    async fn dispatch(&mut self, action: Action) -> Result<Response> {
        match action {
            Action::AccessKeyImport {
                name,
                access_key,
                replace,
            } => self.import_credential(name, access_key, replace).await,
            Action::ProfileRename { name, display_name } => {
                if !ghostlink_engine::outline::valid_label(&display_name) {
                    return Ok(Response::err(
                        "invalid_request",
                        "Server name must contain 1-80 characters",
                    ));
                }
                let mut next = self.store.clone();
                let stored = match next.profiles.get_mut(&name) {
                    Some(stored) => stored,
                    None => return Ok(Response::err("not_found", "Server does not exist")),
                };
                stored.summary.display_name = display_name.trim().into();
                let summary = stored.summary.clone();
                self.commit(next)?;
                Ok(Response::ok(summary))
            }
            Action::ProfileImport {
                name,
                content,
                replace,
            } => {
                // WireGuard/AmneziaWG files run in the managed worker like access keys.
                if access::handles(&content) {
                    return self.import_credential(name, content, replace).await;
                }
                let profile = match profile::validate(&name, &content) {
                    Ok(p) => p,
                    Err(e) => return Ok(Response::err("invalid_profile", &e.to_string())),
                };
                if !replace && self.store.profiles.contains_key(&name) {
                    return Ok(Response::err(
                        "invalid_request",
                        "A profile with this name already exists; choose another name or explicitly replace it",
                    ));
                }
                if self.store.profiles.len() >= 32 && !self.store.profiles.contains_key(&name) {
                    return Ok(Response::err(
                        "invalid_request",
                        "At most 32 profiles may be stored",
                    ));
                }
                if self.session.as_ref().is_some_and(|s| !s.finished())
                    && self.state.read().await.status.profile.as_deref() == Some(&name)
                {
                    return Ok(Response::err(
                        "busy",
                        "Disconnect before replacing the active profile",
                    ));
                }
                let summary = profile.summary;
                let mut next = self.store.clone();
                // Preserve validated source for revalidation at every connect. Internal canonical
                // directives are deliberately not accepted as user-supplied profile options.
                next.profiles.insert(
                    name.clone(),
                    StoredProfile {
                        summary: summary.clone(),
                        sealed_content: storage::seal(content.as_bytes())?,
                        routing_override: self
                            .store
                            .profiles
                            .get(&name)
                            .and_then(|p| p.routing_override.clone()),
                    },
                );
                if next.default_profile.is_none() {
                    next.default_profile = Some(name);
                }
                self.commit(next)?;
                Ok(Response::ok(summary))
            }
            Action::ProfileList {} | Action::ServersList {} => {
                let profiles: Vec<_> = self
                    .store
                    .profiles
                    .values()
                    .map(|p| {
                        let mut summary = p.summary.clone();
                        summary.is_default =
                            self.store.default_profile.as_deref() == Some(&summary.name);
                        summary
                    })
                    .collect();
                Ok(Response::ok(json!({"profiles": profiles})))
            }
            Action::ProfileDefault { name } => {
                if !self.store.profiles.contains_key(&name) {
                    return Ok(Response::err("not_found", "VPN profile does not exist"));
                }
                let mut next = self.store.clone();
                next.default_profile = Some(name.clone());
                self.commit(next)?;
                Ok(Response::ok(json!({"default_profile": name})))
            }
            Action::ProfileRemove { name } => {
                if self.session.as_ref().is_some_and(|s| !s.finished())
                    && self.state.read().await.status.profile.as_deref() == Some(&name)
                {
                    return Ok(Response::err(
                        "busy",
                        "Disconnect before removing the active profile",
                    ));
                }
                let mut next = self.store.clone();
                if next.profiles.remove(&name).is_none() {
                    return Ok(Response::err("not_found", "VPN profile does not exist"));
                }
                if next.default_profile.as_deref() == Some(&name) {
                    next.default_profile = None;
                    next.autoconnect = false;
                }
                self.commit(next)?;
                Ok(Response::ok(json!({"removed": name})))
            }
            Action::Connect { profile } => self.connect(profile, false).await,
            Action::Switch { profile } => self.connect(Some(profile), true).await,
            Action::Disconnect {} => {
                self.disconnect().await;
                if let Some(error) = self.cleanup_failure().await {
                    return Ok(error);
                }
                // A failed connection has no active worker after stop; retain the failure for diagnostics.
                if self.state.read().await.status.status == ConnectionState::Failed {
                    let mut snapshot = self.state.write().await;
                    snapshot.status.status = ConnectionState::Disconnected;
                }
                Ok(Response::ok(self.state.read().await.status()))
            }
            Action::Status {} => Ok(Response::ok(self.state.read().await.status())),
            Action::Info {} => Ok(Response::ok(
                json!({"connection": self.state.read().await.status(), "autoconnect": self.store.autoconnect, "default_profile": self.store.default_profile, "engines": ["outline-compatible-shadowsocks", "openvpn2-management"], "version": env!("CARGO_PKG_VERSION")}),
            )),
            Action::Autoconnect { enabled } => {
                if enabled && self.store.default_profile.is_none() {
                    return Ok(Response::err(
                        "not_found",
                        "Choose a default profile before enabling autoconnect",
                    ));
                }
                let mut next = self.store.clone();
                next.autoconnect = enabled;
                self.commit(next)?;
                Ok(Response::ok(
                    json!({"autoconnect": enabled, "trigger": "daemon_start"}),
                ))
            }
            Action::Logs { tail } => {
                if tail > 1000 {
                    return Ok(Response::err(
                        "invalid_request",
                        "tail must be at most 1000",
                    ));
                }
                let text =
                    fs::read_to_string(self.args.data_dir.join("audit.jsonl")).unwrap_or_default();
                let lines: Vec<serde_json::Value> = text
                    .lines()
                    .rev()
                    .take(tail)
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
                Ok(Response::ok(
                    json!({"entries": lines.into_iter().rev().collect::<Vec<_>>()}),
                ))
            }
            Action::Doctor {} => {
                let outline_available = worker_session::worker_available(&self.args.sing_box).await;
                let engine_available =
                    self.args.openvpn.is_absolute() && self.args.openvpn.is_file();
                let version = if engine_available {
                    let mut command = tokio::process::Command::new(&self.args.openvpn);
                    command.arg("--version").kill_on_drop(true);
                    #[cfg(windows)]
                    command.creation_flags(0x08000000);
                    match tokio::time::timeout(Duration::from_secs(5), command.output()).await {
                        Ok(Ok(output)) if output.status.success() => {
                            String::from_utf8_lossy(&output.stdout)
                                .lines()
                                .next()
                                .filter(|s| s.starts_with("OpenVPN "))
                                .map(String::from)
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                Ok(Response::ok(
                    json!({"engine_available": outline_available || version.is_some(), "outline_engine_available": outline_available, "openvpn_engine_version": version, "ipc": "os_user_restricted", "profile_count": self.store.profiles.len(), "connection": self.state.read().await.status(), "checks": {"routed_traffic": "not_tested", "dns_leaks": "not_tested", "ipv6_leaks": "not_tested", "kill_switch": "unsupported"}, "limitations": ["No persistent kill switch or independently verified leak-prevention guarantee", "OpenVPN backend Linux DNS integration is not yet implemented", "OpenVPN certificate-only inline profiles; password and encrypted-key profiles are unsupported", "Autoconnect runs at daemon startup; disconnect is respected until restart", "Outline supports standard AEAD ss:// and legacy JSON dynamic ssconf:// keys; advanced YAML/prefix/plugin keys are unsupported"]}),
                ))
            }
            Action::AgentGrant { name, control } => {
                if !profile::valid_name(&name) {
                    return Ok(Response::err("invalid_request", "Invalid agent name"));
                }
                if self.store.agents.len() >= 32 && !self.store.agents.contains_key(&name) {
                    return Ok(Response::err(
                        "invalid_request",
                        "At most 32 agent grants are allowed",
                    ));
                }
                let mut random = [0u8; 32];
                OsRng.fill_bytes(&mut random);
                let token = hex::encode(random);
                let mut next = self.store.clone();
                next.agents.insert(
                    name.clone(),
                    Agent {
                        hash: hex::encode(Sha256::digest(token.as_bytes())),
                        control,
                    },
                );
                self.commit(next)?;
                // The CLI writes this one-time issuance to a private file and removes it from output.
                Ok(Response::ok(
                    json!({"name": name, "control": control, "issued_token": token}),
                ))
            }
            Action::AgentRevoke { name } => {
                let mut next = self.store.clone();
                next.agents.remove(&name);
                self.commit(next)?;
                Ok(Response::ok(json!({"revoked": name})))
            }
            Action::RoutingPolicyGet { profile } => match profile {
                None => Ok(Response::ok(
                    json!({"scope": "global", "policy": self.store.routing_policy}),
                )),
                Some(name) => match self.store.profiles.get(&name) {
                    None => Ok(Response::err("not_found", "VPN profile does not exist")),
                    Some(stored) => Ok(Response::ok(json!({
                        "scope": "profile",
                        "profile": name,
                        "policy": stored.routing_override,
                        "follows_global": stored.routing_override.is_none(),
                        "applies": stored.summary.kind != "openvpn",
                    }))),
                },
            },
            Action::RoutingPolicySet { profile, policy } => {
                let policy = match policy.as_ref().map(split::validate).transpose() {
                    Ok(policy) => policy,
                    Err(e) => return Ok(Response::err("invalid_request", &e.to_string())),
                };
                let mut next = self.store.clone();
                match &profile {
                    None => next.routing_policy = policy.clone().unwrap_or_default(),
                    Some(name) => match next.profiles.get_mut(name) {
                        None => {
                            return Ok(Response::err("not_found", "VPN profile does not exist"))
                        }
                        Some(stored) => stored.routing_override = policy.clone(),
                    },
                }
                self.commit(next)?;
                Ok(Response::ok(json!({
                    "scope": if profile.is_some() { "profile" } else { "global" },
                    "policy": policy,
                    "applies": "next_connection",
                })))
            }
            Action::ManagedServerList {} => {
                let servers: Vec<_> = self
                    .store
                    .managed_servers
                    .iter()
                    .map(|(name, managed)| managed.summary(name))
                    .collect();
                Ok(Response::ok(json!({"servers": servers})))
            }
            Action::ManagedServerRemove { name } => {
                let mut next = self.store.clone();
                if next.managed_servers.remove(&name).is_none() {
                    return Ok(Response::err("not_found", "No managed server has this ID"));
                }
                if let Ok(mut clients) = self.admin_clients.lock() {
                    clients.remove(&name);
                }
                self.commit(next)?;
                // Only this device forgets the server; the server and its users are untouched.
                Ok(Response::ok(json!({"removed": name})))
            }
            // Served by remote::handle without holding the service lock.
            Action::ManagedServerAdd { .. } | Action::ServerCall { .. } => Ok(Response::err(
                "internal",
                "Server administration is handled separately",
            )),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    #[cfg(windows)]
    if args.service {
        return service::dispatch();
    }
    #[cfg(unix)]
    if args.service {
        anyhow::bail!("Use the supplied systemd unit on Linux");
    }
    run(args, async { shutdown_signal().await }, || Ok(())).await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    }
    #[cfg(windows)]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn run(
    args: Args,
    shutdown: impl std::future::Future<Output = ()>,
    ready: impl FnOnce() -> Result<()>,
) -> Result<()> {
    anyhow::ensure!(
        args.data_dir.is_absolute(),
        "Data directory must be absolute"
    );
    storage::private_dir(&args.data_dir)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(args.data_dir.join("daemon.lock"))?;
    lock.try_lock_exclusive()
        .context("Another daemon owns this data directory")?;
    let removed_stale_files = remove_stale_runtime_files(&args.data_dir);
    let state_path = args.data_dir.join("state.json");
    let store = if state_path.exists() {
        anyhow::ensure!(
            fs::metadata(&state_path)?.len() <= 64 * 1024 * 1024,
            "State exceeds supported size"
        );
        serde_json::from_slice(&fs::read(state_path)?)
            .context("State is corrupt; refusing to overwrite it")?
    } else {
        Store::default()
    };
    let state = Arc::new(tokio::sync::RwLock::new(management::Snapshot::default()));
    let (events, mut event_rx) = mpsc::channel(128);
    let audit_log = Arc::new(AuditLog {
        dir: args.data_dir.clone(),
        lock: std::sync::Mutex::new(()),
    });
    let daemon = Arc::new(Mutex::new(Daemon {
        args: args.clone(),
        store,
        state,
        session: None,
        events,
        audit_log: audit_log.clone(),
        admin_clients: Default::default(),
    }));
    let mut listener = ipc::Listener::bind(&args).await?;
    {
        let mut daemon = daemon.lock().await;
        daemon.audit("service", "startup", "success")?;
        if removed_stale_files {
            daemon.audit("service", "stale_runtime_cleanup", "removed")?;
        }
        ready()?;
        if daemon.store.autoconnect {
            // Never let a failed automatic connection take the service down: the user needs
            // the service running to see the failure and to disable autoconnect.
            let outcome = match daemon.connect(None, false).await {
                Ok(response) if response.success => "accepted",
                Ok(_) => "failed",
                Err(_) => {
                    let mut snapshot = daemon.state.write().await;
                    snapshot.status.status = ConnectionState::Failed;
                    snapshot.status.last_error = Some("autoconnect_failed".into());
                    "error"
                }
            };
            let _ = daemon.audit("service", "autoconnect", outcome);
        }
    }
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    let mut clients = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            // Must not wait for the daemon mutex: that would stall accepting and shutdown
            // for as long as a connect or switch holds it.
            Some(event) = event_rx.recv() => { let _ = audit_log.record("engine", "event", event); }
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
            accepted = listener.accept() => {
                let stream = accepted?;
                let permit = match permits.clone().try_acquire_owned() { Ok(p) => p, Err(_) => { drop(stream); continue; } };
                let daemon = daemon.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    let mut reader = tokio::io::BufReader::new(stream);
                    let request = tokio::time::timeout(Duration::from_secs(10), ghostlink_contracts::read_frame(&mut reader)).await;
                    let response = match request {
                        Ok(Ok(bytes)) => match serde_json::from_slice::<Request>(&bytes) {
                            Ok(request) if remote::is_remote(&request.action) => remote::handle(&daemon, request).await,
                        Ok(request) => daemon.lock().await.handle(request).await,
                            Err(_) => Response::err("invalid_request", "Invalid request; use the versioned Ghostlink contract"),
                        },
                        _ => Response::err("invalid_request", "Incomplete or oversized IPC frame"),
                    };
                    let _ = tokio::time::timeout(Duration::from_secs(5), ghostlink_contracts::write_frame(reader.get_mut(), &response)).await;
                });
            }
        }
    }
    // Cancel requests still in flight. State commits are synchronous, so a cancelled request
    // either committed or did not. A cancelled disconnect keeps its session, and a cancelled
    // engine start drops its child handles (OpenVPN is killed before hold release; the managed
    // worker sees parent-pipe EOF), so the disconnect below still covers any running tunnel.
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let mut daemon = daemon.lock().await;
    daemon.disconnect().await;
    daemon.audit("service", "shutdown", "success")?;
    drop(lock);
    Ok(())
}
