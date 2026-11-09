use clap::{Parser, Subcommand};
use ghostlink_contracts::{
    Action, ConnectionState, MeshInvite, MeshNodeChange, MeshPatch, MeshRule, ProtocolPatch,
    Request, Response, RoutingPolicy, ServerOp, ServerPatch, SplitMode, TrafficRules, UserChange,
    SCHEMA_VERSION,
};
use serde_json::json;
use std::{
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    name = "ghostlink",
    version,
    about = "Control the authorized local Ghostlink service"
)]
struct Args {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true, default_value_t = 75, value_parser = clap::value_parser!(u64).range(1..=600))]
    timeout: u64,
    #[arg(long, global = true, env = "GHOSTLINK_ENDPOINT", default_value_t = ghostlink_contracts::default_endpoint())]
    endpoint: String,
    #[arg(long, global = true, env = "GHOSTLINK_AGENT_TOKEN_FILE")]
    agent_token_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Add a VPN key (ss://, ssconf://, vless://, Amnezia vpn:// or WireGuard/AmneziaWG
    /// configuration text) from a file or stdin, never from process arguments.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Connect {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        no_wait: bool,
    },
    Disconnect,
    Status,
    Info,
    /// List the VPN servers saved on this device.
    Servers {
        #[command(subcommand)]
        command: ServersCommand,
    },
    /// Administer Ghostlink servers you run: users, keys, traffic rules and usage.
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    Switch {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        no_wait: bool,
    },
    Autoconnect {
        #[command(subcommand)]
        command: Toggle,
    },
    Logs {
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(0..=1000))]
        tail: u16,
    },
    Doctor,
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Version,
    /// Split tunneling: choose which sites, IP ranges and apps use the VPN.
    Split {
        #[command(subcommand)]
        command: SplitCommand,
    },
}
#[derive(Subcommand)]
enum SplitCommand {
    /// Show the global policy, or one server's override.
    Show {
        #[arg(long)]
        profile: Option<String>,
    },
    /// Replace the policy. bypass: listed items skip the VPN; only: only listed items use it.
    Set {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_parser = ["full", "bypass", "only"])]
        mode: String,
        /// Site (matches subdomains), e.g. example.com. Repeatable.
        #[arg(long = "site", visible_alias = "domain")]
        sites: Vec<String>,
        /// IPv4/IPv6 CIDR range. Repeatable.
        #[arg(long = "ip")]
        ips: Vec<String>,
        /// Executable name or full path, e.g. chrome.exe. Repeatable.
        #[arg(long = "app")]
        apps: Vec<String>,
        /// Keep local-network destinations off the VPN.
        #[arg(long)]
        lan_direct: bool,
    },
    /// Remove a server's override (it follows the global policy again), or reset the global policy.
    Clear {
        #[arg(long)]
        profile: Option<String>,
    },
}
#[derive(Subcommand)]
enum ProfileCommand {
    Import {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
        /// Overwrite an existing profile with the same name.
        #[arg(long)]
        replace: bool,
    },
    List,
    Default {
        name: String,
    },
    Remove {
        name: String,
    },
}
#[derive(Subcommand)]
enum KeyCommand {
    Add {
        #[arg(long)]
        name: String,
        #[arg(long, conflicts_with = "stdin")]
        file: Option<PathBuf>,
        #[arg(long, conflicts_with = "file")]
        stdin: bool,
        /// Overwrite an existing server with the same ID.
        #[arg(long)]
        replace: bool,
    },
}
#[derive(Subcommand)]
enum ServersCommand {
    List,
}
#[derive(Subcommand)]
enum ServerCommand {
    /// Print how to install a Ghostlink server on a Linux machine.
    InstallHelp,
    /// Save a server's management key (from `sudo ghostlink-server show-key`).
    Add {
        #[arg(long)]
        name: String,
        #[arg(long, conflicts_with = "key_stdin")]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]
        key_stdin: bool,
        #[arg(long)]
        replace: bool,
    },
    /// List managed servers (addresses only; keys are never shown).
    List,
    /// Forget a managed server on this device. The server itself is not changed.
    Remove {
        #[arg(long)]
        name: String,
    },
    /// Show a server's protocols, ports and settings.
    Info {
        #[arg(long)]
        server: String,
    },
    /// Change server settings. Changes apply immediately; users reconnect automatically.
    Set {
        #[arg(long)]
        server: String,
        /// Display name.
        #[arg(long)]
        name: Option<String>,
        /// Public IP or DNS name written into new keys.
        #[arg(long)]
        hostname: Option<String>,
        /// Public TLS 1.3 site whose handshake VLESS-REALITY borrows.
        #[arg(long)]
        reality_site: Option<String>,
        /// Turn a protocol on (amneziawg, wireguard, vless, shadowsocks, ikev2, ipsec). Repeatable.
        #[arg(long = "enable")]
        enable: Vec<String>,
        /// Turn a protocol off. Its keys stop working until it is turned on again. Repeatable.
        #[arg(long = "disable")]
        disable: Vec<String>,
        /// PROTOCOL=PORT, e.g. vless=8443. Repeatable.
        #[arg(long = "port")]
        ports: Vec<String>,
        /// Record top sites per user (off deletes what was recorded).
        #[arg(long, value_parser = ["on", "off"])]
        site_stats: Option<String>,
        /// Days of traffic history to keep (7-365).
        #[arg(long)]
        history_days: Option<u32>,
        /// Days of site totals to keep (1-90).
        #[arg(long)]
        site_days: Option<u32>,
        /// Size limit for recorded history, in MB.
        #[arg(long)]
        history_max_mb: Option<u32>,
        /// Replace the IPsec group key (every IPsec PSK profile must be installed again).
        #[arg(long)]
        rotate_ipsec_psk: bool,
        /// Speed limit for users without their own, in megabytes per second (10^6 bytes per
        /// second, download and upload alike), or none.
        #[arg(long, value_name = "MB/s|none")]
        default_speed_limit: Option<String>,
    },
    /// Live speed per user, online users and server health.
    Live {
        #[arg(long)]
        server: String,
    },
    /// Recorded traffic: types, protocols, top services and usage over time.
    Stats {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value = "7d", value_parser = ["24h", "7d", "30d", "90d"])]
        range: String,
    },
    /// Addresses users connected from (last 30 days).
    Clients {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: Option<String>,
    },
    Users {
        #[command(subcommand)]
        command: ServerUsersCommand,
    },
    Keys {
        #[command(subcommand)]
        command: ServerKeysCommand,
    },
    Rules {
        #[command(subcommand)]
        command: ServerRulesCommand,
    },
    /// The mesh: a private network between your Linux servers, coordinated by this server.
    Mesh {
        #[command(subcommand)]
        command: ServerMeshCommand,
    },
    /// Data used by each user.
    Usage {
        #[arg(long)]
        server: String,
    },
}
#[derive(Subcommand)]
enum ServerUsersCommand {
    List {
        #[arg(long)]
        server: String,
    },
    Add {
        #[arg(long)]
        server: String,
        #[arg(long)]
        name: String,
        /// Data limit in gigabytes (10^9 bytes); the user is cut off when it is reached.
        #[arg(long)]
        data_limit_gb: Option<f64>,
        /// Speed limit in megabytes per second (10^6 bytes per second, download and upload
        /// alike, for all the user's keys), none, or default (the server's).
        #[arg(long, value_name = "MB/s|none|default")]
        speed_limit: Option<String>,
        /// Do not apply the server-wide rules to this user.
        #[arg(long)]
        exempt_from_global_rules: bool,
    },
    Update {
        #[arg(long)]
        server: String,
        /// User ID (see `server users list`).
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Data limit in gigabytes; 0 removes the limit.
        #[arg(long)]
        data_limit_gb: Option<f64>,
        /// Speed limit in megabytes per second, none, or default (the server's).
        #[arg(long, value_name = "MB/s|none|default")]
        speed_limit: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(bool))]
        exempt_from_global_rules: Option<bool>,
        /// Start counting this user's data from zero again.
        #[arg(long)]
        reset_usage: bool,
    },
    Remove {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
    },
}
#[derive(Subcommand)]
enum ServerKeysCommand {
    /// List a user's keys. Key material is hidden unless --show-keys is given.
    List {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        show_keys: bool,
    },
    /// Create a key. It is printed unless --output or --import is given.
    Create {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        /// ikev2 and ipsec are the built-in VPN of iPhone, iPad and Mac (save with keys profile).
        #[arg(long, value_parser = ["amneziawg", "wireguard", "vless", "shadowsocks", "ikev2", "ipsec"])]
        protocol: String,
        /// Also save it as a VPN server on this device with this ID.
        #[arg(long = "import")]
        import_as: Option<String>,
        /// Write the key to this NEW private file (WireGuard/AmneziaWG also get FILE.conf).
        #[arg(long)]
        output: Option<PathBuf>,
        /// IKEv2: eap (username and password, default) or certificate. IPsec: certificate (default) or psk.
        #[arg(long, value_parser = ["eap", "certificate", "psk"])]
        auth: Option<String>,
        /// IKEv2/IPsec: the address the device connects to (default: the server's address).
        #[arg(long)]
        server_address: Option<String>,
        /// IKEv2: the server identity the device expects (added to the server certificate).
        #[arg(long)]
        remote_id: Option<String>,
        /// IKEv2/IPsec: the device's identity and user name (default: NAME-ID@ghostlink).
        #[arg(long)]
        local_id: Option<String>,
    },
    /// Save an IKEv2/IPsec key as an Apple profile (.mobileconfig) in a NEW private file.
    Profile {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        output: PathBuf,
        /// Leave the certificate password out of the file; the device asks for it.
        #[arg(long)]
        prompt_password: bool,
        /// Connect automatically whenever the device is online.
        #[arg(long)]
        on_demand: bool,
    },
    Remove {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        key: String,
    },
    /// Print a key's QR code in the terminal.
    Qr {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        key: String,
        /// auto (the .conf for WireGuard-family keys), key or conf.
        #[arg(long, default_value = "auto", value_parser = ["auto", "key", "conf"])]
        content: String,
    },
    /// Save an HTML connection kit (all of a user's keys, QR codes and app help) to a NEW private file.
    Kit {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum ServerMeshCommand {
    /// Mesh settings, node count and open invites.
    Show {
        #[arg(long)]
        server: String,
    },
    /// Turn the mesh on (optionally choosing its network before nodes join).
    Enable {
        #[arg(long)]
        server: String,
        #[arg(long)]
        cidr: Option<String>,
    },
    /// Turn the mesh off; connected nodes take their links down, nothing is deleted.
    Disable {
        #[arg(long)]
        server: String,
    },
    /// Create an invite and print the one-line join command (or write it to a NEW private file).
    Invite {
        #[arg(long)]
        server: String,
        /// Tags for access rules, comma-separated.
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        uses: Option<u32>,
        #[arg(long)]
        hours: Option<u32>,
        #[arg(long)]
        relay: bool,
        #[arg(long)]
        approval: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Open invites.
    Invites {
        #[arg(long)]
        server: String,
    },
    Revoke {
        #[arg(long)]
        server: String,
        #[arg(long)]
        invite: String,
    },
    /// Nodes and links (the data the app's map draws).
    Nodes {
        #[arg(long)]
        server: String,
    },
    /// Change a node: approve it, share its subnets, tags, relay, or disable it.
    Node {
        #[arg(long)]
        server: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Option<Vec<String>>,
        /// active (approve or enable) or disabled.
        #[arg(long, value_parser = ["active", "disabled"])]
        status: Option<String>,
        #[arg(long, value_parser = ["on", "off"])]
        relay: Option<String>,
        /// Subnets to share (from those the node offers), comma-separated, or "none".
        #[arg(long)]
        routes: Option<String>,
        #[arg(long, value_parser = ["on", "off"])]
        masquerade: Option<String>,
    },
    Remove {
        #[arg(long)]
        server: String,
        #[arg(long)]
        node: String,
    },
    /// Show the access rules, or replace them with --rule "FROM TO PROTOCOL [PORTS]" (repeatable)
    /// or --clear. Without rules every node reaches every node.
    // The comment above is this command's --help text, so `[PORTS]` stays as the user should
    // type it rather than becoming a rustdoc link (code review 2026-11-10, Rust finding 6).
    #[allow(rustdoc::broken_intra_doc_links)]
    Rules {
        #[arg(long)]
        server: String,
        #[arg(long = "rule")]
        rules: Vec<String>,
        #[arg(long)]
        clear: bool,
    },
}
#[derive(Subcommand)]
enum ServerRulesCommand {
    /// Show the server-wide rules, or one user's rules.
    Show {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: Option<String>,
    },
    /// Replace the server-wide rules, or one user's rules, with exactly these blocks.
    Set {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: Option<String>,
        /// Block a site and its subdomains. Repeatable.
        #[arg(long = "block-site")]
        sites: Vec<String>,
        /// Block an IP address or CIDR range. Repeatable.
        #[arg(long = "block-ip")]
        ips: Vec<String>,
        /// Block a port or range, e.g. 25 or 6881-6889. Repeatable.
        #[arg(long = "block-port")]
        ports: Vec<String>,
        #[arg(long)]
        block_bittorrent: bool,
        /// Block outgoing mail (port 25).
        #[arg(long)]
        block_smtp: bool,
    },
}
#[derive(Subcommand)]
enum Toggle {
    Enable,
    Disable,
}
#[derive(Subcommand)]
enum AgentCommand {
    /// Issue a scoped token directly into a new private file. Existing grants of this name are replaced.
    Grant {
        #[arg(long)]
        name: String,
        #[arg(long)]
        control: bool,
        #[arg(long)]
        token_file: PathBuf,
    },
    Revoke {
        #[arg(long)]
        name: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let operation = run(&args);
    let response = tokio::select! {
        result = operation => result,
        _ = tokio::signal::ctrl_c() => {
            let response = Response::err("interrupted", "CLI interrupted; an accepted operation may continue. Inspect status or explicitly disconnect.");
            print(&response, args.json); std::process::exit(130);
        }
    };
    print(&response, args.json);
    let mut code = response.exit_code();
    if matches!(args.command, Command::Doctor)
        && response
            .data
            .as_ref()
            .and_then(|x| x.get("engine_available"))
            .and_then(|x| x.as_bool())
            == Some(false)
    {
        code = 4;
    }
    std::process::exit(code);
}

async fn run(args: &Args) -> Response {
    if matches!(args.command, Command::Version) {
        return Response::ok(
            json!({"version": env!("CARGO_PKG_VERSION"), "schema_version": SCHEMA_VERSION}),
        );
    }
    let token = if let Some(path) = &args.agent_token_file {
        match std::fs::metadata(path).and_then(|m| {
            if m.len() > 128 {
                Err(std::io::Error::other("Token file too large"))
            } else {
                std::fs::read_to_string(path)
            }
        }) {
            Ok(token) => Some(token.trim().into()),
            Err(_) => {
                return Response::err("permission_denied", "Cannot read private agent token file")
            }
        }
    } else {
        None
    };
    let action = match &args.command {
        Command::Key {
            command:
                KeyCommand::Add {
                    name,
                    file,
                    stdin,
                    replace,
                },
        } => {
            let content = match read_secret(
                file.as_ref(),
                *stdin,
                "access key",
                "--file",
                "--stdin",
                Duration::from_secs(args.timeout),
            )
            .await
            {
                Ok(content) => content,
                Err(response) => return response,
            };
            Action::AccessKeyImport {
                name: name.clone(),
                access_key: content,
                replace: *replace,
            }
        }
        Command::Profile { command } => match command {
            ProfileCommand::Import {
                file,
                name,
                replace,
            } => {
                let content = match std::fs::metadata(file).and_then(|meta| {
                    if meta.len() > ghostlink_engine::profile::MAX_PROFILE as u64 {
                        Err(std::io::Error::other("Profile too large"))
                    } else {
                        std::fs::read_to_string(file)
                    }
                }) {
                    Ok(content) => content,
                    Err(_) => {
                        return Response::err(
                            "invalid_profile",
                            "Cannot read UTF-8 profile (maximum 1 MiB)",
                        )
                    }
                };
                let name = name
                    .clone()
                    .or_else(|| file.file_stem().and_then(|s| s.to_str()).map(String::from))
                    .unwrap_or_default();
                Action::ProfileImport {
                    name,
                    content,
                    replace: *replace,
                }
            }
            ProfileCommand::List => Action::ProfileList {},
            ProfileCommand::Default { name } => Action::ProfileDefault { name: name.clone() },
            ProfileCommand::Remove { name } => Action::ProfileRemove { name: name.clone() },
        },
        Command::Connect { profile, .. } => Action::Connect {
            profile: profile.clone(),
        },
        Command::Disconnect => Action::Disconnect {},
        Command::Status => Action::Status {},
        Command::Info => Action::Info {},
        Command::Servers { .. } => Action::ServersList {},
        Command::Server {
            command: ServerCommand::InstallHelp,
        } => return Response::ok(json!({ "help_text": install_help() })),
        Command::Server { command } => match server_action(command, args.timeout).await {
            Ok(action) => action,
            Err(response) => return response,
        },
        Command::Switch { profile, .. } => Action::Switch {
            profile: profile.clone(),
        },
        Command::Autoconnect { command } => Action::Autoconnect {
            enabled: matches!(command, Toggle::Enable),
        },
        Command::Logs { tail } => Action::Logs {
            tail: *tail as usize,
        },
        Command::Doctor => Action::Doctor {},
        Command::Split { command } => match command {
            SplitCommand::Show { profile } => Action::RoutingPolicyGet {
                profile: profile.clone(),
            },
            SplitCommand::Set {
                profile,
                mode,
                sites,
                ips,
                apps,
                lan_direct,
            } => Action::RoutingPolicySet {
                profile: profile.clone(),
                policy: Some(RoutingPolicy {
                    mode: match mode.as_str() {
                        "bypass" => SplitMode::Bypass,
                        "only" => SplitMode::Only,
                        _ => SplitMode::Full,
                    },
                    domains: sites.clone(),
                    ip_ranges: ips.clone(),
                    apps: apps.clone(),
                    lan_direct: *lan_direct,
                }),
            },
            SplitCommand::Clear { profile } => Action::RoutingPolicySet {
                profile: profile.clone(),
                policy: None,
            },
        },
        Command::Agent { command } => match command {
            AgentCommand::Grant {
                name,
                control,
                token_file,
            } => {
                // Checked before the grant: issuing it replaces any grant of this name, so a
                // token that cannot be saved would also invalidate the one already in use.
                let folder = token_file
                    .parent()
                    .is_none_or(|p| p.as_os_str().is_empty() || p.is_dir());
                if token_file.exists() || !folder {
                    return Response::err(
                        "invalid_request",
                        "--token-file must name a new file in an existing folder; it will not overwrite an existing one",
                    );
                }
                Action::AgentGrant {
                    name: name.clone(),
                    control: *control,
                }
            }
            AgentCommand::Revoke { name } => Action::AgentRevoke { name: name.clone() },
        },
        Command::Version => unreachable!(),
    };
    let start = Instant::now();
    let timeout = Duration::from_secs(args.timeout);
    let mut response = ghostlink_contracts::call(
        &args.endpoint,
        Request {
            schema_version: SCHEMA_VERSION,
            agent_token: token.clone(),
            action,
        },
        timeout,
    )
    .await;
    if let Command::Agent {
        command: AgentCommand::Grant { token_file, .. },
    } = &args.command
    {
        if response.success {
            let value = response
                .data
                .as_mut()
                .and_then(|d| d.as_object_mut())
                .and_then(|d| d.remove("issued_token"));
            let issued = match value.as_ref().and_then(|v| v.as_str()) {
                Some(value) => value,
                None => {
                    return Response::err("internal", "Token issuance did not return a credential")
                }
            };
            let result = (|| -> std::io::Result<()> {
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(token_file)?;
                #[cfg(windows)]
                ghostlink_engine::storage::restrict_acl(token_file)
                    .map_err(|_| std::io::Error::other("Cannot protect token file"))?;
                writeln!(file, "{issued}")?;
                file.sync_all()?;
                Ok(())
            })();
            if result.is_err() {
                return Response::err("permission_denied", "Could not create a NEW private token file; revoke this grant or issue it again to a writable unused path");
            }
            response.data.as_mut().unwrap()["token_saved"] = json!(true);
        }
    }
    if let Command::Server { command } = &args.command {
        if response.success {
            if let Err(error) = finish_server_response(command, &mut response) {
                return error;
            }
        }
    }
    let wait = matches!(
        args.command,
        Command::Connect { no_wait: false, .. } | Command::Switch { no_wait: false, .. }
    );
    while response.success && wait {
        let status = response.data.as_ref().and_then(|data| {
            serde_json::from_value::<ghostlink_contracts::Status>(data.clone()).ok()
        });
        match status.map(|s| s.status) {
            Some(ConnectionState::Connected) => break,
            Some(ConnectionState::Failed | ConnectionState::Disconnected) => return Response::err("connection_failed", "The engine did not establish a VPN connection; inspect status and doctor for the sanitized failure reason"),
            Some(_) => {}
            None => return Response::err("internal", "Invalid connection state returned by service"),
        }
        let remaining = match timeout.checked_sub(start.elapsed()) {
            Some(value) if value > Duration::from_millis(300) => value,
            _ => return Response::err(
                "timeout",
                "Connection wait timed out; inspect status or disconnect the accepted operation",
            ),
        };
        tokio::time::sleep(Duration::from_millis(250)).await;
        response = ghostlink_contracts::call(
            &args.endpoint,
            Request {
                schema_version: SCHEMA_VERSION,
                agent_token: token.clone(),
                action: Action::Status {},
            },
            remaining,
        )
        .await;
    }
    response
}

fn print(response: &Response, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string(response).expect("serializable response")
        );
        return;
    }
    if let Some(error) = &response.error {
        eprintln!("{}: {}", error.code, error.message);
        return;
    }
    let data = response.data.as_ref().unwrap();
    if let Some(text) = data.get("help_text").and_then(|t| t.as_str()) {
        println!("{text}");
        return;
    }
    if let Ok(status) = serde_json::from_value::<ghostlink_contracts::Status>(data.clone()) {
        println!(
            "{}",
            serde_json::to_value(&status.status)
                .unwrap()
                .as_str()
                .unwrap()
        );
        if let Some(name) = status.profile {
            println!("Profile: {name}");
        }
        if let Some(server) = status.server {
            println!("Server: {server}");
        }
        if let Some(ip) = status.vpn_ip {
            println!("VPN IP: {ip}");
        }
        if let Some(error) = status.last_error {
            println!("Last error: {error}");
        }
    } else if let Some(profiles) = data.get("profiles").and_then(|p| p.as_array()) {
        if profiles.is_empty() {
            println!("No VPN profiles imported.");
        }
        for profile in profiles {
            println!(
                "{}{} ({})",
                profile["name"].as_str().unwrap_or("?"),
                if profile["is_default"] == true {
                    " *"
                } else {
                    ""
                },
                profile["tunnel_mode"].as_str().unwrap_or("?")
            );
        }
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap());
    }
}

/// Reads a credential from a file or a pipe, never from an argument or an interactive terminal.
/// A pipe is read within `timeout`.
async fn read_secret(
    file: Option<&PathBuf>,
    stdin: bool,
    what: &str,
    file_flag: &str,
    stdin_flag: &str,
    timeout: Duration,
) -> Result<String, Response> {
    const LIMIT: u64 = 16384;
    if let Some(file) = file {
        return std::fs::metadata(file)
            .and_then(|m| {
                if m.len() <= LIMIT {
                    std::fs::read_to_string(file)
                } else {
                    Err(std::io::Error::other("too large"))
                }
            })
            .map_err(|_| {
                Response::err(
                    "invalid_profile",
                    &format!("Cannot read the {what} file (maximum 16 KiB)"),
                )
            });
    }
    if stdin {
        use std::io::{IsTerminal, Read};
        if std::io::stdin().is_terminal() {
            return Err(Response::err("invalid_request", &format!("Pipe the {what} to stdin or use {file_flag}; interactive terminal entry is disabled to avoid echoing credentials")));
        }
        // On a blocking thread: a pipe that never closes must not hold the CLI past --timeout
        // or keep Ctrl+C from being handled.
        let read = tokio::task::spawn_blocking(|| {
            let mut value = String::new();
            std::io::stdin()
                .take(LIMIT + 1)
                .read_to_string(&mut value)
                .map(|_| value)
        });
        return match tokio::time::timeout(timeout, read).await {
            Ok(Ok(Ok(value))) if value.len() as u64 <= LIMIT => Ok(value),
            Err(_) => Err(Response::err(
                "timeout",
                &format!(
                    "Timed out reading the {what} from stdin; close the pipe after the {what}"
                ),
            )),
            _ => Err(Response::err(
                "invalid_profile",
                &format!("Cannot read the {what} from stdin"),
            )),
        };
    }
    Err(Response::err(
        "invalid_request",
        &format!("Choose {stdin_flag} or {file_flag} for the {what}"),
    ))
}

fn install_help() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
        "Set up a Ghostlink server on a Linux machine with Docker (Debian/Ubuntu or Fedora/RHEL):

  1. Download from the Ghostlink {version} release:
       ghostlink-server_{version}-1_amd64.deb   (or _arm64.deb)
       ghostlink-server-{version}-1.x86_64.rpm  (or .aarch64.rpm)
  2. Install it; this loads the bundled container image and starts the server:
       sudo apt install ./ghostlink-server_{version}-1_amd64.deb
       sudo dnf install ./ghostlink-server-{version}-1.x86_64.rpm
  3. Copy the management key it prints (show it again: sudo ghostlink-server show-key)
     into a private file on this device, then:
       ghostlink server add --name myserver --key-file management-key.json
  4. Allow the server's ports in its firewall / cloud security group
     (sudo ghostlink-server status lists them).

Or in one command, which also installs Docker and verifies the package:
       curl -fsSL https://raw.githubusercontent.com/winyannainghtut/GHOSTLINK/main/scripts/install-server.sh | sudo bash
Already running Outline there? Add -s -- --migrate-outline (try --migrate-outline --check
first): every Outline access key becomes a client, and its ss:// key keeps working.

The management key gives full control of the server. Keep it private."
    )
}

fn gigabytes(value: f64) -> Result<u64, Response> {
    if !value.is_finite() || !(0.0..=1.0e9).contains(&value) {
        return Err(Response::err(
            "invalid_request",
            "Data limits must be between 0 and 1,000,000,000 GB",
        ));
    }
    Ok((value * 1.0e9).round() as u64)
}

/// Megabytes per second (10^6 bytes) as bytes per second, from 0.001 to 1250 MB/s.
fn megabytes_per_second(value: &str) -> Result<i64, Response> {
    let text = value.trim();
    let number = text
        .strip_suffix("MB/s")
        .or_else(|| text.strip_suffix("mb/s"))
        .unwrap_or(text)
        .trim();
    match number.parse::<f64>() {
        Ok(mb) if mb.is_finite() && (0.001..=1250.0).contains(&mb) => {
            Ok((mb * 1.0e6).round() as i64)
        }
        _ => Err(Response::err(
            "invalid_request",
            "Speed limits are 0.001 to 1250 MB/s (megabytes per second), none or default",
        )),
    }
}

/// A user's speed limit: MB/s, none (-1: no limit whatever the default) or default (0).
fn user_speed_limit(value: &str) -> Result<i64, Response> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "off" | "unlimited" => Ok(-1),
        "default" => Ok(0),
        _ => megabytes_per_second(value),
    }
}

/// The server's default speed limit: MB/s or none (0).
fn default_speed_limit(value: &str) -> Result<u64, Response> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "off" | "0" => Ok(0),
        _ => megabytes_per_second(value).map(|bps| bps as u64),
    }
}

fn call(server: &str, op: ServerOp) -> Action {
    Action::ServerCall {
        server: server.into(),
        op,
    }
}

/// `timeout` is the CLI's `--timeout` in seconds, for reading a management key from a pipe.
async fn server_action(command: &ServerCommand, timeout: u64) -> Result<Action, Response> {
    Ok(match command {
        ServerCommand::InstallHelp => unreachable!("answered locally"),
        ServerCommand::Add {
            name,
            key_file,
            key_stdin,
            replace,
        } => Action::ManagedServerAdd {
            name: name.clone(),
            management_key: read_secret(
                key_file.as_ref(),
                *key_stdin,
                "management key",
                "--key-file",
                "--key-stdin",
                Duration::from_secs(timeout),
            )
            .await?,
            replace: *replace,
        },
        ServerCommand::List => Action::ManagedServerList {},
        ServerCommand::Remove { name } => Action::ManagedServerRemove { name: name.clone() },
        ServerCommand::Info { server } => call(server, ServerOp::Info {}),
        ServerCommand::Set {
            server,
            name,
            hostname,
            reality_site,
            enable,
            disable,
            ports,
            site_stats,
            history_days,
            site_days,
            history_max_mb,
            rotate_ipsec_psk,
            default_speed_limit: speed_default,
        } => {
            let mut protocols = std::collections::BTreeMap::<String, ProtocolPatch>::new();
            for protocol in enable {
                protocols.entry(protocol.clone()).or_default().enabled = Some(true);
            }
            for protocol in disable {
                protocols.entry(protocol.clone()).or_default().enabled = Some(false);
            }
            for entry in ports {
                let (protocol, port) = entry
                    .split_once('=')
                    .and_then(|(p, n)| n.parse::<u16>().ok().map(|n| (p, n)))
                    .ok_or_else(|| {
                        Response::err(
                            "invalid_request",
                            "Use --port PROTOCOL=PORT, e.g. vless=8443",
                        )
                    })?;
                protocols.entry(protocol.into()).or_default().port = Some(port);
            }
            call(
                server,
                ServerOp::Update {
                    patch: ServerPatch {
                        name: name.clone(),
                        hostname: hostname.clone(),
                        vless_handshake: reality_site.clone(),
                        protocols: (!protocols.is_empty()).then_some(protocols),
                        site_stats: site_stats.as_deref().map(|v| v == "on"),
                        history_days: *history_days,
                        site_days: *site_days,
                        history_max_mb: *history_max_mb,
                        rotate_ipsec_psk: rotate_ipsec_psk.then_some(true),
                        default_speed_limit_bps: speed_default
                            .as_deref()
                            .map(default_speed_limit)
                            .transpose()?,
                    },
                },
            )
        }
        ServerCommand::Users { command } => match command {
            ServerUsersCommand::List { server } => call(server, ServerOp::UsersList {}),
            ServerUsersCommand::Add {
                server,
                name,
                data_limit_gb,
                speed_limit,
                exempt_from_global_rules,
            } => call(
                server,
                ServerOp::UserCreate {
                    change: UserChange {
                        name: Some(name.clone()),
                        data_limit_bytes: data_limit_gb.map(gigabytes).transpose()?,
                        speed_limit_bps: speed_limit
                            .as_deref()
                            .map(user_speed_limit)
                            .transpose()?,
                        exempt_from_global_rules: Some(*exempt_from_global_rules),
                        ..Default::default()
                    },
                },
            ),
            ServerUsersCommand::Update {
                server,
                user,
                name,
                enable,
                disable,
                data_limit_gb,
                speed_limit,
                exempt_from_global_rules,
                reset_usage,
            } => call(
                server,
                ServerOp::UserUpdate {
                    user: user.clone(),
                    change: UserChange {
                        name: name.clone(),
                        enabled: if *enable {
                            Some(true)
                        } else if *disable {
                            Some(false)
                        } else {
                            None
                        },
                        data_limit_bytes: data_limit_gb.map(gigabytes).transpose()?,
                        exempt_from_global_rules: *exempt_from_global_rules,
                        rules: None,
                        reset_usage: *reset_usage,
                        speed_limit_bps: speed_limit
                            .as_deref()
                            .map(user_speed_limit)
                            .transpose()?,
                    },
                },
            ),
            ServerUsersCommand::Remove { server, user } => {
                call(server, ServerOp::UserDelete { user: user.clone() })
            }
        },
        ServerCommand::Keys { command } => match command {
            ServerKeysCommand::List { server, user, .. } => {
                call(server, ServerOp::KeysList { user: user.clone() })
            }
            ServerKeysCommand::Create {
                server,
                user,
                protocol,
                import_as,
                output,
                auth,
                server_address,
                remote_id,
                local_id,
            } => {
                if output.as_ref().is_some_and(|path| path.exists()) {
                    return Err(Response::err(
                        "invalid_request",
                        "--output must name a new file; it will not overwrite an existing one",
                    ));
                }
                // Checked before the server creates a key whose configuration could not be saved.
                if output.as_ref().is_some_and(|path| {
                    matches!(protocol.as_str(), "wireguard" | "amneziawg")
                        && conf_path(path).exists()
                }) {
                    return Err(Response::err(
                        "invalid_request",
                        "--output FILE also writes FILE.conf for WireGuard and AmneziaWG keys, and that file already exists; it will not overwrite it",
                    ));
                }
                if output.is_some() && (protocol == "ikev2" || protocol == "ipsec") {
                    return Err(Response::err(
                        "invalid_request",
                        "IKEv2 and IPsec keys are saved as a profile: ghostlink server keys profile --output FILE",
                    ));
                }
                call(
                    server,
                    ServerOp::KeyCreate {
                        user: user.clone(),
                        protocol: protocol.clone(),
                        import_as: import_as.clone(),
                        auth: auth.clone(),
                        server_address: server_address.clone(),
                        remote_identifier: remote_id.clone(),
                        local_identifier: local_id.clone(),
                    },
                )
            }
            ServerKeysCommand::Profile {
                server,
                user,
                key,
                output,
                prompt_password,
                on_demand,
            } => {
                if output.exists() {
                    return Err(Response::err(
                        "invalid_request",
                        "--output must name a new file; it will not overwrite an existing one",
                    ));
                }
                call(
                    server,
                    ServerOp::KeyProfile {
                        user: user.clone(),
                        key: key.clone(),
                        prompt_password: *prompt_password,
                        on_demand: *on_demand,
                    },
                )
            }
            ServerKeysCommand::Remove { server, user, key } => call(
                server,
                ServerOp::KeyDelete {
                    user: user.clone(),
                    key: key.clone(),
                },
            ),
            ServerKeysCommand::Qr {
                server,
                user,
                key,
                content,
            } => call(
                server,
                ServerOp::KeyQr {
                    user: user.clone(),
                    key: key.clone(),
                    format: "text".into(),
                    content: Some(content.clone()),
                },
            ),
            ServerKeysCommand::Kit {
                server,
                user,
                output,
            } => {
                if output.exists() {
                    return Err(Response::err(
                        "invalid_request",
                        "--output must name a new file; it will not overwrite an existing one",
                    ));
                }
                call(server, ServerOp::Kit { user: user.clone() })
            }
        },
        ServerCommand::Rules { command } => match command {
            ServerRulesCommand::Show { server, user: None } => call(server, ServerOp::RulesGet {}),
            // One user's rules come from the user list.
            ServerRulesCommand::Show {
                server,
                user: Some(_),
            } => call(server, ServerOp::UsersList {}),
            ServerRulesCommand::Set {
                server,
                user,
                sites,
                ips,
                ports,
                block_bittorrent,
                block_smtp,
            } => {
                let rules = TrafficRules {
                    blocked_domains: sites.clone(),
                    blocked_ips: ips.clone(),
                    blocked_ports: ports.clone(),
                    block_bittorrent: *block_bittorrent,
                    block_smtp: *block_smtp,
                };
                match user {
                    None => call(server, ServerOp::RulesSet { rules }),
                    Some(user) => call(
                        server,
                        ServerOp::UserUpdate {
                            user: user.clone(),
                            change: UserChange {
                                rules: Some(rules),
                                ..Default::default()
                            },
                        },
                    ),
                }
            }
        },
        ServerCommand::Mesh { command } => mesh_action(command)?,
        ServerCommand::Usage { server } => call(server, ServerOp::Metrics {}),
        ServerCommand::Live { server } => call(server, ServerOp::Live {}),
        ServerCommand::Stats {
            server,
            user,
            range,
        } => call(
            server,
            ServerOp::Stats {
                user: user.clone(),
                range: range.clone(),
            },
        ),
        ServerCommand::Clients { server, user } => {
            call(server, ServerOp::Clients { user: user.clone() })
        }
    })
}

/// The `.conf` file written next to a WireGuard or AmneziaWG key saved with `--output FILE`.
fn conf_path(path: &std::path::Path) -> PathBuf {
    let mut conf = path.as_os_str().to_owned();
    conf.push(".conf");
    PathBuf::from(conf)
}

/// Writes `content` to a NEW file only this user can read.
fn write_private(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(windows)]
    ghostlink_engine::storage::restrict_acl(path)
        .map_err(|_| std::io::Error::other("Cannot protect the file"))?;
    file.write_all(content.as_bytes())?;
    file.sync_all()
}

fn on_off(value: &Option<String>) -> Option<bool> {
    value.as_deref().map(|v| v == "on")
}

fn mesh_action(command: &ServerMeshCommand) -> Result<Action, Response> {
    let call = |server: &String, op| Action::ServerCall {
        server: server.clone(),
        op,
    };
    Ok(match command {
        ServerMeshCommand::Show { server } => call(server, ServerOp::MeshInfo {}),
        ServerMeshCommand::Enable { server, cidr } => call(
            server,
            ServerOp::MeshUpdate {
                patch: MeshPatch {
                    enabled: Some(true),
                    cidr: cidr.clone(),
                    ..Default::default()
                },
            },
        ),
        ServerMeshCommand::Disable { server } => call(
            server,
            ServerOp::MeshUpdate {
                patch: MeshPatch {
                    enabled: Some(false),
                    ..Default::default()
                },
            },
        ),
        ServerMeshCommand::Invite {
            server,
            tags,
            uses,
            hours,
            relay,
            approval,
            output,
        } => {
            if output.as_ref().is_some_and(|p| p.exists()) {
                return Err(Response::err(
                    "invalid_request",
                    "--output must name a new file; it will not overwrite an existing one",
                ));
            }
            call(
                server,
                ServerOp::MeshInviteCreate {
                    invite: MeshInvite {
                        tags: tags.clone(),
                        uses: *uses,
                        expires_hours: *hours,
                        relay: *relay,
                        approval: *approval,
                        note: None,
                    },
                },
            )
        }
        ServerMeshCommand::Invites { server } => call(server, ServerOp::MeshInviteList {}),
        ServerMeshCommand::Revoke { server, invite } => call(
            server,
            ServerOp::MeshInviteDelete {
                invite: invite.clone(),
            },
        ),
        ServerMeshCommand::Nodes { server } => call(server, ServerOp::MeshTopology {}),
        ServerMeshCommand::Node {
            server,
            node,
            name,
            tags,
            status,
            relay,
            routes,
            masquerade,
        } => {
            let approved_routes = routes.as_deref().map(|r| {
                if r == "none" {
                    Vec::new()
                } else {
                    r.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
            });
            call(
                server,
                ServerOp::MeshNodeUpdate {
                    node: node.clone(),
                    change: MeshNodeChange {
                        name: name.clone(),
                        tags: tags.clone(),
                        status: status.clone(),
                        relay: on_off(relay),
                        approved_routes,
                        masquerade: on_off(masquerade),
                    },
                },
            )
        }
        ServerMeshCommand::Remove { server, node } => {
            call(server, ServerOp::MeshNodeDelete { node: node.clone() })
        }
        ServerMeshCommand::Rules {
            server,
            rules,
            clear,
        } => {
            if rules.is_empty() && !clear {
                return Ok(call(server, ServerOp::MeshRulesGet {}));
            }
            let mut parsed = Vec::new();
            for rule in rules {
                let parts: Vec<&str> = rule.split_whitespace().collect();
                if !(3..=4).contains(&parts.len()) {
                    return Err(Response::err(
                        "invalid_request",
                        "Use --rule \"FROM TO PROTOCOL [PORTS]\", e.g. --rule \"tag:web tag:db tcp 5432\"",
                    ));
                }
                parsed.push(MeshRule {
                    from: parts[0].into(),
                    to: parts[1].into(),
                    protocol: parts[2].into(),
                    ports: parts
                        .get(3)
                        .map(|p| p.split(',').map(str::to_string).collect())
                        .unwrap_or_default(),
                });
            }
            call(server, ServerOp::MeshRulesSet { rules: parsed })
        }
    })
}

fn finish_server_response(
    command: &ServerCommand,
    response: &mut Response,
) -> Result<(), Response> {
    let Some(data) = response.data.as_mut() else {
        return Ok(());
    };
    match command {
        ServerCommand::Mesh {
            command:
                ServerMeshCommand::Invite {
                    output: Some(path), ..
                },
        } => {
            // Never save an empty file and drop the answer: the invite is shown only once.
            let Some(command) = data["command"].as_str().filter(|c| !c.trim().is_empty()) else {
                return Err(Response::err(
                    "server_error",
                    "The invite was created, but the server returned no join command; revoke it with server mesh revoke and create another",
                ));
            };
            let command = command.to_string();
            if write_private(path, &format!("{command}\n")).is_err() {
                return Err(Response::err(
                    "permission_denied",
                    "The invite was created, but the NEW private --output file could not be written",
                ));
            }
            if let Some(invite) = data.as_object_mut() {
                invite.remove("invite");
                invite.remove("command");
            }
            data["saved_to"] = json!(path.display().to_string());
        }
        ServerCommand::Keys {
            command: ServerKeysCommand::List {
                show_keys: false, ..
            },
        } => {
            for key in data.as_array_mut().into_iter().flatten() {
                if let Some(key) = key.as_object_mut() {
                    key.remove("access_key");
                    key.remove("config");
                    key.remove("certificate_password");
                }
            }
        }
        ServerCommand::Keys {
            command: ServerKeysCommand::Profile { output, .. },
        } => {
            let profile = data.as_str().unwrap_or_default().to_string();
            if !profile.contains("com.apple.vpn.managed") {
                return Err(Response::err(
                    "invalid_response",
                    "The server did not return an Apple profile",
                ));
            }
            if write_private(output, &profile).is_err() {
                return Err(Response::err(
                    "permission_denied",
                    "Could not write the NEW private --output file",
                ));
            }
            *data = json!({
                "saved_to": output.display().to_string(),
                "help_text": "Send this file privately (AirDrop, Mail or Files). Opening it on the iPhone, iPad or Mac installs the VPN: Settings > General > VPN & Device Management."
            });
        }
        ServerCommand::Keys {
            command: ServerKeysCommand::Create {
                output, import_as, ..
            },
        } => {
            if let Some(path) = output {
                let Some(access_key) = data["access_key"].as_str().filter(|k| !k.trim().is_empty())
                else {
                    return Err(Response::err("server_error", "The key was created on the server, but it returned no key to save; list it with server keys list --show-keys"));
                };
                let access_key = access_key.to_string();
                if write_private(path, &format!("{access_key}\n")).is_err() {
                    return Err(Response::err("permission_denied", "The key was created on the server, but the NEW private --output file could not be written; list it with server keys list --show-keys"));
                }
                if let Some(config) = data["config"].as_str().filter(|c| !c.is_empty()) {
                    let conf = conf_path(path);
                    if write_private(&conf, config).is_err() {
                        return Err(Response::err(
                            "permission_denied",
                            "The key was saved, but the .conf file next to it could not be written",
                        ));
                    }
                    data["config_saved_to"] = json!(conf.display().to_string());
                }
                data["saved_to"] = json!(path.display().to_string());
            }
            if output.is_some() || import_as.is_some() {
                if let Some(key) = data.as_object_mut() {
                    key.remove("access_key");
                    key.remove("config");
                }
            }
        }
        ServerCommand::Keys {
            command: ServerKeysCommand::Qr { .. },
        } => {
            // Printed as-is so the terminal draws the code.
            if let Some(text) = data.as_str() {
                *data = json!({ "help_text": text.trim_end() });
            }
        }
        ServerCommand::Keys {
            command: ServerKeysCommand::Kit { output, .. },
        } => {
            let Some(page) = data.as_str().filter(|p| !p.trim().is_empty()) else {
                return Err(Response::err(
                    "server_error",
                    "The server did not return a connection kit",
                ));
            };
            let page = page.to_string();
            if write_private(output, &page).is_err() {
                return Err(Response::err(
                    "permission_denied",
                    "Could not write the NEW private --output file",
                ));
            }
            *data = json!({ "saved_to": output.display().to_string() });
        }
        ServerCommand::Rules {
            command: ServerRulesCommand::Show {
                user: Some(user), ..
            },
        } => {
            let found = data
                .as_array()
                .and_then(|users| users.iter().find(|u| u["id"] == json!(user)))
                .map(|u| json!({"user": u["id"], "name": u["name"], "rules": u["rules"], "exempt_from_global_rules": u["exempt_from_global_rules"]}));
            match found {
                Some(found) => *data = found,
                None => {
                    return Err(Response::err(
                        "not_found",
                        "No user with this ID on the server",
                    ))
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_limits_are_megabytes_per_second() {
        assert_eq!(megabytes_per_second("2").ok(), Some(2_000_000));
        assert_eq!(megabytes_per_second("1.5 MB/s").ok(), Some(1_500_000));
        assert_eq!(megabytes_per_second("0.001").ok(), Some(1_000));
        assert_eq!(megabytes_per_second("1250").ok(), Some(1_250_000_000));
        for bad in ["0", "-1", "1251", "fast", "NaN", "inf", ""] {
            assert!(megabytes_per_second(bad).is_err(), "{bad} was accepted");
        }
        assert_eq!(user_speed_limit("none").ok(), Some(-1));
        assert_eq!(user_speed_limit("Default").ok(), Some(0));
        assert_eq!(user_speed_limit("10").ok(), Some(10_000_000));
        assert_eq!(default_speed_limit("none").ok(), Some(0));
        assert_eq!(default_speed_limit("0").ok(), Some(0));
        assert_eq!(default_speed_limit("2.5").ok(), Some(2_500_000));
        assert!(default_speed_limit("default").is_err());
    }
}
