use clap::{Parser, Subcommand};
use ghostlink_contracts::{Action, ConnectionState, Request, Response, SCHEMA_VERSION};
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
    /// Add an Outline access key without exposing credentials in process arguments.
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
    Servers {
        #[command(subcommand)]
        command: ServersCommand,
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
            let content = if let Some(file) = file {
                match std::fs::metadata(file).and_then(|m| {
                    if m.len() <= 16384 {
                        std::fs::read_to_string(file)
                    } else {
                        Err(std::io::Error::other("Key too large"))
                    }
                }) {
                    Ok(value) => value,
                    Err(_) => {
                        return Response::err(
                            "invalid_profile",
                            "Cannot read access key file (maximum 16 KiB)",
                        )
                    }
                }
            } else if *stdin {
                use std::io::{IsTerminal, Read};
                if std::io::stdin().is_terminal() {
                    return Response::err("invalid_request", "Pipe the key to stdin or use --file; interactive terminal entry is disabled to avoid echoing credentials");
                }
                let mut value = String::new();
                if std::io::stdin()
                    .take(16385)
                    .read_to_string(&mut value)
                    .is_err()
                    || value.len() > 16384
                {
                    return Response::err("invalid_profile", "Cannot read access key from stdin");
                }
                value
            } else {
                return Response::err(
                    "invalid_request",
                    "Choose --stdin or --file for the access key",
                );
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
            ProfileCommand::List => Action::ProfileList,
            ProfileCommand::Default { name } => Action::ProfileDefault { name: name.clone() },
            ProfileCommand::Remove { name } => Action::ProfileRemove { name: name.clone() },
        },
        Command::Connect { profile, .. } => Action::Connect {
            profile: profile.clone(),
        },
        Command::Disconnect => Action::Disconnect,
        Command::Status => Action::Status,
        Command::Info => Action::Info,
        Command::Servers { .. } => Action::ServersList,
        Command::Switch { profile, .. } => Action::Switch {
            profile: profile.clone(),
        },
        Command::Autoconnect { command } => Action::Autoconnect {
            enabled: matches!(command, Toggle::Enable),
        },
        Command::Logs { tail } => Action::Logs {
            tail: *tail as usize,
        },
        Command::Doctor => Action::Doctor,
        Command::Agent { command } => match command {
            AgentCommand::Grant { name, control, .. } => Action::AgentGrant {
                name: name.clone(),
                control: *control,
            },
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
                action: Action::Status,
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
