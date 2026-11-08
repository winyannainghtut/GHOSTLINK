use clap::Parser;
use ghostlink_contracts::{Action, Request, SCHEMA_VERSION};
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};
use tokio::io::BufReader;

#[derive(Parser)]
#[command(
    version,
    about = "Restricted Ghostlink stdio MCP server; an explicit agent token is required"
)]
struct Args {
    #[arg(long, env = "GHOSTLINK_ENDPOINT", default_value_t = ghostlink_contracts::default_endpoint())]
    endpoint: String,
    #[arg(long, env = "GHOSTLINK_AGENT_TOKEN_FILE")]
    token_file: PathBuf,
    /// Expose connection tools in addition to read-only tools. The daemon still enforces token scope.
    #[arg(long)]
    allow_control: bool,
}

fn tool(name: &str, description: &str, control: bool, profile: bool) -> Value {
    let schema = if profile {
        json!({"type":"object","properties":{"profile":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+$"}},"required":["profile"],"additionalProperties":false})
    } else {
        json!({"type":"object","properties":{},"additionalProperties":false})
    };
    json!({"name":name,"description":description,"inputSchema":schema,"annotations":{"readOnlyHint":!control,"destructiveHint":control,"openWorldHint":false}})
}
fn tools(control: bool) -> Vec<Value> {
    let mut values = vec![
        tool("vpn_list_profiles", "List already imported profiles. Returns no keys or profile contents.", false, false),
        tool("vpn_status", "Read the actual local VPN connection state for any protocol. Connected does not prove leak prevention.", false, false),
        tool("vpn_diagnostics", "Run local installation diagnostics. No public-IP or external network requests are made.", false, false),
    ];
    if control {
        values.extend([
        tool("vpn_connect", "Request connection to an existing profile. Accepted connecting state is not connection success; poll vpn_status.", true, true),
        tool("vpn_disconnect", "Disconnect the local VPN; this changes the machine's network routing.", true, false),
        tool("vpn_switch", "Disconnect the active VPN and connect an existing profile. There is no kill switch during the transition.", true, true),
    ]);
    }
    values
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::ensure!(
        std::fs::metadata(&args.token_file)?.len() <= 128,
        "Invalid token file"
    );
    let token = std::fs::read_to_string(&args.token_file)?
        .trim()
        .to_string();
    anyhow::ensure!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid token file"
    );
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut initialized = false;
    loop {
        let bytes = match ghostlink_contracts::read_frame(&mut input).await {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        let request: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                ghostlink_contracts::write_frame(&mut output, &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})).await?;
                continue;
            }
        };
        if request.get("id").is_none() {
            continue;
        }
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let mut response = json!({"jsonrpc":"2.0","id":id});
        if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            response["error"] = json!({"code":-32600,"message":"Invalid JSON-RPC request"});
        } else {
            match request["method"].as_str().unwrap_or("") {
                "initialize" => {
                    let requested = request["params"]["protocolVersion"].as_str().unwrap_or("");
                    let version = if ["2025-11-25", "2025-06-18", "2024-11-05"].contains(&requested)
                    {
                        requested
                    } else {
                        "2025-06-18"
                    };
                    response["result"] = json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"ghostlink","version":env!("CARGO_PKG_VERSION")}});
                    initialized = true;
                }
                "ping" => response["result"] = json!({}),
                "tools/list" if initialized => {
                    response["result"] = json!({"tools":tools(args.allow_control)})
                }
                "tools/call" if initialized => {
                    let params = &request["params"];
                    let name = params["name"].as_str().unwrap_or("");
                    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                    let allowed = tools(args.allow_control).iter().any(|t| t["name"] == name);
                    let profile = arguments["profile"].as_str().filter(|s| {
                        !s.is_empty()
                            && s.len() <= 64
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                    });
                    let needs_profile = matches!(name, "vpn_connect" | "vpn_switch");
                    let valid = arguments.as_object().is_some_and(|o| {
                        if needs_profile {
                            o.len() == 1 && profile.is_some()
                        } else {
                            o.is_empty()
                        }
                    });
                    let action = match name {
                        "vpn_list_profiles" => Some(Action::ProfileList {}),
                        "vpn_status" => Some(Action::Status {}),
                        "vpn_diagnostics" => Some(Action::Doctor {}),
                        "vpn_connect" => profile.map(|s| Action::Connect {
                            profile: Some(s.into()),
                        }),
                        "vpn_disconnect" => Some(Action::Disconnect {}),
                        "vpn_switch" => profile.map(|s| Action::Switch { profile: s.into() }),
                        _ => None,
                    };
                    if let Some(action) = action.filter(|_| allowed && valid) {
                        let result = ghostlink_contracts::call(
                            &args.endpoint,
                            Request {
                                schema_version: SCHEMA_VERSION,
                                agent_token: Some(token.clone()),
                                action,
                            },
                            // Match the CLI default: a connect can legitimately wait behind
                            // another operation and a dynamic-key fetch before it is accepted.
                            Duration::from_secs(75),
                        )
                        .await;
                        response["result"] = json!({"content":[{"type":"text","text":serde_json::to_string(&result)?}],"structuredContent":result,"isError":!result.success});
                    } else {
                        response["error"] = json!({"code":-32602,"message":"Unknown, unauthorized or invalid tool call"});
                    }
                }
                _ => {
                    response["error"] = json!({"code":-32601,"message":"Method unavailable or initialization required"})
                }
            }
        }
        ghostlink_contracts::write_frame(&mut output, &response).await?;
    }
    Ok(())
}
