//! Administration of managed Ghostlink servers. Management keys are sealed in service state and
//! never returned. Calls go to the network without holding the service lock, so a slow server
//! cannot stall status, connect or disconnect requests.

use crate::{Daemon, ManagedServer};
use anyhow::Result;
use ghostlink_contracts::{Action, Request, Response, ServerOp};
use ghostlink_engine::{
    profile,
    server_admin::{self, AdminError, ManagementKey},
    storage,
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const MAX_MANAGED_SERVERS: usize = 32;

/// Actions that reach a remote server and are served by [`handle`].
pub(crate) fn is_remote(action: &Action) -> bool {
    matches!(
        action,
        Action::ManagedServerAdd { .. } | Action::ServerCall { .. }
    )
}

enum Plan {
    Add {
        name: String,
        key: ManagementKey,
        replace: bool,
    },
    Call {
        key: ManagementKey,
        op: ServerOp,
        client: server_admin::AdminClient,
    },
}

fn outcome(response: &Response) -> &str {
    response
        .error
        .as_ref()
        .map(|e| e.code.as_str())
        .unwrap_or("success")
}

fn admin_error(error: AdminError) -> Response {
    let code = match &error {
        AdminError::Unreachable => "server_unreachable",
        AdminError::IdentityMismatch => "server_identity_mismatch",
        AdminError::NotGhostlink { .. } => "unsupported",
        AdminError::Rejected { status: 404, .. } => "not_found",
        AdminError::Rejected { status, .. } if *status < 500 => "invalid_request",
        AdminError::Rejected { .. } | AdminError::InvalidResponse => "server_error",
        AdminError::Invalid(_) => "invalid_request",
    };
    Response::err(code, &error.to_string())
}

fn text(value: &Value, limit: usize, fallback: &str) -> String {
    let text: String = value
        .as_str()
        .unwrap_or(fallback)
        .chars()
        .filter(|c| !c.is_control())
        .take(limit)
        .collect();
    if text.trim().is_empty() {
        fallback.into()
    } else {
        text
    }
}

pub(crate) async fn handle(daemon: &Mutex<Daemon>, request: Request) -> Response {
    let operation = request.action.name();
    // 1. Authorize, audit and read the sealed key while holding the lock only briefly.
    let (actor, plan) = {
        let guard = daemon.lock().await;
        let actor = match guard.authorize(&request) {
            Ok(actor) => actor,
            Err(response) => {
                let _ = guard.audit("unauthorized", operation, "denied");
                return response;
            }
        };
        if guard.audit(&actor, operation, "accepted").is_err() {
            return Response::err("internal", "Audit storage is unavailable");
        }
        match guard.plan(request.action) {
            Ok(plan) => (actor, plan),
            Err(response) => {
                let _ = guard.audit(&actor, operation, outcome(&response));
                return response;
            }
        }
    };
    // 2. The network call, unlocked.
    let response = match plan {
        Plan::Add { name, key, replace } => match server_admin::probe(&key).await {
            Err(error) => admin_error(error),
            Ok(info) => daemon
                .lock()
                .await
                .finish_add(name, key, replace, &info)
                .unwrap_or_else(|_| Response::err("internal", "Service storage failed")),
        },
        Plan::Call { key, op, client } => match client.call(&key, &op).await {
            Err(error) => admin_error(error),
            Ok(value) => match op {
                // 3. Saving a new key on this device needs the lock again.
                ServerOp::KeyCreate {
                    import_as: Some(local),
                    ..
                } => daemon.lock().await.import_issued(local, value).await,
                _ => Response::ok(value),
            },
        },
    };
    let _ = daemon
        .lock()
        .await
        .audit(&actor, operation, outcome(&response));
    response
}

impl ManagedServer {
    fn key(&self) -> Result<ManagementKey> {
        Ok(serde_json::from_slice(&storage::unseal(&self.sealed_key)?)?)
    }
}

impl Daemon {
    fn plan(&self, action: Action) -> Result<Plan, Response> {
        match action {
            Action::ManagedServerAdd {
                name,
                management_key,
                replace,
            } => {
                if !profile::valid_name(&name) {
                    return Err(Response::err(
                        "invalid_request",
                        "Server ID must contain 1-64 letters, digits, hyphens or underscores",
                    ));
                }
                let exists = self.store.managed_servers.contains_key(&name);
                if exists && !replace {
                    return Err(Response::err("invalid_request", "A managed server with this ID already exists; choose another ID or explicitly replace it"));
                }
                if !exists && self.store.managed_servers.len() >= MAX_MANAGED_SERVERS {
                    return Err(Response::err(
                        "invalid_request",
                        "At most 32 managed servers may be saved",
                    ));
                }
                // Parse errors are fixed messages; they never echo the key.
                let key = ManagementKey::parse(&management_key)
                    .map_err(|e| Response::err("invalid_request", &e.to_string()))?;
                Ok(Plan::Add { name, key, replace })
            }
            Action::ServerCall { server, op } => {
                let managed =
                    self.store.managed_servers.get(&server).ok_or_else(|| {
                        Response::err("not_found", "No managed server has this ID")
                    })?;
                let key = managed.key().map_err(|_| {
                    Response::err("internal", "The saved management key could not be read")
                })?;
                if let ServerOp::KeyCreate {
                    import_as: Some(local),
                    ..
                } = &op
                {
                    // Check before the server creates a key we could not save.
                    if !profile::valid_name(local) {
                        return Err(Response::err("invalid_request", "The local server ID must contain 1-64 letters, digits, hyphens or underscores"));
                    }
                    if self.store.profiles.contains_key(local) {
                        return Err(Response::err("invalid_request", "A VPN server with this ID already exists on this device; choose another ID"));
                    }
                    if self.store.profiles.len() >= 32 {
                        return Err(Response::err(
                            "invalid_request",
                            "At most 32 servers may be saved",
                        ));
                    }
                }
                // Reuse this server's client while its key is unchanged.
                let identity = format!("{}|{}", key.api_url, key.cert_sha256);
                let mut clients = self
                    .admin_clients
                    .lock()
                    .map_err(|_| Response::err("internal", "Service state is unavailable"))?;
                let client = match clients.get(&server) {
                    Some((known, client)) if *known == identity => client.clone(),
                    _ => {
                        let client = server_admin::AdminClient::new(&key).map_err(admin_error)?;
                        clients.insert(server.clone(), (identity, client.clone()));
                        client
                    }
                };
                Ok(Plan::Call { key, op, client })
            }
            _ => Err(Response::err(
                "internal",
                "Not a server administration action",
            )),
        }
    }

    fn finish_add(
        &mut self,
        name: String,
        key: ManagementKey,
        replace: bool,
        info: &Value,
    ) -> Result<Response> {
        // Another request may have saved this ID, or other servers, while the server was being
        // checked.
        let exists = self.store.managed_servers.contains_key(&name);
        if exists && !replace {
            return Ok(Response::err(
                "invalid_request",
                "A managed server with this ID already exists; choose another ID or explicitly replace it",
            ));
        }
        if !exists && self.store.managed_servers.len() >= MAX_MANAGED_SERVERS {
            return Ok(Response::err(
                "invalid_request",
                "At most 32 managed servers may be saved",
            ));
        }
        let (host, port) = key.host_port();
        let managed = ManagedServer {
            sealed_key: storage::seal(&serde_json::to_vec(&key)?)?,
            host,
            port,
            server_name: text(&info["name"], 80, "Ghostlink server"),
            version: text(&info["version"], 40, ""),
            added_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        let summary = managed.summary(&name);
        let mut next = self.store.clone();
        next.managed_servers.insert(name, managed);
        self.commit(next)?;
        let mut summary = summary;
        summary["protocols"] = info["protocols"].clone();
        Ok(Response::ok(summary))
    }

    /// Saves a key the server just issued as a VPN server on this device.
    async fn import_issued(&mut self, local: String, mut issued: Value) -> Response {
        let Some(access_key) = issued
            .get("access_key")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Response::err("server_error", "The server returned no access key");
        };
        match self.import_credential(local, access_key, false).await {
            Ok(response) if response.success => issued["imported"] = json!(response.data),
            // The key exists on the server either way; report it so it is not lost.
            Ok(response) => issued["import_error"] = json!(response.error.map(|e| e.message)),
            Err(_) => issued["import_error"] = json!("Service storage failed"),
        }
        Response::ok(issued)
    }
}

impl ManagedServer {
    pub(crate) fn summary(&self, name: &str) -> Value {
        let endpoint = format!("{}:{}", self.host, self.port);
        json!({
            "name": name,
            "endpoint": endpoint,
            "server_name": self.server_name,
            "version": self.version,
            "added_unix": self.added_unix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_that_overlap_cannot_pass_the_server_limit() {
        // Both adds were planned while 31 servers were saved; the first one filled the list.
        let mut daemon = crate::test_daemon("server-limit");
        for n in 0..MAX_MANAGED_SERVERS {
            daemon.store.managed_servers.insert(
                format!("s{n}"),
                ManagedServer {
                    sealed_key: vec![],
                    host: "192.0.2.1".into(),
                    port: 8443,
                    server_name: "test".into(),
                    version: String::new(),
                    added_unix: 0,
                },
            );
        }
        let key = || {
            ManagementKey::parse(&format!(
                r#"{{"apiUrl":"https://192.0.2.1:8443/abcdefghijklmnop0123","certSha256":"{}"}}"#,
                "ab".repeat(32)
            ))
            .unwrap()
        };
        let late = daemon
            .finish_add("late".into(), key(), false, &json!({}))
            .unwrap();
        assert_eq!(late.error.unwrap().code, "invalid_request");
        assert_eq!(daemon.store.managed_servers.len(), MAX_MANAGED_SERVERS);
        // Replacing a saved server is still possible at the limit.
        assert!(
            daemon
                .finish_add("s0".into(), key(), true, &json!({}))
                .unwrap()
                .success
        );
        let _ = std::fs::remove_dir_all(&daemon.args.data_dir);
    }
}
