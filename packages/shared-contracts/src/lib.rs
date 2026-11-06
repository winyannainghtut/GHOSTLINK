use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    #[serde(default)]
    pub agent_token: Option<String>,
    pub action: Action,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// An existing server ID is rejected unless `replace` is set, so a stale client view can
    /// never silently overwrite a saved credential.
    AccessKeyImport {
        name: String,
        access_key: String,
        #[serde(default)]
        replace: bool,
    },
    ProfileRename {
        name: String,
        display_name: String,
    },
    ProfileImport {
        name: String,
        content: String,
        #[serde(default)]
        replace: bool,
    },
    ProfileList,
    ProfileDefault {
        name: String,
    },
    ProfileRemove {
        name: String,
    },
    Connect {
        profile: Option<String>,
    },
    Disconnect,
    Switch {
        profile: String,
    },
    Status,
    Info,
    ServersList,
    Autoconnect {
        enabled: bool,
    },
    Logs {
        tail: usize,
    },
    Doctor,
    AgentGrant {
        name: String,
        control: bool,
    },
    AgentRevoke {
        name: String,
    },
    /// Without `profile`, the global policy; with it, that server's override (if any).
    RoutingPolicyGet {
        #[serde(default)]
        profile: Option<String>,
    },
    /// `policy: None` clears a server override, or resets the global policy to full tunnel.
    RoutingPolicySet {
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        policy: Option<RoutingPolicy>,
    },
    /// Saves a Ghostlink server's management key (sealed; never returned) after checking that
    /// the server answers with the pinned certificate.
    ManagedServerAdd {
        name: String,
        management_key: String,
        #[serde(default)]
        replace: bool,
    },
    ManagedServerList,
    ManagedServerRemove {
        name: String,
    },
    /// One typed administration call to a managed server. The service makes the pinned HTTPS
    /// request itself, so the management key never leaves it.
    ServerCall {
        server: String,
        op: ServerOp,
    },
}

/// Administration operations on a managed Ghostlink server. IDs are the server's numeric IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerOp {
    Info,
    Update {
        patch: ServerPatch,
    },
    UsersList,
    UserCreate {
        change: UserChange,
    },
    UserUpdate {
        user: String,
        change: UserChange,
    },
    UserDelete {
        user: String,
    },
    KeysList {
        user: String,
    },
    /// With `import_as`, the new key is also saved on this device under that server ID.
    KeyCreate {
        user: String,
        protocol: String,
        #[serde(default)]
        import_as: Option<String>,
    },
    KeyDelete {
        user: String,
        key: String,
    },
    RulesGet,
    RulesSet {
        rules: TrafficRules,
    },
    Metrics,
    /// Live speeds, open connections, online users and server health.
    Live,
    /// Recorded traffic: `range` is 24h, 7d, 30d or 90d; without `user`, everyone.
    Stats {
        #[serde(default)]
        user: Option<String>,
        range: String,
    },
    /// Addresses users connected from (last 30 days).
    Clients {
        #[serde(default)]
        user: Option<String>,
    },
    /// A key's QR code: `format` svg or text; `content` auto, key or conf.
    KeyQr {
        user: String,
        key: String,
        format: String,
        #[serde(default)]
        content: Option<String>,
    },
    /// A self-contained HTML page with all of a user's keys, QR codes and app help.
    Kit {
        user: String,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The public IP or DNS name written into new keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless_handshake: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<std::collections::BTreeMap<String, ProtocolPatch>>,
    /// Record per-user top sites; turning it off deletes them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_stats: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_max_mb: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// 0 removes the limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_limit_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exempt_from_global_rules: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<TrafficRules>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset_usage: bool,
}

/// Traffic a server blocks, for everyone or for one user.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficRules {
    /// Sites, matched with their subdomains.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// IP addresses or CIDR ranges.
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    /// Ports ("25") or ranges ("6881-6889").
    #[serde(default)]
    pub blocked_ports: Vec<String>,
    #[serde(default)]
    pub block_bittorrent: bool,
    /// Outgoing mail on port 25.
    #[serde(default)]
    pub block_smtp: bool,
}

/// Client split tunneling. Applied by the managed worker at the next connection; OpenVPN
/// profiles ignore it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    #[serde(default)]
    pub mode: SplitMode,
    /// Sites matched with their subdomains, e.g. `example.com`.
    #[serde(default)]
    pub domains: Vec<String>,
    /// IPv4/IPv6 CIDR ranges.
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    /// Executable names (`chrome.exe`) or absolute paths.
    #[serde(default)]
    pub apps: Vec<String>,
    /// Keep private-network destinations (LAN, printers) off the tunnel.
    #[serde(default)]
    pub lan_direct: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitMode {
    /// Everything uses the VPN.
    #[default]
    Full,
    /// Listed sites, ranges and apps go direct; everything else uses the VPN.
    Bypass,
    /// Only listed sites, ranges and apps use the VPN.
    Only,
}

impl Action {
    pub fn name(&self) -> &'static str {
        match self {
            Self::AccessKeyImport { .. } => "access_key_import",
            Self::ProfileRename { .. } => "profile_rename",
            Self::ProfileImport { .. } => "profile_import",
            Self::ProfileList => "profile_list",
            Self::ProfileDefault { .. } => "profile_default",
            Self::ProfileRemove { .. } => "profile_remove",
            Self::Connect { .. } => "connect",
            Self::Disconnect => "disconnect",
            Self::Switch { .. } => "switch",
            Self::Status => "status",
            Self::Info => "info",
            Self::ServersList => "servers_list",
            Self::Autoconnect { .. } => "autoconnect",
            Self::Logs { .. } => "logs",
            Self::Doctor => "doctor",
            Self::AgentGrant { .. } => "agent_grant",
            Self::AgentRevoke { .. } => "agent_revoke",
            Self::RoutingPolicyGet { .. } => "routing_policy_get",
            Self::RoutingPolicySet { .. } => "routing_policy_set",
            Self::ManagedServerAdd { .. } => "managed_server_add",
            Self::ManagedServerList => "managed_server_list",
            Self::ManagedServerRemove { .. } => "managed_server_remove",
            Self::ServerCall { op, .. } => op.name(),
        }
    }
    pub fn agent_allowed(&self, control: bool) -> bool {
        matches!(
            self,
            Self::Status | Self::Info | Self::Doctor | Self::ProfileList | Self::ServersList
        ) || (control
            && matches!(
                self,
                Self::Connect { .. } | Self::Disconnect | Self::Switch { .. }
            ))
    }
}

impl ServerOp {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Info => "server_info",
            Self::Update { .. } => "server_update",
            Self::UsersList => "server_users_list",
            Self::UserCreate { .. } => "server_user_create",
            Self::UserUpdate { .. } => "server_user_update",
            Self::UserDelete { .. } => "server_user_delete",
            Self::KeysList { .. } => "server_keys_list",
            Self::KeyCreate { .. } => "server_key_create",
            Self::KeyDelete { .. } => "server_key_delete",
            Self::RulesGet => "server_rules_get",
            Self::RulesSet { .. } => "server_rules_set",
            Self::Metrics => "server_metrics",
            Self::Live => "server_live",
            Self::Stats { .. } => "server_stats",
            Self::Clients { .. } => "server_clients",
            Self::KeyQr { .. } => "server_key_qr",
            Self::Kit { .. } => "server_kit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema_version: u32,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl Response {
    pub fn ok(value: impl Serialize) -> Self {
        match serde_json::to_value(value) {
            Ok(data) => Self {
                schema_version: SCHEMA_VERSION,
                success: true,
                data: Some(data),
                error: None,
            },
            Err(_) => Self::err("internal", "Could not encode response"),
        }
    }
    pub fn err(code: &str, message: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
    pub fn exit_code(&self) -> i32 {
        match self.error.as_ref().map(|e| e.code.as_str()) {
            None => 0,
            Some("invalid_request" | "invalid_profile" | "not_found") => 2,
            Some("permission_denied") => 3,
            Some("daemon_unavailable" | "engine_unavailable" | "unsupported") => 4,
            Some("timeout") => 5,
            Some("busy") => 6,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Status {
    pub status: ConnectionState,
    pub profile: Option<String>,
    pub server: Option<String>,
    pub vpn_ip: Option<String>,
    pub protocol: Option<String>,
    pub connected_duration_seconds: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub receive_bytes_per_second: u64,
    pub send_bytes_per_second: u64,
    pub last_error: Option<String>,
}

pub trait IpcStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IpcStream for T {}
pub type Stream = Box<dyn IpcStream>;

pub fn default_endpoint() -> String {
    if cfg!(windows) {
        r"\\.\pipe\ghostlink".into()
    } else {
        "/run/ghostlink/control.sock".into()
    }
}

pub async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        anyhow::ensure!(!buf.is_empty(), "IPC peer closed before a complete frame");
        let count = buf
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buf.len());
        anyhow::ensure!(
            result.len() + count <= MAX_FRAME,
            "IPC frame exceeds size limit"
        );
        let done = buf[count - 1] == b'\n';
        result.extend_from_slice(&buf[..count]);
        reader.consume(count);
        if done {
            return Ok(result);
        }
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    data: &T,
) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(data)?;
    anyhow::ensure!(bytes.len() < MAX_FRAME, "IPC frame exceeds size limit");
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn connect(endpoint: &str) -> anyhow::Result<Stream> {
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        anyhow::ensure!(
            endpoint.starts_with(r"\\.\pipe\") && !endpoint[9..].contains(['\\', '/']),
            "Only local named pipes are allowed"
        );
        loop {
            match ClientOptions::new()
                .security_qos_flags(0x0001_0000)
                .open(endpoint)
            {
                Ok(pipe) => {
                    verify_pipe_server(&pipe)?;
                    return Ok(Box::new(pipe));
                }
                Err(e) if e.raw_os_error() == Some(231) => {
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    #[cfg(unix)]
    {
        Ok(Box::new(tokio::net::UnixStream::connect(endpoint).await?))
    }
}

/// Refuses a pipe that another, unprivileged account could have created (pipe squatting).
///
/// The pipe's owner identifies who created it, and any client may read it. A service running
/// as SYSTEM creates objects owned by BUILTIN\Administrators (its default owner) or SYSTEM.
/// A development service owns its pipe as the user who runs it. A process can only make
/// itself the owner of an object if that SID is its own user or an enabled owner group, so an
/// ordinary process cannot fake SYSTEM or Administrators ownership. Opening the server
/// process's token instead would fail for standard users when the service runs as SYSTEM.
#[cfg(windows)]
fn verify_pipe_server(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        System::Threading::*,
    };
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = GetSecurityInfo(
            pipe.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        anyhow::ensure!(
            status == ERROR_SUCCESS && !owner.is_null(),
            "Cannot inspect the pipe owner"
        );
        let result = (|| {
            if IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            {
                return Ok(());
            }
            let mut token = std::ptr::null_mut();
            anyhow::ensure!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
                "Cannot inspect this process"
            );
            let mut size = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
            let mut data = vec![0u8; size as usize];
            let read =
                GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size);
            CloseHandle(token);
            anyhow::ensure!(read != 0, "Cannot inspect this process");
            let own = (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid;
            anyhow::ensure!(
                EqualSid(owner, own) != 0,
                "The pipe was not created by SYSTEM, an administrator or this user"
            );
            Ok(())
        })();
        LocalFree(descriptor as HLOCAL);
        result
    }
}

pub async fn call(endpoint: &str, request: Request, timeout: std::time::Duration) -> Response {
    let operation = async {
        let stream = connect(endpoint).await.map_err(|_| {
            Response::err(
                "daemon_unavailable",
                "Cannot reach the authorized local Ghostlink service",
            )
        })?;
        let mut reader = BufReader::new(stream);
        write_frame(reader.get_mut(), &request)
            .await
            .map_err(|_| Response::err("daemon_unavailable", "Could not send service request"))?;
        let bytes = read_frame(&mut reader)
            .await
            .map_err(|_| Response::err("daemon_unavailable", "Incomplete service response"))?;
        let response: Response = serde_json::from_slice(&bytes)
            .map_err(|_| Response::err("internal", "Invalid service response"))?;
        if response.schema_version != SCHEMA_VERSION
            || response.success != response.error.is_none()
            || response.success != response.data.is_some()
        {
            return Err(Response::err("internal", "Incompatible service response"));
        }
        Ok(response)
    };
    match tokio::time::timeout(timeout, operation).await {
        Ok(Ok(r)) | Ok(Err(r)) => r,
        Err(_) => Response::err(
            "timeout",
            "Command timed out; use status to inspect any operation already accepted by the daemon",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oversized_frame_and_truncated_frames_are_rejected() {
        let bytes = vec![b'x'; MAX_FRAME + 1];
        assert!(read_frame(&mut &bytes[..]).await.is_err());
        assert!(read_frame(&mut &b"{}"[..]).await.is_err());
    }
    #[test]
    fn agents_cannot_import_or_grant() {
        assert!(!Action::AgentGrant {
            name: "x".into(),
            control: true
        }
        .agent_allowed(true));
        assert!(!Action::ProfileImport {
            name: "x".into(),
            content: "".into(),
            replace: true
        }
        .agent_allowed(true));
        assert!(!Action::Disconnect.agent_allowed(false));
        assert!(Action::Status.agent_allowed(false));
    }
    #[test]
    fn agents_cannot_manage_servers() {
        let actions = [
            Action::ManagedServerAdd {
                name: "x".into(),
                management_key: "{}".into(),
                replace: false,
            },
            Action::ManagedServerList,
            Action::ManagedServerRemove { name: "x".into() },
            Action::ServerCall {
                server: "x".into(),
                op: ServerOp::Info,
            },
            Action::ServerCall {
                server: "x".into(),
                op: ServerOp::Metrics,
            },
            Action::ServerCall {
                server: "x".into(),
                op: ServerOp::Live,
            },
            Action::ServerCall {
                server: "x".into(),
                op: ServerOp::Kit { user: "1".into() },
            },
        ];
        for action in actions {
            assert!(!action.agent_allowed(true), "{}", action.name());
        }
    }
    #[test]
    fn server_ops_round_trip_and_refuse_unknown_fields() {
        let op: ServerOp = serde_json::from_str(
            r#"{"op":"user_update","user":"3","change":{"enabled":false,"rules":{"blocked_domains":["example.com"]}}}"#,
        )
        .unwrap();
        let text = serde_json::to_string(&op).unwrap();
        assert!(
            text.contains(r#""enabled":false"#)
                && !text.contains("reset_usage")
                && !text.contains("name")
        );
        assert!(
            serde_json::from_str::<ServerOp>(r#"{"op":"user_delete","user":"1","path":"/x"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<ServerOp>(r#"{"op":"raw","method":"GET"}"#).is_err());
    }
}
