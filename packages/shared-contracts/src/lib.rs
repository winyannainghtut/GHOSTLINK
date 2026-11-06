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
    AccessKeyImport { name: String, access_key: String },
    ProfileRename { name: String, display_name: String },
    ProfileImport { name: String, content: String },
    ProfileList,
    ProfileDefault { name: String },
    ProfileRemove { name: String },
    Connect { profile: Option<String> },
    Disconnect,
    Switch { profile: String },
    Status,
    Info,
    ServersList,
    Autoconnect { enabled: bool },
    Logs { tail: usize },
    Doctor,
    AgentGrant { name: String, control: bool },
    AgentRevoke { name: String },
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
        r"\\.\pipe\myvpn".into()
    } else {
        "/run/myvpn/control.sock".into()
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

#[cfg(windows)]
fn verify_pipe_server(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::*,
        Security::*,
        System::{Pipes::GetNamedPipeServerProcessId, Threading::*},
    };
    unsafe fn sid(token: HANDLE) -> anyhow::Result<Vec<u8>> {
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
        }
        let mut data = vec![0u8; size as usize];
        anyhow::ensure!(
            unsafe {
                GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size)
            } != 0,
            "Cannot inspect pipe server identity"
        );
        Ok(data)
    }
    unsafe {
        let mut pid = 0;
        anyhow::ensure!(
            GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) != 0,
            "Cannot identify pipe server"
        );
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        anyhow::ensure!(!process.is_null(), "Cannot inspect pipe server");
        let mut server_token = std::ptr::null_mut();
        let mut own_token = std::ptr::null_mut();
        let ok = OpenProcessToken(process, TOKEN_QUERY, &mut server_token) != 0
            && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own_token) != 0;
        CloseHandle(process);
        let result = (|| {
            anyhow::ensure!(ok, "Cannot inspect pipe server token");
            let server = sid(server_token)?;
            let own = sid(own_token)?;
            let server_sid = (*(server.as_ptr().cast::<TOKEN_USER>())).User.Sid;
            let own_sid = (*(own.as_ptr().cast::<TOKEN_USER>())).User.Sid;
            anyhow::ensure!(
                EqualSid(server_sid, own_sid) != 0
                    || IsWellKnownSid(server_sid, WinLocalSystemSid) != 0,
                "Pipe server must run as this user or SYSTEM"
            );
            Ok(())
        })();
        if !server_token.is_null() {
            CloseHandle(server_token);
        }
        if !own_token.is_null() {
            CloseHandle(own_token);
        }
        result
    }
}

pub async fn call(endpoint: &str, request: Request, timeout: std::time::Duration) -> Response {
    let operation = async {
        let stream = connect(endpoint).await.map_err(|_| {
            Response::err(
                "daemon_unavailable",
                "Cannot reach the authorized local MyVPN service",
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
            content: "".into()
        }
        .agent_allowed(true));
        assert!(!Action::Disconnect.agent_allowed(false));
        assert!(Action::Status.agent_allowed(false));
    }
}
