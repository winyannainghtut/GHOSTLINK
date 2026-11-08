use crate::{profile::ValidatedProfile, storage};
use anyhow::{ensure, Result};
use ghostlink_contracts::{ConnectionState, Status, Stream};
use rand::{rngs::OsRng, RngCore};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    process::Command,
    sync::{mpsc, RwLock},
    task::JoinHandle,
};

#[derive(Default)]
pub struct Snapshot {
    pub status: Status,
    pub connected_since: Option<Instant>,
    pub counter_at: Option<Instant>,
}
impl Snapshot {
    pub fn status(&self) -> Status {
        let mut status = self.status.clone();
        status.connected_duration_seconds = self
            .connected_since
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        status
    }
}
pub type Shared = Arc<RwLock<Snapshot>>;

pub struct Session {
    pub(crate) stop: mpsc::Sender<()>,
    pub task: JoinHandle<()>,
}
impl Session {
    /// Request a stop and wait for the engine teardown to finish.
    ///
    /// Cancel-safe: if the caller is cancelled mid-wait, the session stays owned by the caller
    /// and a later `stop` waits for the same teardown instead of losing track of it. Callers
    /// must drop the session once this returns; awaiting it again is not supported.
    pub async fn stop(&mut self) {
        // A full channel already holds a stop request; a closed one means teardown is done.
        let _ = self.stop.try_send(());
        let _ = (&mut self.task).await;
    }
    pub fn finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// `connected_once` is whether this session has already reached CONNECTED: only such a session
/// is reported as reconnecting, as with the managed worker. Before that, a restart (a retry or
/// the next `remote`) keeps the first attempt in `connecting`.
pub fn apply_event(
    line: &str,
    snapshot: &mut Snapshot,
    connected_once: bool,
) -> Option<&'static str> {
    if let Some(data) = line.strip_prefix(">STATE:") {
        let fields: Vec<_> = data.split(',').collect();
        if fields.len() < 3 {
            return None;
        }
        match fields[1] {
            "CONNECTED" if fields[2] == "SUCCESS" => {
                // A valid assigned address is required; never infer connected from a log string.
                let ip = fields
                    .get(3)
                    .and_then(|x| x.parse::<std::net::IpAddr>().ok())?;
                snapshot.status.status = ConnectionState::Connected;
                snapshot.status.vpn_ip = Some(ip.to_string());
                if let Some(server) = fields
                    .get(4)
                    .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
                {
                    snapshot.status.server = Some((*server).into());
                }
                snapshot.status.last_error = None;
                snapshot.connected_since = Some(Instant::now());
                snapshot.status.receive_bytes_per_second = 0;
                snapshot.status.send_bytes_per_second = 0;
                return Some("connected");
            }
            "RECONNECTING" => {
                snapshot.status.status = if connected_once {
                    ConnectionState::Reconnecting
                } else {
                    ConnectionState::Connecting
                };
                snapshot.status.vpn_ip = None;
                snapshot.connected_since = None;
                snapshot.status.receive_bytes_per_second = 0;
                snapshot.status.send_bytes_per_second = 0;
                return Some("reconnecting");
            }
            "EXITING" => return Some("exiting"),
            _ => {}
        }
    } else if let Some(data) = line.strip_prefix(">BYTECOUNT:") {
        let (rx, tx) = data.trim().split_once(',')?;
        let rx = rx.parse::<u64>().ok()?;
        let tx = tx.parse::<u64>().ok()?;
        let now = Instant::now();
        if let Some(last) = snapshot.counter_at {
            let elapsed = now.duration_since(last).as_secs_f64().max(0.001);
            snapshot.status.receive_bytes_per_second =
                (rx.saturating_sub(snapshot.status.bytes_received) as f64 / elapsed) as u64;
            snapshot.status.send_bytes_per_second =
                (tx.saturating_sub(snapshot.status.bytes_sent) as f64 / elapsed) as u64;
        }
        snapshot.status.bytes_received = rx;
        snapshot.status.bytes_sent = tx;
        snapshot.counter_at = Some(now);
    } else if line.starts_with(">PASSWORD:") {
        return Some(if line.contains("Verification Failed") {
            "authentication_failed"
        } else {
            "credentials_required"
        });
    } else if line.starts_with(">FATAL:") {
        return Some("engine_fatal_error");
    }
    None
}

pub async fn start(
    executable: &Path,
    run_dir: &Path,
    profile: ValidatedProfile,
    shared: Shared,
    driver: &str,
    events: mpsc::Sender<&'static str>,
    connection_timeout: Duration,
) -> Result<Session> {
    ensure!(
        executable.is_absolute() && executable.is_file(),
        "A standalone OpenVPN executable at an absolute path is required"
    );
    storage::private_dir(run_dir)?;
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let password = hex::encode(random);
    let config_path = run_dir.join("active.conf");
    let auth_path = run_dir.join("management.auth");
    // The plaintext profile (with its private key) and the management password are removed
    // again if anything below fails or this start is cancelled; the session keeps them until
    // it ends.
    let config_file = storage::PrivateConfig::write(&config_path, profile.canonical.as_bytes())?;
    let auth_file = storage::PrivateConfig::write(&auth_path, password.as_bytes())?;
    #[cfg(windows)]
    let (listener, address, port) = {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port().to_string();
        (listener, "127.0.0.1".to_string(), port)
    };
    #[cfg(unix)]
    let (listener, address, port) = {
        let path = run_dir.join("engine.sock");
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        (
            listener,
            path.to_string_lossy().to_string(),
            "unix".to_string(),
        )
    };
    let mut command = Command::new(executable);
    command
        .arg("--config")
        .arg(&config_path)
        .args(["--management", &address, &port])
        .arg(&auth_path)
        .args([
            "--management-client",
            "--management-hold",
            "--management-query-passwords",
            "--management-forget-disconnect",
            "--auth-retry",
            "none",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        command.args(["--windows-driver", driver]);
        command.creation_flags(0x08000000);
    }
    #[cfg(unix)]
    let _ = driver;
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("Engine did not start"))?;
    {
        let mut snapshot = shared.write().await;
        *snapshot = Snapshot::default();
        snapshot.status.status = ConnectionState::Connecting;
        snapshot.status.profile = Some(profile.summary.name);
        snapshot.status.protocol = profile.summary.remotes.first().map(|r| r.protocol.clone());
        // Endpoint and assigned address remain unknown until reported by the engine.
    }
    let (stop, mut stop_rx) = mpsc::channel(1);
    let run_dir: PathBuf = run_dir.into();
    let task = tokio::spawn(async move {
        let _runtime_files = (config_file, auth_file);
        let setup = async {
            loop {
                let (stream, _) = listener.accept().await?;
                #[cfg(windows)]
                let authorized = tcp_peer_pid(&stream)
                    .map(|peer| peer == pid)
                    .unwrap_or(false);
                #[cfg(unix)]
                let authorized = stream
                    .peer_cred()
                    .map(|c| c.pid() == Some(pid as i32))
                    .unwrap_or(false);
                if authorized {
                    return Ok::<Stream, anyhow::Error>(Box::new(stream));
                }
            }
        };
        let mut reason = None;
        let mut requested_stop = false;
        // Set once the hold is released: from then on the engine may have changed routes/DNS.
        let mut initialized = false;
        let stream = tokio::select! {
            _ = stop_rx.recv() => { requested_stop = true; None }
            _ = child.wait() => { reason = Some("engine_exited_before_management"); None }
            result = tokio::time::timeout(Duration::from_secs(15), setup) => {
                match result { Ok(Ok(stream)) => Some(stream), _ => { reason = Some("management_connection_failed"); None } }
            }
        };
        if let Some(stream) = stream {
            let mut reader = BufReader::new(stream);
            let auth = format!("{password}\n");
            if reader.get_mut().write_all(auth.as_bytes()).await.is_err() {
                reason = Some("management_connection_failed");
            }
            let deadline = tokio::time::sleep(connection_timeout);
            tokio::pin!(deadline);
            let mut connected_once = false;
            while reason.is_none() {
                tokio::select! {
                    _ = stop_rx.recv() => { requested_stop = true; break; }
                    _ = &mut deadline, if !connected_once => { reason = Some("connection_timeout"); break; }
                    _ = child.wait() => { reason = Some("engine_exited"); break; }
                    line = ghostlink_contracts::read_frame(&mut reader) => {
                        let line = match line { Ok(bytes) => String::from_utf8_lossy(&bytes).trim().to_string(), Err(_) => { reason = Some("management_connection_lost"); break; } };
                        if !initialized && line.contains("SUCCESS: password is correct") {
                            initialized = true;
                            // `hold release` frees only this start. With `--management-hold`
                            // OpenVPN would hold again at every restart (a ping-restart, a
                            // server restart, a TLS error, the next remote) and wait for a
                            // release that never comes, so turn the hold off for those.
                            if reader.get_mut().write_all(b"state on\nbytecount 1\nhold off\nhold release\n").await.is_err() { reason = Some("management_connection_failed"); }
                        } else if initialized {
                            let event = apply_event(&line, &mut *shared.write().await, connected_once);
                            if let Some(event) = event {
                                let _ = events.try_send(event);
                                if event == "connected" { connected_once = true; }
                                if matches!(event, "authentication_failed" | "credentials_required" | "engine_fatal_error") { reason = Some(event); }
                            }
                        }
                    }
                }
            }
            if requested_stop {
                shared.write().await.status.status = ConnectionState::Disconnecting;
                let _ = reader.get_mut().write_all(b"signal SIGTERM\n").await;
                if tokio::time::timeout(Duration::from_secs(10), child.wait())
                    .await
                    .is_err()
                {
                    let _ = child.kill().await;
                    reason = Some("forced_stop_network_cleanup_unverified");
                }
            }
        }
        // A lost reverse management channel also tells OpenVPN to terminate gracefully.
        if !requested_stop
            && tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .is_err()
        {
            let _ = child.kill().await;
            // Same rule as an explicit stop: a forced kill after hold release may leave
            // routes/DNS behind, so block further connects until someone inspects them.
            if initialized {
                reason = Some("forced_stop_network_cleanup_unverified");
            }
        }
        if requested_stop {
            let _ = child.kill().await;
        }
        let _ = child.wait().await;
        let mut snapshot = shared.write().await;
        snapshot.status.status = if reason.is_some() {
            ConnectionState::Failed
        } else {
            ConnectionState::Disconnected
        };
        snapshot.status.last_error = reason.map(String::from);
        snapshot.status.vpn_ip = None;
        snapshot.connected_since = None;
        snapshot.status.receive_bytes_per_second = 0;
        snapshot.status.send_bytes_per_second = 0;
        drop(snapshot);
        let _ = events.try_send(reason.unwrap_or("disconnected"));
        // The profile and password files go with `_runtime_files` when this task ends.
        let _ = std::fs::remove_file(run_dir.join("engine.sock"));
    });
    Ok(Session { stop, task })
}

#[cfg(windows)]
fn tcp_peer_pid(stream: &tokio::net::TcpStream) -> Result<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    let remote = stream.peer_addr()?;
    let local = stream.local_addr()?;
    let mut size = 0u32;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            2,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        // u32 alignment is sufficient for MIB_TCPTABLE_OWNER_PID. The slack covers connections
        // opened between the two calls; without it the engine's own connection could be
        // refused because the table grew.
        let mut data = vec![0u32; size as usize / 4 + 64];
        size = (data.len() * 4) as u32;
        let result = GetExtendedTcpTable(
            data.as_mut_ptr().cast(),
            &mut size,
            0,
            2,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        ensure!(result == 0, "Cannot verify engine TCP identity");
        let table = data.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        ensure!(
            count
                <= (data.len() * 4).saturating_sub(4) / std::mem::size_of::<MIB_TCPROW_OWNER_PID>(),
            "Invalid TCP ownership table"
        );
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
        for row in rows {
            if u16::from_be(row.dwLocalPort as u16) == remote.port()
                && u16::from_be(row.dwRemotePort as u16) == local.port()
                && std::net::Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).is_loopback()
                && std::net::Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()).is_loopback()
            {
                return Ok(row.dwOwningPid);
            }
        }
    }
    anyhow::bail!("Engine socket owner not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_real_valid_state_events_connect() {
        let mut snapshot = Snapshot::default();
        apply_event("Initialization Sequence Completed", &mut snapshot, false);
        assert_eq!(snapshot.status.status, ConnectionState::Disconnected);
        apply_event(
            ">STATE:1,CONNECTED,SUCCESS,garbage,1.2.3.4",
            &mut snapshot,
            false,
        );
        assert_eq!(snapshot.status.status, ConnectionState::Disconnected);
        assert_eq!(
            apply_event(
                ">STATE:1,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194",
                &mut snapshot,
                false
            ),
            Some("connected")
        );
        assert_eq!(snapshot.status.vpn_ip.as_deref(), Some("10.8.0.2"));
        apply_event(">STATE:2,RECONNECTING,network-error", &mut snapshot, true);
        assert_eq!(snapshot.status.status, ConnectionState::Reconnecting);
        assert!(snapshot.status.vpn_ip.is_none());
    }
    #[test]
    fn a_first_attempt_that_restarts_is_still_connecting() {
        let mut snapshot = Snapshot::default();
        snapshot.status.status = ConnectionState::Connecting;
        assert_eq!(
            apply_event(">STATE:3,RECONNECTING,server_poll", &mut snapshot, false),
            Some("reconnecting")
        );
        assert_eq!(snapshot.status.status, ConnectionState::Connecting);
    }
    #[test]
    fn password_events_are_sanitized() {
        let mut snapshot = Snapshot::default();
        assert_eq!(
            apply_event(
                ">PASSWORD:Verification Failed: 'Auth' secret-value",
                &mut snapshot,
                false
            ),
            Some("authentication_failed")
        );
        assert_eq!(
            apply_event(
                ">PASSWORD:Need 'Auth' username/password",
                &mut snapshot,
                false
            ),
            Some("credentials_required")
        );
    }
    #[test]
    fn counters_cannot_underflow() {
        let mut snapshot = Snapshot::default();
        apply_event(">BYTECOUNT:100,200", &mut snapshot, true);
        apply_event(">BYTECOUNT:1,2", &mut snapshot, true);
        assert_eq!(snapshot.status.receive_bytes_per_second, 0);
    }

    #[tokio::test]
    async fn a_failed_start_removes_the_plaintext_profile_and_password() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        // An existing file that is not a program: everything up to the spawn succeeds.
        let engine = dir.path().join("not-openvpn.exe");
        std::fs::write(&engine, "not a program").unwrap();
        let profile = ValidatedProfile {
            canonical: "client\n<key>\ntest-only-private-key\n</key>\n".into(),
            summary: crate::profile::ProfileSummary {
                name: "test".into(),
                kind: "openvpn".into(),
                display_name: "test".into(),
                remotes: vec![],
                tunnel_mode: "split".into(),
                certificate_expires_unix: None,
                sha256: String::new(),
                is_default: false,
            },
        };
        let shared = Arc::new(RwLock::new(Snapshot::default()));
        let (events, _receiver) = mpsc::channel(8);
        let result = start(
            &engine,
            &run,
            profile,
            shared,
            "wintun",
            events,
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_err(), "a text file started as OpenVPN");
        for name in ["active.conf", "management.auth"] {
            assert!(
                !run.join(name).exists(),
                "{name} remained after the failed start"
            );
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn engine_connections_are_matched_to_their_process() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        assert_eq!(tcp_peer_pid(&accepted).unwrap(), std::process::id());
    }
}
