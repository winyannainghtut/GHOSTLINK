//! Real encrypted Shadowsocks interoperability; proxy-only, without changing OS routes.
use ghostlink_engine::{access::Outbound, outline::AccessKey, storage, worker_session};
use serde_json::json;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::{Child, Command},
};

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A port free on TCP and UDP alike: a Shadowsocks server binds both, and exits at startup
/// when either side is taken. The UDP port comes from the system first, because Windows
/// reserves UDP ranges that TCP's free ports often fall into.
async fn free_shared_port() -> u16 {
    let mut last_error = None;
    for _ in 0..200 {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_) => return port,
            Err(error) => last_error = Some(error),
        }
    }
    panic!("no port is free on both TCP and UDP (last: {last_error:?})");
}

#[tokio::test]
#[ignore = "requires GHOSTLINK_TEST_OUTLINE_WORKER: built managed worker"]
async fn managed_worker_gracefully_closes_on_stop_and_parent_eof() {
    let engine = PathBuf::from(
        std::env::var_os("GHOSTLINK_TEST_OUTLINE_WORKER")
            .expect("Set GHOSTLINK_TEST_OUTLINE_WORKER"),
    );
    let dir = tempfile::tempdir().unwrap();
    storage::private_dir(dir.path()).unwrap();
    for explicit_stop in [true, false] {
        let port = free_port().await;
        let path = dir.path().join(if explicit_stop {
            "stop.json"
        } else {
            "eof.json"
        });
        storage::atomic_write(&path, &serde_json::to_vec(&json!({"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":port}],"outbounds":[{"type":"direct"}]})).unwrap()).unwrap();
        let mut command = Command::new(&engine);
        command
            .args(["run", "-c"])
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut event = String::new();
        tokio::time::timeout(Duration::from_secs(10), stderr.read_line(&mut event))
            .await
            .unwrap()
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(event["event"], "started");
        assert!(
            event.get("vpn_ip").is_none(),
            "Proxy-only fixture must not report a TUN address"
        );
        ghostlink_engine::process::verify_listeners(pid, &[port]).unwrap();
        assert!(
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
        );
        let mut control = child.stdin.take().unwrap();
        if explicit_stop {
            control
                .write_all(b"{\"command\":\"stop\"}\n")
                .await
                .unwrap();
        }
        drop(control);
        assert!(tokio::time::timeout(Duration::from_secs(12), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
        let mut closed = String::new();
        stderr.read_line(&mut closed).await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&closed).unwrap()["event"],
            "closed"
        );
        assert!(
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .is_err(),
            "Listener survived worker shutdown"
        );
    }
}

#[tokio::test]
#[ignore = "requires GHOSTLINK_TEST_OUTLINE_WORKER: built managed worker"]
async fn failed_engine_validation_removes_plaintext_configuration() {
    let engine = PathBuf::from(
        std::env::var_os("GHOSTLINK_TEST_OUTLINE_WORKER")
            .expect("Set GHOSTLINK_TEST_OUTLINE_WORKER"),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut key = AccessKey::parse("ss://aes-256-gcm:test-only-secret@127.0.0.1:1").unwrap();
    key.method = "invalid-test-cipher".into();
    let shared = std::sync::Arc::new(tokio::sync::RwLock::new(
        ghostlink_engine::management::Snapshot::default(),
    ));
    let (events, _receiver) = tokio::sync::mpsc::channel(8);
    let result = worker_session::start(
        &engine,
        dir.path(),
        "invalid".into(),
        Outbound::Shadowsocks(key),
        Default::default(),
        Vec::new(),
        shared,
        events,
        Duration::from_secs(3),
    )
    .await;
    assert!(result.is_err());
    assert!(
        !dir.path().join("outline.json").exists(),
        "Plaintext config remained after startup validation failed"
    );
}
fn spawn(engine: &PathBuf, path: &std::path::Path) -> Child {
    let mut command = Command::new(engine);
    command
        .args(["run", "-c"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command.spawn().unwrap()
}

#[tokio::test]
#[ignore = "requires GHOSTLINK_TEST_SING_BOX: unmodified sing-box 1.14.4"]
async fn outline_key_transports_real_http_and_rejects_wrong_password() {
    let engine = PathBuf::from(
        std::env::var_os("GHOSTLINK_TEST_SING_BOX").expect("Set GHOSTLINK_TEST_SING_BOX"),
    );
    let dir = tempfile::tempdir().unwrap();
    storage::private_dir(dir.path()).unwrap();
    let ss_port = free_shared_port().await;
    let server_config = json!({"log":{"disabled":true},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":ss_port,"method":"aes-256-gcm","password":"test-only-randomish-access-credential"}],"outbounds":[{"type":"direct"}]});
    let server_path = dir.path().join("server.json");
    storage::atomic_write(&server_path, &serde_json::to_vec(&server_config).unwrap()).unwrap();
    let mut server = spawn(&engine, &server_path);
    let proxy_port = free_port().await;
    let api_port = free_port().await;
    let key = AccessKey::parse(&format!(
        "ss://aes-256-gcm:test-only-randomish-access-credential@127.0.0.1:{ss_port}#Loopback"
    ))
    .unwrap();
    let config = worker_session::config(
        &Outbound::Shadowsocks(key),
        proxy_port,
        api_port,
        "local-test-controller-password",
        false,
        &Default::default(),
    );
    let client_path = dir.path().join("client.json");
    storage::atomic_write(&client_path, &serde_json::to_vec(&config).unwrap()).unwrap();
    let mut client = spawn(&engine, &client_path);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let receiver = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0; 4096];
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..count])
            .starts_with("GET /encrypted-through-outline-key"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}"))
        .unwrap()
        .basic_auth("ghostlink", "local-test-controller-password");
    let http = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut success = false;
    for _ in 0..30 {
        if let Ok(response) = http
            .get(format!(
                "http://127.0.0.1:{target_port}/encrypted-through-outline-key"
            ))
            .send()
            .await
        {
            if response.status().as_u16() == 204 {
                success = true;
                break;
            }
        }
        assert!(
            server.try_wait().unwrap().is_none(),
            "Shadowsocks server failed to start"
        );
        assert!(
            client.try_wait().unwrap().is_none(),
            "Client configuration rejected"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        success,
        "Actual encrypted traffic did not traverse the Shadowsocks server"
    );
    receiver.await.unwrap();
    let api = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(
        api.get(format!("http://127.0.0.1:{api_port}/connections"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    let stats: serde_json::Value = api
        .get(format!("http://127.0.0.1:{api_port}/connections"))
        .bearer_auth("local-test-controller-password")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(stats["uploadTotal"].as_u64().unwrap() > 0);
    client.kill().await.unwrap();
    client.wait().await.unwrap();
    let wrong = AccessKey::parse(&format!(
        "ss://aes-256-gcm:incorrect-key-password@127.0.0.1:{ss_port}"
    ))
    .unwrap();
    let wrong_path = dir.path().join("wrong.json");
    storage::atomic_write(
        &wrong_path,
        &serde_json::to_vec(&worker_session::config(
            &Outbound::Shadowsocks(wrong),
            proxy_port,
            api_port,
            "local-test-controller-password",
            false,
            &Default::default(),
        ))
        .unwrap(),
    )
    .unwrap();
    let mut wrong_client = spawn(&engine, &wrong_path);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let forbidden_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forbidden_port = forbidden_target.local_addr().unwrap().port();
    let rejected = http
        .get(format!(
            "http://127.0.0.1:{forbidden_port}/invalid-credential"
        ))
        .send()
        .await;
    assert!(rejected
        .map(|response| !response.status().is_success())
        .unwrap_or(true));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), forbidden_target.accept())
            .await
            .is_err(),
        "Incorrect key reached the destination"
    );
    wrong_client.kill().await.unwrap();
    let _ = wrong_client.wait().await;
    server.kill().await.unwrap();
    let _ = server.wait().await;
}
