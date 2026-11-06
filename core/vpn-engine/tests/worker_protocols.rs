//! Real managed-worker checks for the WireGuard, AmneziaWG and VLESS outbounds. Proxy-only:
//! no OS routes change. Enable with GHOSTLINK_TEST_OUTLINE_WORKER=<built ghostlink-tunnel>.
use base64::{engine::general_purpose::STANDARD, Engine};
use ghostlink_engine::{
    access::Outbound, outline::AccessKey, storage, vless::VlessKey, wireguard, worker_session,
};
use serde_json::json;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::{Child, Command},
};

// Test-only X25519 key pairs; never used outside these local loopback tests.
const SERVER_PRIVATE: &str = "uGrEIaWy6VOLGQnn0T+yQlK5buL2Oqq2/uUSeRGNmUs=";
const SERVER_PUBLIC: &str = "sbMjRh86HBqetQmA4xqU1L/92yeppL84NPcS9nSohC4=";
const CLIENT_PRIVATE: &str = "KLZXkasr0PAF8dcnyz3zAE2OGEpjZkxzsL11TncwRE0=";
const CLIENT_PUBLIC: &str = "Vyfa2s2POMcxUlucFhFTCA+LeJ60W89nrZp2AepKJm8=";
const SECRET: &str = "local-test-controller-password";

fn worker() -> PathBuf {
    PathBuf::from(
        std::env::var_os("GHOSTLINK_TEST_OUTLINE_WORKER")
            .expect("Set GHOSTLINK_TEST_OUTLINE_WORKER"),
    )
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn command(args: &[&str], path: &std::path::Path) -> Command {
    let mut command = Command::new(worker());
    command.args(args).arg(path).kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command
}

/// A running worker plus every credential-free event it has written to stderr. The pipe is
/// drained for the worker's whole life, as the daemon does; dropping it early would make the
/// worker's final event a broken-pipe write.
struct Worker {
    child: Child,
    events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Worker {
    /// Closes the control pipe and requires a clean exit, reporting the worker's own events.
    async fn stop(mut self, name: &str) {
        drop(self.child.stdin.take());
        let status = tokio::time::timeout(Duration::from_secs(12), self.child.wait()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let events = self.events.lock().unwrap().join(" | ");
        match status {
            Ok(Ok(status)) if status.success() => {}
            other => panic!("{name} worker did not stop cleanly ({other:?}); events: {events}"),
        }
    }
}

/// Starts `worker run` and waits for its "started" event.
async fn run_worker(path: &std::path::Path) -> Worker {
    let mut child = command(&["run", "-c"], path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let first = tokio::time::timeout(Duration::from_secs(15), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap_or_default();
    let event: serde_json::Value = serde_json::from_str(&first).unwrap_or_default();
    assert_eq!(event["event"], "started", "worker did not start: {first}");
    let events = std::sync::Arc::new(std::sync::Mutex::new(vec![first]));
    let sink = events.clone();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            sink.lock().unwrap().push(line);
        }
    });
    Worker { child, events }
}

/// Minimal HTTP server on loopback answering every request with `reply`.
async fn serve_http(reply: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    port
}

fn conf(server_port: u16, allowed: &str, interface_extra: &str, keepalive: &str) -> String {
    format!("[Interface]\nPrivateKey = {CLIENT_PRIVATE}\nAddress = 10.99.0.2/32\nDNS = 10.99.0.1\n{interface_extra}\n[Peer]\nPublicKey = {SERVER_PUBLIC}\nEndpoint = 127.0.0.1:{server_port}\nAllowedIPs = {allowed}\nPersistentKeepalive = {keepalive}\n")
}

const LEGACY: &str = "Jc = 3\nJmin = 10\nJmax = 30\nS1 = 15\nS2 = 18\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890";

fn awg2() -> String {
    format!(
        "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 24\nS2 = 28\nS3 = 16\nS4 = 12\nH1 = 100000-199999\nH2 = 200000-299999\nH3 = 300000-399999\nH4 = 400000-499999\nI1 = <b 0x0102030405><r 12><t>\nHeaderProtectionKey = {}\nRandomTrailers = off",
        STANDARD.encode([0xab; 32])
    )
}

#[tokio::test]
#[ignore = "requires GHOSTLINK_TEST_OUTLINE_WORKER: built managed worker"]
async fn generated_configs_for_every_protocol_pass_worker_validation() {
    let dir = tempfile::tempdir().unwrap();
    storage::private_dir(dir.path()).unwrap();
    let pbk = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";
    let id = "8f3d2c1b-1a2b-4c3d-9e8f-0123456789ab";
    let outbounds = vec![
        ("wireguard", Outbound::WireGuard(wireguard::parse(&conf(51820, "0.0.0.0/0, ::/0", "MTU = 1420", "25")).unwrap())),
        ("wireguard-split", Outbound::WireGuard(wireguard::parse(&conf(51820, "10.0.0.0/8, 192.168.50.0/24", "", "25-35")).unwrap())),
        ("amneziawg-legacy", Outbound::WireGuard(wireguard::parse(&conf(51820, "0.0.0.0/0", LEGACY, "25")).unwrap())),
        ("amneziawg-2", Outbound::WireGuard(wireguard::parse(&conf(51820, "0.0.0.0/0", &awg2(), "25-35")).unwrap())),
        ("vless-reality", Outbound::Vless(VlessKey::parse(&format!("vless://{id}@203.0.113.7:443?type=tcp&security=reality&sni=www.googletagmanager.com&fp=hellochrome_120&pbk={pbk}&sid=0123abcd&flow=xtls-rprx-vision")).unwrap())),
        ("vless-tls", Outbound::Vless(VlessKey::parse(&format!("vless://{id}@vpn.example.com:443?security=tls&sni=vpn.example.com&fp=firefox")).unwrap())),
        ("shadowsocks", Outbound::Shadowsocks(AccessKey::parse("ss://aes-256-gcm:test-only-secret@203.0.113.9:8388").unwrap())),
    ];
    for (name, outbound) in outbounds {
        for tunnel in [false, true] {
            let path = dir.path().join(format!("{name}-{tunnel}.json"));
            storage::atomic_write(
                &path,
                &serde_json::to_vec(&worker_session::config(
                    &outbound,
                    20000,
                    20001,
                    SECRET,
                    tunnel,
                    &Default::default(),
                ))
                .unwrap(),
            )
            .unwrap();
            let output = command(&["check", "-c"], &path)
                .stderr(Stdio::piped())
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "worker rejected the generated {name} config (tunnel={tunnel}): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires GHOSTLINK_TEST_OUTLINE_WORKER: built managed worker"]
async fn wireguard_and_amneziawg_profiles_carry_real_traffic() {
    let dir = tempfile::tempdir().unwrap();
    storage::private_dir(dir.path()).unwrap();
    let web_port = serve_http("hello through the ghostlink worker").await;
    for (name, extra, keepalive) in [
        ("plain WireGuard", String::new(), "1"),
        ("legacy AmneziaWG", LEGACY.to_string(), "1"),
        ("AmneziaWG 2.0", awg2(), "1-2"),
    ] {
        let server_port = free_udp_port();
        let client = wireguard::parse(&conf(server_port, "0.0.0.0/0", &extra, keepalive)).unwrap();
        // The worker's own AmneziaWG endpoint acts as the server; zero parameters is plain WireGuard.
        let mut server_endpoint = json!({"type":"amneziawg","tag":"srv","address":["10.99.0.1/24"],"private_key":SERVER_PRIVATE,"listen_port":server_port,
            "peers":[{"user":"test","public_key":CLIENT_PUBLIC,"allowed_ips":["10.99.0.2/32"]}]});
        if client.is_amnezia() {
            server_endpoint["obfuscation"] = json!(client.obfuscation);
        }
        let server_path = dir.path().join("server.json");
        storage::atomic_write(&server_path, &serde_json::to_vec(&json!({"endpoints":[server_endpoint],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap()).unwrap();
        let server = run_worker(&server_path).await;

        let proxy_port = free_port().await;
        let api_port = free_port().await;
        let client_path = dir.path().join("client.json");
        storage::atomic_write(
            &client_path,
            &serde_json::to_vec(&worker_session::config(
                &Outbound::WireGuard(client),
                proxy_port,
                api_port,
                SECRET,
                false,
                &Default::default(),
            ))
            .unwrap(),
        )
        .unwrap();
        let client = run_worker(&client_path).await;

        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}"))
            .unwrap()
            .basic_auth("ghostlink", SECRET);
        let http = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap();
        let mut body = String::new();
        for _ in 0..4 {
            if let Ok(response) = http
                .get(format!("http://10.99.0.1:{web_port}/"))
                .send()
                .await
            {
                body = response.text().await.unwrap_or_default();
                break;
            }
        }
        assert_eq!(
            body, "hello through the ghostlink worker",
            "{name} carried no traffic"
        );
        client.stop(&format!("{name} client")).await;
        server.stop(&format!("{name} server")).await;
    }
}

/// A worker server (plain WireGuard) and a worker client generated with `policy`. The client
/// also gets an unauthenticated "probe" proxy that, unlike the health proxy, follows the policy.
async fn split_pair(
    dir: &std::path::Path,
    policy: ghostlink_contracts::RoutingPolicy,
    web: u16,
) -> (Worker, Worker, u16, u16) {
    let server_port = free_udp_port();
    let server_path = dir.join("split-server.json");
    storage::atomic_write(&server_path, &serde_json::to_vec(&json!({
        "endpoints":[{"type":"amneziawg","tag":"srv","address":["10.99.0.1/24"],"private_key":SERVER_PRIVATE,"listen_port":server_port,
            "peers":[{"public_key":CLIENT_PUBLIC,"allowed_ips":["10.99.0.2/32"]}]}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap()).unwrap();
    let server = run_worker(&server_path).await;
    let (proxy_port, api_port, probe_port) =
        (free_port().await, free_port().await, free_port().await);
    let policy = ghostlink_engine::split::validate(&policy).unwrap();
    let outbound =
        Outbound::WireGuard(wireguard::parse(&conf(server_port, "0.0.0.0/0", "", "1")).unwrap());
    let mut config =
        worker_session::config(&outbound, proxy_port, api_port, SECRET, false, &policy);
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"mixed","tag":"probe","listen":"127.0.0.1","listen_port":probe_port}));
    let client_path = dir.join("split-client.json");
    storage::atomic_write(&client_path, &serde_json::to_vec(&config).unwrap()).unwrap();
    let client = run_worker(&client_path).await;
    // Wait for the WireGuard handshake through the health proxy, which is always tunneled,
    // so that routing assertions never race the tunnel coming up.
    let warm = format!("http://10.99.0.1:{web}/");
    let mut ready = false;
    for _ in 0..10 {
        if probe(proxy_port, true, &warm, None).await {
            ready = true;
            break;
        }
    }
    assert!(
        ready,
        "split-test tunnel never came up; client events: {:?}",
        client.events.lock().unwrap()
    );
    (server, client, probe_port, proxy_port)
}

/// GET through a local proxy; `host` overrides the Host header so sniffing sees a site name.
async fn probe(proxy_port: u16, auth: bool, url: &str, host: Option<&str>) -> bool {
    let mut proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap();
    if auth {
        proxy = proxy.basic_auth("ghostlink", SECRET);
    }
    let http = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for _ in 0..3 {
        let mut request = http.get(url);
        if let Some(host) = host {
            request = request.header(reqwest::header::HOST, host);
        }
        if let Ok(response) = request.send().await {
            return response.text().await.unwrap_or_default() == "split ok";
        }
    }
    false
}

#[tokio::test]
#[ignore = "requires GHOSTLINK_TEST_OUTLINE_WORKER: built managed worker"]
async fn split_tunnel_rules_route_by_ip_and_site() {
    use ghostlink_contracts::{RoutingPolicy, SplitMode};
    let dir = tempfile::tempdir().unwrap();
    storage::private_dir(dir.path()).unwrap();
    let web = serve_http("split ok").await;
    let local = format!("http://127.0.0.1:{web}/");
    let tunneled = format!("http://10.99.0.1:{web}/");
    // Loopback can only be reached directly: inside the tunnel it never leaves the client's stack.
    // (through the health proxy?, URL, Host header override, expected reachable)
    type Expectation<'a> = (bool, &'a str, Option<&'a str>, bool);
    let cases: Vec<(&str, RoutingPolicy, Vec<Expectation>)> = vec![
        (
            "full",
            RoutingPolicy::default(),
            vec![(false, &local, None, false), (false, &tunneled, None, true)],
        ),
        (
            "bypass by IP",
            RoutingPolicy {
                mode: SplitMode::Bypass,
                ip_ranges: vec!["127.0.0.1/32".into()],
                ..Default::default()
            },
            vec![(false, &local, None, true), (false, &tunneled, None, true)],
        ),
        (
            "bypass by site",
            RoutingPolicy {
                mode: SplitMode::Bypass,
                domains: vec!["bypass.test".into()],
                ..Default::default()
            },
            vec![
                (false, &local, Some("www.bypass.test"), true),
                (false, &local, Some("other.test"), false),
            ],
        ),
        (
            "only listed",
            RoutingPolicy {
                mode: SplitMode::Only,
                ip_ranges: vec!["10.99.0.0/24".into()],
                ..Default::default()
            },
            vec![
                (false, &tunneled, None, true),
                (false, &local, None, true),
                (true, &local, None, false),
            ],
        ),
    ];
    for (name, policy, expectations) in cases {
        let (server, client, probe_port, health_port) = split_pair(dir.path(), policy, web).await;
        for (via_health, url, host, reachable) in expectations {
            let port = if via_health { health_port } else { probe_port };
            assert_eq!(
                probe(port, via_health, url, host).await,
                reachable,
                "{name}: {url} host={host:?} via {} should be {}",
                if via_health { "health proxy" } else { "policy" },
                if reachable {
                    "reachable"
                } else {
                    "unreachable"
                }
            );
        }
        client.stop(&format!("{name} client")).await;
        server.stop(&format!("{name} server")).await;
    }
}
