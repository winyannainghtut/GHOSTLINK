use crate::{
    access::Outbound,
    management::{Session, Shared, Snapshot},
    split, storage,
    vless::Security,
};
use anyhow::{ensure, Result};
use ghostlink_contracts::ConnectionState;
use ghostlink_contracts::RoutingPolicy;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc,
};

pub const WORKER_VERSION: &str =
    "Ghostlink tunnel worker 0.8.1; sing-box 1.14.4; amneziawg-go 3.1.20260828";

/// Tag of the tunnel outbound or endpoint in every generated configuration.
pub const PROXY_TAG: &str = "proxy";

pub async fn worker_available(executable: &Path) -> bool {
    if !executable.is_absolute() || !executable.is_file() {
        return false;
    }
    let mut command = Command::new(executable);
    command.arg("version").kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    matches!(tokio::time::timeout(Duration::from_secs(5), command.output()).await,
        Ok(Ok(output)) if output.status.success() && output.stdout == format!("{WORKER_VERSION}\n").as_bytes())
}

/// One status line from the worker (`started`, `failed` or `closed`).
#[derive(Deserialize)]
struct Event {
    event: String,
    #[serde(default)]
    vpn_ip: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

impl Event {
    /// A failure after which the worker could not confirm that the engine removed its routes,
    /// filters and DNS settings.
    fn cleanup_failed(&self) -> bool {
        self.event == "failed"
            && matches!(
                self.code.as_deref(),
                Some(
                    "engine_close_failed" | "engine_close_timeout" | "engine_start_cancel_timeout"
                )
            )
    }
}

/// Reads the worker's remaining status lines until it closes them (it exits) and reports
/// whether one was a cleanup failure. `frame` may hold a line the session loop started reading.
async fn reported_cleanup_failure<R: AsyncBufRead + Unpin>(
    logs: &mut R,
    frame: &mut Vec<u8>,
) -> bool {
    let mut failed = false;
    loop {
        match logs.read_until(b'\n', frame).await {
            Ok(0) | Err(_) => return failed,
            Ok(_) => {}
        }
        if frame.len() <= 4096 {
            failed |= serde_json::from_slice::<Event>(frame).is_ok_and(|e| e.cleanup_failed());
        }
        frame.clear();
    }
}

/// The sing-box outbound (Shadowsocks, VLESS) or endpoint (WireGuard, AmneziaWG) for a credential.
fn proxy(outbound: &Outbound) -> (Option<Value>, Option<Value>) {
    match outbound {
        Outbound::Shadowsocks(key) => (
            Some(
                json!({"type":"shadowsocks","tag":PROXY_TAG,"server":key.server,"server_port":key.port,"method":key.method,"password":key.password}),
            ),
            None,
        ),
        Outbound::Vless(key) => {
            let mut tls = json!({"enabled":true,"server_name":key.server_name,"utls":{"enabled":true,"fingerprint":key.fingerprint}});
            if let Security::Reality {
                public_key,
                short_id,
            } = &key.security
            {
                tls["reality"] =
                    json!({"enabled":true,"public_key":public_key,"short_id":short_id});
            }
            let mut vless = json!({"type":"vless","tag":PROXY_TAG,"server":key.server,"server_port":key.port,"uuid":key.uuid,"tls":tls});
            if !key.flow.is_empty() {
                vless["flow"] = json!(key.flow);
            }
            (Some(vless), None)
        }
        Outbound::WireGuard(config) => {
            let peer = &config.peer;
            let default_mtu = if config.is_amnezia() { 1376 } else { 1420 };
            let mut endpoint = json!({"tag":PROXY_TAG,"address":config.addresses,"private_key":config.private_key,"mtu":config.mtu.unwrap_or(default_mtu)});
            let mut peer_json = json!({"address":peer.host,"port":peer.port,"public_key":peer.public_key,"allowed_ips":peer.allowed_ips});
            if let Some(psk) = &peer.preshared_key {
                peer_json["pre_shared_key"] = json!(psk);
            }
            if config.is_amnezia() {
                endpoint["type"] = json!("amneziawg");
                endpoint["obfuscation"] = json!(config.obfuscation);
                if let Some(keepalive) = &peer.keepalive {
                    peer_json["persistent_keepalive"] = json!(keepalive);
                }
            } else {
                endpoint["type"] = json!("wireguard");
                // The native endpoint takes one interval; use the lower bound of a range.
                if let Some(seconds) = peer
                    .keepalive
                    .as_deref()
                    .and_then(|k| k.split('-').next())
                    .and_then(|k| k.parse::<u16>().ok())
                {
                    peer_json["persistent_keepalive_interval"] = json!(seconds);
                }
            }
            endpoint["peers"] = json!([peer_json]);
            (None, Some(endpoint))
        }
    }
}

/// `policy` must already be validated with `split::validate`.
pub fn config(
    outbound: &Outbound,
    proxy_port: u16,
    api_port: u16,
    secret: &str,
    tunnel: bool,
    policy: &RoutingPolicy,
) -> Value {
    config_with_direct(outbound, proxy_port, api_port, secret, tunnel, policy, &[])
}

/// `always_direct` lists (host, port) destinations that must never enter the tunnel: the
/// management APIs of servers this device administers. A Ghostlink server refuses its own API
/// port from VPN users, so while connected through it, management must go around the tunnel.
#[allow(clippy::too_many_arguments)]
pub fn config_with_direct(
    outbound: &Outbound,
    proxy_port: u16,
    api_port: u16,
    secret: &str,
    tunnel: bool,
    policy: &RoutingPolicy,
    always_direct: &[(String, u16)],
) -> Value {
    let mut inbounds = vec![
        json!({"type":"mixed","tag":"health-proxy","listen":"127.0.0.1","listen_port":proxy_port,"users":[{"username":"ghostlink","password":secret}]}),
    ];
    if tunnel {
        let mut tun = json!({"type":"tun","tag":"ghostlink-tun","interface_name":"Ghostlink","address":["172.28.85.1/30","fdfe:85:85::1/126"],"auto_route":true,"strict_route":true,"dns_mode":"hijack","mtu":1500,"stack":"mixed"});
        // A WireGuard profile with limited AllowedIPs routes only those prefixes into the TUN.
        if let Outbound::WireGuard(config) = outbound {
            if !config.routes_everything() {
                tun["route_address"] = json!(config.peer.allowed_ips);
            }
        }
        inbounds.push(tun);
    }
    // WireGuard profiles name their resolver; otherwise DNS-over-HTTPS through the tunnel.
    let vpn_dns = match outbound {
        Outbound::WireGuard(config) if !config.dns.is_empty() => {
            json!({"type":"udp","tag":"vpn-dns","server":config.dns[0].to_string(),"detour":PROXY_TAG})
        }
        _ => {
            json!({"type":"https","tag":"vpn-dns","server":"1.1.1.1","path":"/dns-query","tls":{"enabled":true,"server_name":"cloudflare-dns.com"},"detour":PROXY_TAG})
        }
    };
    let (outbound_json, endpoint_json) = proxy(outbound);
    let split = split::render(policy, PROXY_TAG);
    let mut direct_rules = vec![];
    let mut dns_rules = vec![];
    for (host, port) in always_direct {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match bare.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                direct_rules.push(
                    json!({"ip_cidr":[format!("{ip}/{bits}")],"port":[port],"outbound":"direct"}),
                );
            }
            Err(_) => {
                direct_rules.push(json!({"domain":[bare],"port":[port],"outbound":"direct"}));
                dns_rules.push(json!({"domain":[bare],"server":"bootstrap"}));
            }
        }
    }
    dns_rules.extend(split.dns_rules);
    let mut outbounds: Vec<Value> = outbound_json.into_iter().collect();
    if split.needs_direct || !direct_rules.is_empty() {
        // Bound to the physical interface by auto_detect_interface, like the tunnel's own sockets.
        outbounds.push(json!({"type":"direct","tag":"direct"}));
    }
    let mut rules = vec![];
    if endpoint_json.is_some() {
        // A WireGuard or AmneziaWG endpoint is an inbound too. A flow its far side starts (the
        // server, or a peer the server forwards) would otherwise be routed like this device's own
        // traffic: to its loopback, its LAN in bypass or LAN-direct setups, or out to the internet.
        rules.push(json!({"inbound":PROXY_TAG,"action":"reject"}));
    }
    rules.extend([
        // Learn site names (TLS SNI, HTTP Host, QUIC) and DNS for the rules below.
        json!({"action":"sniff"}),
        // The health probe must always test the tunnel, even when "only" mode sends the
        // rest of the traffic direct; otherwise a dead tunnel could be reported as connected.
        json!({"inbound":"health-proxy","outbound":PROXY_TAG}),
    ]);
    rules.extend(direct_rules);
    rules.extend([
        json!({"inbound":"ghostlink-tun","ip_version":6,"action":"reject"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
    ]);
    rules.extend(split.route_rules);
    let mut document = json!({
        "log":{"level":"info","timestamp":false,"disabled":false},
        "dns":{"servers":[vpn_dns,{"type":"local","tag":"bootstrap"}],"rules":dns_rules,"final":split.dns_final,"strategy":"ipv4_only"},
        "inbounds":inbounds,
        "outbounds":outbounds,
        "route":{"auto_detect_interface":tunnel,"default_domain_resolver":{"server":"bootstrap","strategy":"ipv4_only"},"rules":rules,"final":split.route_final,"find_process":split.find_process},
        "experimental":{"clash_api":{"external_controller":format!("127.0.0.1:{api_port}"),"secret":secret,"access_control_allow_origin":["http://ghostlink.invalid"],"access_control_allow_private_network":false}}
    });
    if let Some(endpoint) = endpoint_json {
        document["endpoints"] = json!([endpoint]);
    }
    document
}

#[allow(clippy::too_many_arguments)] // One call site; a struct would only rename these.
pub async fn start(
    executable: &Path,
    run_dir: &Path,
    name: String,
    outbound: Outbound,
    policy: RoutingPolicy,
    always_direct: Vec<(String, u16)>,
    shared: Shared,
    events: mpsc::Sender<&'static str>,
    timeout: Duration,
) -> Result<Session> {
    ensure!(
        worker_available(executable).await,
        "Install the pinned managed Ghostlink tunnel worker"
    );
    storage::private_dir(run_dir)?;
    let mut random = [0; 32];
    OsRng.fill_bytes(&mut random);
    let secret = hex::encode(random);
    let proxy_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let api_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = proxy_reservation.local_addr()?.port();
    let api_port = api_reservation.local_addr()?.port();
    let path = run_dir.join("outline.json");
    let config_guard = storage::PrivateConfig::write(
        &path,
        &serde_json::to_vec(&config_with_direct(
            &outbound,
            proxy_port,
            api_port,
            &secret,
            true,
            &policy,
            &always_direct,
        ))?,
    )?;
    let mut check = Command::new(executable);
    check.args(["check", "-c"]).arg(&path).kill_on_drop(true);
    #[cfg(windows)]
    check.creation_flags(0x08000000);
    let checked = tokio::time::timeout(Duration::from_secs(10), check.output()).await??;
    ensure!(
        checked.status.success(),
        "Managed tunnel engine rejected configuration"
    );
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}"))?
        .basic_auth("ghostlink", &secret);
    let health = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let controller = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    drop(proxy_reservation);
    drop(api_reservation);
    let mut command = Command::new(executable);
    command
        .args(["run", "-c"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("Tunnel worker did not start"))?;
    let mut control = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Missing private worker control pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Cannot monitor tunnel engine"))?;
    {
        let mut snapshot = shared.write().await;
        *snapshot = Snapshot::default();
        snapshot.status.status = ConnectionState::Connecting;
        snapshot.status.profile = Some(name);
        snapshot.status.protocol = Some(outbound.protocol().into());
        snapshot.status.server = Some(outbound.server().0.to_string());
    }
    let (stop, mut stop_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        let _config_guard = config_guard;
        let mut logs = BufReader::new(stderr);
        let mut initialized = false;
        let mut reason = None;
        let mut stopping = false;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        // Keep partial frames across select cancellation (for example a health-check tick).
        let mut frame = Vec::new();
        let mut observed_ip = None;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut connected_once = false;
        let mut last_counters = (0u64, 0u64, Instant::now());
        loop {
            tokio::select! {
                _ = stop_rx.recv() => { stopping = true; break; }
                _ = child.wait() => { reason = Some("outline_engine_exited_check_service_permissions"); break; }
                _ = &mut deadline, if !connected_once => { reason = Some("outline_server_unreachable_or_key_rejected"); break; }
                result = logs.read_until(b'\n', &mut frame) => {
                    match result { Ok(0) | Err(_) => { reason = Some("outline_engine_exited_check_service_permissions"); break; }, _ => {} }
                    if frame.len() > 4096 { reason = Some("outline_engine_protocol_error"); break; }
                    let event = serde_json::from_slice::<Event>(&frame); frame.clear();
                    match event {
                        Ok(event) if event.event == "started" => {
                            if crate::process::verify_listeners(pid, &[proxy_port, api_port]).is_err() { reason = Some("outline_engine_socket_owner_mismatch"); break; }
                            observed_ip = event.vpn_ip.filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok());
                            if observed_ip.is_none() { reason = Some("outline_tunnel_interface_not_observed"); break; }
                            initialized = true;
                        }
                        Ok(event) if event.event == "failed" => {
                            reason = Some(if event.cleanup_failed() { "network_cleanup_unverified" } else { "outline_engine_start_failed_check_permissions_or_driver" }); break;
                        }
                        _ => { reason = Some("outline_engine_protocol_error"); break; }
                    }
                }
                _ = interval.tick(), if initialized => {
                    if crate::process::verify_listeners(pid, &[proxy_port, api_port]).is_err() { reason = Some("outline_engine_socket_owner_mismatch"); break; }
                    let check = health.get("https://www.gstatic.com/generate_204").send();
                    let healthy = tokio::select! {
                        _ = stop_rx.recv() => { stopping = true; break; }
                        _ = &mut deadline, if !connected_once => { reason = Some("outline_server_unreachable_or_key_rejected"); break; }
                        response = check => response.map(|r| r.status().as_u16() == 204).unwrap_or(false)
                    };
                    let mut snapshot = shared.write().await;
                    if healthy {
                        if snapshot.status.status != ConnectionState::Connected {
                            snapshot.status.status = ConnectionState::Connected;
                            snapshot.status.vpn_ip = observed_ip.clone();
                            snapshot.connected_since = Some(Instant::now());
                            snapshot.status.last_error = None;
                            let _ = events.try_send("outline_connected_health_verified");
                        }
                        connected_once = true;
                    } else if connected_once {
                        // Only a session that was verified healthy can be "reconnecting"; before
                        // that it stays "connecting" until success or the deadline.
                        snapshot.status.status = ConnectionState::Reconnecting;
                        snapshot.status.last_error = Some("outline_health_check_failed".into());
                        snapshot.status.vpn_ip = None; snapshot.connected_since = None;
                        snapshot.status.receive_bytes_per_second = 0; snapshot.status.send_bytes_per_second = 0;
                    }
                    drop(snapshot);
                    if let Ok(response) = controller.get(format!("http://127.0.0.1:{api_port}/connections")).bearer_auth(&secret).send().await {
                        if let Ok(data) = response.json::<Value>().await {
                            if let (Some(rx), Some(tx)) = (data["downloadTotal"].as_u64(), data["uploadTotal"].as_u64()) {
                                let now = Instant::now(); let elapsed = now.duration_since(last_counters.2).as_secs_f64().max(0.001);
                                let mut snapshot = shared.write().await;
                                snapshot.status.bytes_received = rx; snapshot.status.bytes_sent = tx;
                                snapshot.status.receive_bytes_per_second = (rx.saturating_sub(last_counters.0) as f64 / elapsed) as u64;
                                snapshot.status.send_bytes_per_second = (tx.saturating_sub(last_counters.1) as f64 / elapsed) as u64;
                                last_counters = (rx, tx, now);
                            }
                        }
                    }
                }
            }
        }
        if stopping {
            shared.write().await.status.status = ConnectionState::Disconnecting;
        }
        // The managed worker calls upstream Close() on this command or parent-pipe EOF.
        let _ = control.write_all(b"{\"command\":\"stop\"}\n").await;
        let _ = control.shutdown().await;
        drop(control);
        // Keep reading events until the worker exits. A stop, the deadline or the worker's own
        // exit can end the loop above while it is still starting, and the cleanup failure it
        // reports on the way out would otherwise go unnoticed.
        let exit = async {
            let cleanup_failed = reported_cleanup_failure(&mut logs, &mut frame).await;
            (cleanup_failed, child.wait().await)
        };
        match tokio::time::timeout(Duration::from_secs(12), exit).await {
            Ok((true, _)) => reason = Some("network_cleanup_unverified"),
            Ok((false, Ok(status))) if status.success() => {}
            Ok((false, _)) => {
                if initialized {
                    reason = Some("network_cleanup_unverified");
                }
            }
            Err(_) => {
                let _ = child.kill().await;
                reason = Some("forced_stop_network_cleanup_unverified");
            }
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
        let _ = events.try_send(reason.unwrap_or("outline_disconnected"));
    });
    Ok(Session { stop, task })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outline::AccessKey;

    #[test]
    fn managed_server_apis_bypass_the_tunnel() {
        let key = AccessKey::parse("ss://aes-256-gcm:test-only@192.0.2.10:8388").unwrap();
        let direct = vec![
            ("203.0.113.5".to_string(), 23456),
            ("vpn.example.com".to_string(), 34567),
        ];
        let config = config_with_direct(
            &Outbound::Shadowsocks(key),
            1,
            2,
            "secret",
            true,
            &RoutingPolicy::default(),
            &direct,
        );
        let rules = config["route"]["rules"].as_array().unwrap();
        // After sniffing and the health rule, before the IPv6 reject and DNS hijack.
        assert_eq!(
            rules[2],
            json!({"ip_cidr":["203.0.113.5/32"],"port":[23456],"outbound":"direct"})
        );
        assert_eq!(
            rules[3],
            json!({"domain":["vpn.example.com"],"port":[34567],"outbound":"direct"})
        );
        assert_eq!(rules[4]["action"], "reject");
        assert_eq!(
            config["dns"]["rules"][0],
            json!({"domain":["vpn.example.com"],"server":"bootstrap"})
        );
        assert!(config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["tag"] == "direct"));
        // Without managed servers nothing changes and no direct outbound appears.
        let plain = config_with_direct(
            &Outbound::Shadowsocks(
                AccessKey::parse("ss://aes-256-gcm:test-only@192.0.2.10:8388").unwrap(),
            ),
            1,
            2,
            "secret",
            true,
            &RoutingPolicy::default(),
            &[],
        );
        assert!(!plain["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["tag"] == "direct"));
    }

    #[tokio::test]
    async fn cleanup_failures_reported_while_stopping_are_noticed() {
        // The session loop may have stopped in the middle of the line.
        let mut frame = b"{\"event\":\"fai".to_vec();
        let mut rest: &[u8] = b"led\",\"code\":\"engine_close_failed\"}\n";
        assert!(reported_cleanup_failure(&mut rest, &mut frame).await);
        let mut later: &[u8] =
            b"{\"event\":\"closed\"}\n{\"event\":\"failed\",\"code\":\"engine_start_cancel_timeout\"}\n";
        assert!(reported_cleanup_failure(&mut later, &mut Vec::new()).await);
        for lines in [
            &b"{\"event\":\"closed\"}\n"[..],
            b"{\"event\":\"failed\",\"code\":\"engine_start_failed_check_permissions\"}\n",
            b"{\"event\":\"started\",\"code\":\"engine_close_failed\"}\nnot json\n",
            b"",
        ] {
            let mut reader = lines;
            assert!(!reported_cleanup_failure(&mut reader, &mut Vec::new()).await);
        }
    }

    #[test]
    fn endpoints_refuse_flows_their_far_side_starts() {
        let wireguard = crate::wireguard::parse("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.1.2/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0\n").unwrap();
        let through_endpoint = config(
            &Outbound::WireGuard(wireguard),
            1,
            2,
            "secret",
            true,
            &RoutingPolicy::default(),
        );
        assert_eq!(
            through_endpoint["route"]["rules"][0],
            json!({"inbound":PROXY_TAG,"action":"reject"})
        );
        // Shadowsocks and VLESS are outbounds only: nothing arrives through them, so no rule.
        let key = AccessKey::parse("ss://aes-256-gcm:test-only@192.0.2.10:8388").unwrap();
        let through_outbound = config(
            &Outbound::Shadowsocks(key),
            1,
            2,
            "secret",
            true,
            &RoutingPolicy::default(),
        );
        assert_eq!(
            through_outbound["route"]["rules"][0],
            json!({"action":"sniff"})
        );
    }

    #[test]
    fn wireguard_tun_routes_follow_allowed_ips() {
        let conf = |allowed: &str| {
            crate::wireguard::parse(&format!("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.1.2/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 203.0.113.5:51820\nAllowedIPs = {allowed}\n")).unwrap()
        };
        let tun = |allowed: &str| {
            let config = config(
                &Outbound::WireGuard(conf(allowed)),
                1,
                2,
                "secret",
                true,
                &RoutingPolicy::default(),
            );
            config["inbounds"][1].clone()
        };
        assert!(tun("0.0.0.0/0, ::/0").get("route_address").is_none());
        // Split into halves it is a full tunnel, but the TUN still takes exactly those routes.
        assert_eq!(
            tun("0.0.0.0/1, 128.0.0.0/1")["route_address"],
            json!(["0.0.0.0/1", "128.0.0.0/1"])
        );
        assert_eq!(
            tun("192.168.1.0/24")["route_address"],
            json!(["192.168.1.0/24"])
        );
    }
}
