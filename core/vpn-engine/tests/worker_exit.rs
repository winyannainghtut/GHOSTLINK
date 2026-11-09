//! How a session ends when its tunnel worker ends, through the real session code (code review
//! 2026-11-10, Rust finding 2). The worker is a stand-in: this test binary itself, which acts as
//! the worker when started with `version`, `check` or `run` (the test has its own `main`,
//! `harness = false`). It changes no network settings. A `fake-mode` file in each case's run
//! directory says how the stand-in ends.
use ghostlink_engine::{access::Outbound, management::Shared, outline::AccessKey, worker_session};
use std::{path::Path, process::exit, time::Duration};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("version") => println!("{}", worker_session::WORKER_VERSION),
        Some("check") => {}
        Some("run") if args.len() == 4 => run(Path::new(&args[3])),
        _ => cases(),
    }
}

/// The stand-in worker's `run -c CONFIG`.
fn run(config: &Path) {
    let mode = std::fs::read_to_string(config.with_file_name("fake-mode")).unwrap_or_default();
    match mode.trim() {
        // Ends with an error before it could report `started`: a crash, or a kill.
        "exit-before-started" => exit(23),
        // Reports a failure after which it undid what it changed, then exits 1, as the real
        // worker does.
        "clean-failure" => {
            eprintln!(r#"{{"event":"failed","code":"engine_start_failed"}}"#);
            exit(1)
        }
        // Reports that it could not confirm its cleanup.
        "cleanup-failure" => {
            eprintln!(r#"{{"event":"failed","code":"engine_close_failed"}}"#);
            exit(1)
        }
        // Waits for the stop command (or the end of its control pipe), then exits cleanly: a
        // stop that comes while it is still starting.
        "stop" => {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            exit(0)
        }
        _ => exit(99),
    }
}

const BARRIERS: [&str; 2] = [
    "network_cleanup_unverified",
    "forced_stop_network_cleanup_unverified",
];

fn cases() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let failures = runtime.block_on(async {
        let worker = std::env::current_exe().unwrap();
        let mut failures = 0;
        // (mode, whether the next connection must wait for an inspection)
        for (mode, barrier) in [
            ("exit-before-started", true),
            ("clean-failure", false),
            ("cleanup-failure", true),
            ("stop", false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let run_dir = dir.path().join("run");
            std::fs::create_dir(&run_dir).unwrap();
            std::fs::write(run_dir.join("fake-mode"), mode).unwrap();
            let shared = Shared::default();
            let (events, _received) = tokio::sync::mpsc::channel(16);
            let key =
                AccessKey::parse("ss://aes-256-gcm:test-only-secret@203.0.113.9:8388").unwrap();
            let mut session = worker_session::start(
                &worker,
                &run_dir,
                mode.into(),
                Outbound::Shadowsocks(key),
                Default::default(),
                vec![],
                shared.clone(),
                events,
                Duration::from_secs(20),
            )
            .await
            .unwrap();
            if mode == "stop" {
                tokio::time::sleep(Duration::from_millis(300)).await;
                session.stop().await;
            } else if tokio::time::timeout(Duration::from_secs(30), &mut session.task)
                .await
                .is_err()
            {
                println!("FAIL {mode}: the session did not end");
                failures += 1;
                continue;
            }
            let last_error = shared.read().await.status.last_error.clone();
            let blocked = last_error.as_deref().is_some_and(|e| BARRIERS.contains(&e));
            let ok = blocked == barrier && (mode == "stop") == last_error.is_none();
            println!(
                "{} {mode}: last_error {last_error:?}",
                if ok { "ok  " } else { "FAIL" }
            );
            failures += usize::from(!ok);
        }
        failures
    });
    if failures > 0 {
        exit(1);
    }
}
