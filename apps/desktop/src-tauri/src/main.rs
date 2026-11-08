#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use ghostlink_contracts::{Action, Request, Response, SCHEMA_VERSION};
use std::time::Duration;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[tauri::command]
async fn vpn_request(action: Action) -> Response {
    // The GUI may import WireGuard/AmneziaWG files; OpenVPN profiles stay CLI-only.
    let wireguard_file = matches!(&action, Action::ProfileImport { content, .. }
        if content.lines().any(|line| line.trim().eq_ignore_ascii_case("[interface]")));
    if !wireguard_file
        && matches!(
            action,
            Action::AgentGrant { .. } | Action::AgentRevoke { .. } | Action::ProfileImport { .. }
        )
    {
        return Response::err(
            "permission_denied",
            "Use the CLI for administrator and OpenVPN profile operations",
        );
    }
    let endpoint = std::env::var("GHOSTLINK_ENDPOINT")
        .unwrap_or_else(|_| ghostlink_contracts::default_endpoint());
    ghostlink_contracts::call(
        &endpoint,
        Request {
            schema_version: SCHEMA_VERSION,
            agent_token: None,
            action,
        },
        Duration::from_secs(30),
    )
    .await
}

/// Saves a connection kit page, an Apple VPN profile or a WireGuard/AmneziaWG .conf in the user's
/// Downloads folder. WebView2 cannot download blob: links from the app's custom scheme, so the
/// shell writes the file itself: a name built from safe characters with an allowlisted extension
/// (html, mobileconfig or conf), never overwriting an existing file, at most 4 MiB.
#[tauri::command]
fn save_download(
    app: tauri::AppHandle,
    name: String,
    content: String,
    extension: Option<String>,
) -> Result<String, String> {
    let extension = match extension.as_deref() {
        None | Some("html") => "html",
        Some("mobileconfig") => "mobileconfig",
        Some("conf") => "conf",
        Some(_) => return Err("This kind of file cannot be saved".into()),
    };
    use std::io::Write;
    if content.len() > 4 << 20 {
        return Err("The file is too large".into());
    }
    let stem: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(60)
        .collect();
    let stem = if stem.is_empty() {
        "ghostlink-kit".to_string()
    } else {
        stem
    };
    let dir = app
        .path()
        .download_dir()
        .map_err(|_| "Could not find your Downloads folder".to_string())?;
    for n in 0..100 {
        let file_name = if n == 0 {
            format!("{stem}.{extension}")
        } else {
            format!("{stem} ({n}).{extension}")
        };
        let path = dir.join(file_name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(content.as_bytes())
                    .and_then(|_| file.sync_all())
                    .map_err(|_| "Could not write the file".to_string())?;
                return Ok(path.display().to_string());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Could not create the file in Downloads".into()),
        }
    }
    Err("Too many files with this name in Downloads".into())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![vpn_request, save_download])
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "Open Ghostlink", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Ghostlink", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &disconnect, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .tooltip("Ghostlink")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "disconnect" => {
                        tauri::async_runtime::spawn(async {
                            let _ = vpn_request(Action::Disconnect {}).await;
                        });
                    }
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("Ghostlink desktop could not start");
}
