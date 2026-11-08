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

/// WireGuard for Windows and AmneziaWG name a tunnel after its .conf file and refuse names longer
/// than this, or with a space: a second copy is "name-1.conf" rather than "name (1).conf". (The
/// views keep .conf names to 29 characters, which leaves room for "-99".)
const CONF_NAME_MAX: usize = 32;

/// The file name for the `n`th try at saving `stem.extension` (0 is the plain name). `stem` holds
/// only ASCII letters, digits, '-' and '_'.
fn download_name(stem: &str, extension: &str, n: u32) -> String {
    let suffix = match (n, extension) {
        (0, _) => String::new(),
        (_, "conf") => format!("-{n}"),
        _ => format!(" ({n})"),
    };
    let stem = if extension == "conf" {
        &stem[..stem.len().min(CONF_NAME_MAX.saturating_sub(suffix.len()))]
    } else {
        stem
    };
    format!("{stem}{suffix}.{extension}")
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
        let path = dir.join(download_name(&stem, extension, n));
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
                            // show() leaves a minimized window minimized, and set_focus() does
                            // nothing then: restore it first.
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "disconnect" => {
                        tauri::async_runtime::spawn(async {
                            let _ = vpn_request(Action::Disconnect).await;
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

#[cfg(test)]
mod tests {
    use super::download_name;

    #[test]
    fn conf_files_keep_names_that_wireguard_can_import() {
        assert_eq!(
            download_name("maya-wireguard-15", "conf", 0),
            "maya-wireguard-15.conf"
        );
        assert_eq!(
            download_name("maya-wireguard-15", "conf", 1),
            "maya-wireguard-15-1.conf"
        );
        let views = "Grandpa-s-Window-wireguard-15"; // the views send at most 29 characters
        assert_eq!(download_name(views, "conf", 99), format!("{views}-99.conf"));
        let long = "a".repeat(40);
        assert_eq!(
            download_name(&long, "conf", 0),
            format!("{}.conf", "a".repeat(32))
        );
        assert_eq!(
            download_name(&long, "conf", 12),
            format!("{}-12.conf", "a".repeat(29))
        );
    }

    #[test]
    fn other_files_keep_their_names() {
        assert_eq!(download_name("maya-vpn", "html", 0), "maya-vpn.html");
        assert_eq!(download_name("maya-vpn", "html", 2), "maya-vpn (2).html");
        let long = "a".repeat(60);
        assert_eq!(
            download_name(&long, "mobileconfig", 0),
            format!("{long}.mobileconfig")
        );
    }
}
