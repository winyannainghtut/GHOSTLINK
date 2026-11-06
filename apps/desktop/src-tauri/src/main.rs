#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use myvpn_contracts::{Action, Request, Response, SCHEMA_VERSION};
use std::time::Duration;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[tauri::command]
async fn vpn_request(action: Action) -> Response {
    if matches!(
        action,
        Action::AgentGrant { .. } | Action::AgentRevoke { .. } | Action::ProfileImport { .. }
    ) {
        return Response::err(
            "permission_denied",
            "Use the CLI for administrator and OpenVPN profile operations",
        );
    }
    let endpoint =
        std::env::var("MYVPN_ENDPOINT").unwrap_or_else(|_| myvpn_contracts::default_endpoint());
    myvpn_contracts::call(
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![vpn_request])
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "Open MyVPN", true, None::<&str>)?;
            let disconnect =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit MyVPN", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &disconnect, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .tooltip("MyVPN")
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
        .expect("MyVPN desktop could not start");
}
