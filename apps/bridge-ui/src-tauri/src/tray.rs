use crate::grpc::{adapter::UserSummary, pb::UserState};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime};

const MAIN_TRAY_ID: &str = "main-tray";
const USER_ACTION_PREFIX: &str = "select_user:";

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn user_state_label(state: i32) -> &'static str {
    match UserState::try_from(state) {
        Ok(UserState::Connected) => "CONNECTED",
        Ok(UserState::Locked) => "LOCKED",
        Ok(UserState::SignedOut) | Err(_) => "SIGNED_OUT",
    }
}

fn build_tray_menu<R: Runtime>(
    app: &AppHandle<R>,
    users: &[UserSummary],
) -> tauri::Result<Menu<R>> {
    let menu = Menu::new(app)?;

    for user in users {
        let user_label = format!("{} ({})", user.username, user_state_label(user.state));
        let user_id = format!("{USER_ACTION_PREFIX}{}", user.id);
        let user_item = MenuItem::with_id(app, user_id, user_label, true, None::<&str>)?;
        menu.append(&user_item)?;
    }

    if !users.is_empty() {
        let users_separator = PredefinedMenuItem::separator(app)?;
        menu.append(&users_separator)?;
    }

    let open_bridge = MenuItem::with_id(app, "open_bridge", "Open Bridge", true, None::<&str>)?;
    let help = MenuItem::with_id(app, "help", "Help", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
    let static_separator = PredefinedMenuItem::separator(app)?;
    let quit_bridge = MenuItem::with_id(app, "quit_bridge", "Quit Bridge", true, None::<&str>)?;

    menu.append(&open_bridge)?;
    menu.append(&help)?;
    menu.append(&settings)?;
    menu.append(&static_separator)?;
    menu.append(&quit_bridge)?;

    Ok(menu)
}

pub fn refresh_tray_users<R: Runtime>(
    app: &AppHandle<R>,
    users: &[UserSummary],
) -> tauri::Result<()> {
    let menu = build_tray_menu(app, users)?;
    if let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) {
        tray.set_menu(Some(menu))?;
    }
    Ok(())
}

pub fn build_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let menu = build_tray_menu(app, &[])?;

    let mut builder = TrayIconBuilder::with_id(MAIN_TRAY_ID);

    builder = builder.menu(&menu);

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let event_id = event.id.as_ref();

            if let Some(user_id) = event_id.strip_prefix(USER_ACTION_PREFIX) {
                show_main_window(&app);
                let _ = app.emit(
                    "bridge://tray-action",
                    format!("{USER_ACTION_PREFIX}{user_id}"),
                );
                return;
            }

            match event_id {
                "open_bridge" => {
                    show_main_window(&app);
                    let _ = app.emit("bridge://tray-action", "show_main");
                }
                "help" => {
                    show_main_window(&app);
                    let _ = app.emit("bridge://tray-action", "show_help");
                }
                "settings" => {
                    show_main_window(&app);
                    let _ = app.emit("bridge://tray-action", "show_settings");
                }
                "quit_bridge" => {
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                show_main_window(&app);
                let _ = app.emit("bridge://tray-action", "show_main");
            }
        })
        .build(app)?;

    Ok(())
}
