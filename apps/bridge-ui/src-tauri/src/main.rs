mod grpc;
mod state;
mod tray;

use crate::grpc::adapter::GrpcAdapter;
use crate::state::{AppState, BridgeSnapshot};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

#[derive(Default)]
struct AdapterState {
    adapter: Mutex<GrpcAdapter>,
}

fn emit_state(app: &AppHandle, snapshot: &BridgeSnapshot) {
    let _ = app.emit("bridge://state-changed", snapshot);
}

#[tauri::command]
async fn bridge_status(state: State<'_, AppState>) -> Result<BridgeSnapshot, String> {
    Ok(state.snapshot().await)
}

#[tauri::command]
async fn bridge_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<BridgeSnapshot, String> {
    let connect_result = {
        let mut adapter = adapter_state.adapter.lock().await;
        adapter.connect(app.clone(), state.inner().clone()).await
    };

    let snapshot = match connect_result {
        Ok(()) => state.snapshot().await,
        Err(err) => {
            tracing::error!("bridge_connect failed: {err}");
            state
                .update(|snapshot| {
                    snapshot.connected = false;
                    snapshot.stream_running = false;
                    snapshot.last_error = Some(err.clone());
                })
                .await
        }
    };

    emit_state(&app, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
async fn bridge_set_config_path(
    app: AppHandle,
    path: String,
    state: State<'_, AppState>,
) -> Result<BridgeSnapshot, String> {
    let snapshot = state
        .update(|snapshot| {
            snapshot.config_path = if path.trim().is_empty() {
                None
            } else {
                Some(path)
            };
        })
        .await;

    emit_state(&app, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
async fn bridge_disconnect(
    app: AppHandle,
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<BridgeSnapshot, String> {
    {
        let mut adapter = adapter_state.adapter.lock().await;
        adapter.disconnect().await;
    }

    let snapshot = state
        .update(|snapshot| {
            snapshot.connected = false;
            snapshot.stream_running = false;
        })
        .await;

    emit_state(&app, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
async fn bridge_set_login_step(
    app: AppHandle,
    step: String,
    state: State<'_, AppState>,
) -> Result<BridgeSnapshot, String> {
    let snapshot = state
        .update(|snapshot| {
            snapshot.login_step = step;
        })
        .await;

    emit_state(&app, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
async fn bridge_push_mock_error(
    app: AppHandle,
    message: String,
    state: State<'_, AppState>,
) -> Result<BridgeSnapshot, String> {
    let snapshot = state
        .update(|snapshot| {
            snapshot.last_error = Some(message);
        })
        .await;

    emit_state(&app, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
async fn bridge_clear_error(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BridgeSnapshot, String> {
    let snapshot = state
        .update(|snapshot| {
            snapshot.last_error = None;
        })
        .await;

    emit_state(&app, &snapshot);
    Ok(snapshot)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "bridge_ui_tauri=debug,tauri=info".to_string()),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        .manage(AppState::default())
        .manage(AdapterState::default())
        .setup(|app| {
            tray::build_tray(&app.handle())?;

            if let Some(window) = app.get_webview_window("main") {
                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        if let Some(main) = app_handle.get_webview_window("main") {
                            let _ = main.hide();
                        }
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bridge_status,
            bridge_connect,
            bridge_set_config_path,
            bridge_disconnect,
            bridge_set_login_step,
            bridge_push_mock_error,
            bridge_clear_error
        ])
        .run(tauri::generate_context!())
        .expect("tauri runtime failed");
}
