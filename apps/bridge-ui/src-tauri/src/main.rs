mod grpc;
mod state;
mod tray;

use crate::grpc::adapter::{AppSettings, GrpcAdapter, MailSettings, UserSummary};
use crate::state::{AppState, BridgeSnapshot};
use std::path::PathBuf;
use tauri::{AppHandle, Emitter, Manager, State, Url, WebviewUrl, WebviewWindowBuilder};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing_appender::non_blocking::WorkerGuard;

#[derive(Default)]
struct AdapterState {
    adapter: Mutex<GrpcAdapter>,
}

struct FrontendLogState {
    file_path: PathBuf,
    write_lock: Mutex<()>,
}

impl FrontendLogState {
    fn new() -> Self {
        Self {
            file_path: resolve_frontend_log_file_path(),
            write_lock: Mutex::new(()),
        }
    }
}

const CAPTCHA_WINDOW_LABEL: &str = "captcha";

const CAPTCHA_WINDOW_INIT_SCRIPT: &str = r#"
(() => {
  if (window.__openProtonCaptchaHookInstalled) {
    return;
  }
  window.__openProtonCaptchaHookInstalled = true;

  function parseToken(payload) {
    let value = payload;
    if (typeof value === 'string') {
      try {
        value = JSON.parse(value);
      } catch {
        return null;
      }
    }

    if (!value || typeof value !== 'object') {
      return null;
    }

    const token =
      value.type === 'pm_captcha' && typeof value.token === 'string' && value.token.length > 0
        ? value.token
        : (
            value.type === 'HUMAN_VERIFICATION_SUCCESS' &&
            value.payload &&
            typeof value.payload === 'object' &&
            value.payload.type === 'captcha' &&
            typeof value.payload.token === 'string' &&
            value.payload.token.length > 0
          )
          ? value.payload.token
          : null;

    if (!token) {
      return null;
    }

    return { type: value.type, token };
  }

  function emitToken(token) {
    if (window.__openProtonCaptchaTokenSent) {
      return;
    }
    window.__openProtonCaptchaTokenSent = true;

    const invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
    if (typeof invoke === 'function') {
      invoke('bridge_captcha_token_captured', { token }).catch(() => {
        window.__openProtonCaptchaTokenSent = false;
      });
    }
  }

  let fallbackToken = null;
  let fallbackTimer = null;

  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://verify.proton.me' && event.origin !== 'https://verify-api.proton.me') {
      return;
    }

    const parsed = parseToken(event.data);
    if (!parsed) {
      return;
    }

    if (parsed.type === 'pm_captcha') {
      // Keep pm_captcha as a fallback, but prefer HUMAN_VERIFICATION_SUCCESS
      // which indicates Proton finished verification and prevents premature retries.
      fallbackToken = parsed.token;
      if (!fallbackTimer) {
        fallbackTimer = setTimeout(() => {
          if (fallbackToken) {
            emitToken(fallbackToken);
          }
        }, 2000);
      }
      return;
    }

    if (parsed.type === 'HUMAN_VERIFICATION_SUCCESS') {
      if (fallbackTimer) {
        clearTimeout(fallbackTimer);
        fallbackTimer = null;
      }
      emitToken(parsed.token);
    }
  });
})();
"#;

fn emit_state(app: &AppHandle, snapshot: &BridgeSnapshot) {
    let _ = app.emit("bridge://state-changed", snapshot);
}

fn resolve_frontend_log_file_path() -> PathBuf {
    let base_dir = std::env::var_os("BRIDGE_UI_FRONTEND_LOG_DIR")
        .or_else(|| std::env::var_os("BRIDGE_UI_LOG_DIR"))
        .map(PathBuf::from)
        .or_else(|| dirs::data_local_dir().map(|path| path.join("openproton-bridge").join("logs")))
        .unwrap_or_else(|| std::env::temp_dir().join("openproton-bridge-logs"));

    base_dir.join("bridge-ui-frontend.log")
}

fn init_logging() -> Option<WorkerGuard> {
    let env_filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "bridge_ui_tauri=debug,tauri=info".to_string());

    if let Some(log_dir) = std::env::var_os("BRIDGE_UI_LOG_DIR") {
        let log_dir = PathBuf::from(log_dir);
        if let Err(err) = std::fs::create_dir_all(&log_dir) {
            eprintln!("bridge-ui-tauri: failed to create log directory: {err}");
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(false)
                .init();
            return None;
        }

        let file_appender = tracing_appender::rolling::daily(&log_dir, "bridge-ui-tauri.log");
        let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_ansi(false)
            .with_writer(file_writer)
            .init();

        tracing::info!(log_dir = %log_dir.display(), "file logging enabled");
        Some(guard)
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .init();
        None
    }
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state))]
async fn bridge_status(state: State<'_, AppState>) -> Result<BridgeSnapshot, String> {
    Ok(state.snapshot().await)
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(app, state, adapter_state))]
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
#[tracing::instrument(level = "debug", skip(app, state), fields(path = %path))]
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
#[tracing::instrument(level = "debug", skip(app, state, adapter_state))]
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
#[tracing::instrument(level = "debug", skip(app, state))]
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

#[tauri::command]
#[tracing::instrument(
    level = "debug",
    skip(log_state, context),
    fields(level = %level, target = %target)
)]
async fn bridge_frontend_log(
    log_state: State<'_, FrontendLogState>,
    level: String,
    target: String,
    message: String,
    context: Option<String>,
) -> Result<(), String> {
    let timestamp = chrono_like_timestamp();
    let line = if let Some(context) = context {
        serde_json::json!({
            "timestamp": timestamp,
            "level": level,
            "target": target,
            "message": message,
            "context": context
        })
        .to_string()
            + "\n"
    } else {
        serde_json::json!({
            "timestamp": timestamp,
            "level": level,
            "target": target,
            "message": message
        })
        .to_string()
            + "\n"
    };

    if let Some(parent) = log_state.file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| format!("failed to prepare frontend log directory: {err}"))?;
    }

    let _guard = log_state.write_lock.lock().await;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_state.file_path)
        .await
        .map_err(|err| format!("failed to open frontend log file: {err}"))?;

    file.write_all(line.as_bytes())
        .await
        .map_err(|err| format!("failed to write frontend log entry: {err}"))?;

    Ok(())
}

fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{now}")
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state))]
async fn bridge_fetch_users(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<Vec<UserSummary>, String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.fetch_users(state.inner()).await
}

#[tauri::command]
#[tracing::instrument(
    level = "debug",
    skip(state, adapter_state, password, human_verification_token),
    fields(username = %username, use_hv_details = ?use_hv_details)
)]
async fn bridge_login(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    username: String,
    password: String,
    use_hv_details: Option<bool>,
    human_verification_token: Option<String>,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .login(
            state.inner(),
            &username,
            &password,
            use_hv_details,
            human_verification_token.as_deref(),
        )
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(app), fields(url = %url))]
async fn bridge_open_captcha_window(app: AppHandle, url: String) -> Result<(), String> {
    if !url.starts_with("https://verify.proton.me/") {
        return Err("captcha url must start with https://verify.proton.me/".to_string());
    }

    let parsed = Url::parse(&url).map_err(|err| format!("invalid captcha url: {err}"))?;

    if let Some(existing) = app.get_webview_window(CAPTCHA_WINDOW_LABEL) {
        let _ = existing.close();
    }

    WebviewWindowBuilder::new(&app, CAPTCHA_WINDOW_LABEL, WebviewUrl::External(parsed))
        .title("Proton CAPTCHA Verification")
        .inner_size(520.0, 760.0)
        .resizable(true)
        .initialization_script(CAPTCHA_WINDOW_INIT_SCRIPT)
        .build()
        .map_err(|err| format!("failed to create captcha window: {err}"))?;

    Ok(())
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(app))]
async fn bridge_close_captcha_window(app: AppHandle) -> Result<(), String> {
    if let Some(existing) = app.get_webview_window(CAPTCHA_WINDOW_LABEL) {
        let _ = existing.close();
    }
    Ok(())
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(app, token), fields(token_len = token.len()))]
async fn bridge_captcha_token_captured(app: AppHandle, token: String) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("captcha token is empty".to_string());
    }

    app.emit("bridge://captcha-token", token)
        .map_err(|err| format!("failed to emit captcha token event: {err}"))?;

    if let Some(existing) = app.get_webview_window(CAPTCHA_WINDOW_LABEL) {
        let _ = existing.close();
    }

    Ok(())
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state, code), fields(username = %username))]
async fn bridge_login_2fa(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    username: String,
    code: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.login_2fa(state.inner(), &username, &code).await
}

#[tauri::command]
#[tracing::instrument(
    level = "debug",
    skip(state, adapter_state, mailbox_password),
    fields(username = %username)
)]
async fn bridge_login_2passwords(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    username: String,
    mailbox_password: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .login_2passwords(state.inner(), &username, &mailbox_password)
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(username = %username))]
async fn bridge_login_abort(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    username: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.login_abort(state.inner(), &username).await
}

#[tauri::command]
#[tracing::instrument(
    level = "debug",
    skip(state, adapter_state, assertion_payload),
    fields(username = %username)
)]
async fn bridge_login_fido(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    username: String,
    assertion_payload: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .login_fido(state.inner(), &username, assertion_payload.as_bytes())
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(username = %username))]
async fn bridge_fido_assertion_abort(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    username: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.fido_assertion_abort(state.inner(), &username).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state))]
async fn bridge_get_hostname(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<String, String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.get_hostname(state.inner()).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state))]
async fn bridge_get_mail_settings(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<MailSettings, String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.get_mail_settings(state.inner()).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(imap_port = settings.imap_port, smtp_port = settings.smtp_port))]
async fn bridge_set_mail_settings(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    settings: MailSettings,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.set_mail_settings(state.inner(), settings).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(port = port))]
async fn bridge_is_port_free(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    port: i32,
) -> Result<bool, String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.is_port_free(state.inner(), port).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(user_id = %user_id))]
async fn bridge_logout_user(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    user_id: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.logout_user(state.inner(), &user_id).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(user_id = %user_id))]
async fn bridge_remove_user(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    user_id: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.remove_user(state.inner(), &user_id).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(user_id = %user_id, active = active))]
async fn bridge_set_user_split_mode(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    user_id: String,
    active: bool,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .set_user_split_mode(state.inner(), &user_id, active)
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state))]
async fn bridge_is_tls_certificate_installed(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<bool, String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.is_tls_certificate_installed(state.inner()).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state))]
async fn bridge_install_tls_certificate(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.install_tls_certificate(state.inner()).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(output_dir = %output_dir))]
async fn bridge_export_tls_certificates(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    output_dir: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .export_tls_certificates(state.inner(), &output_dir)
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state))]
async fn bridge_get_app_settings(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
) -> Result<AppSettings, String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.get_app_settings(state.inner()).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(enabled = enabled))]
async fn bridge_set_is_autostart_on(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    enabled: bool,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.set_is_autostart_on(state.inner(), enabled).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(enabled = enabled))]
async fn bridge_set_is_beta_enabled(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    enabled: bool,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.set_is_beta_enabled(state.inner(), enabled).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(enabled = enabled))]
async fn bridge_set_is_all_mail_visible(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    enabled: bool,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .set_is_all_mail_visible(state.inner(), enabled)
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(disabled = disabled))]
async fn bridge_set_is_telemetry_disabled(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    disabled: bool,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter
        .set_is_telemetry_disabled(state.inner(), disabled)
        .await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(path = %path))]
async fn bridge_set_disk_cache_path(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    path: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.set_disk_cache_path(state.inner(), &path).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(enabled = enabled))]
async fn bridge_set_is_doh_enabled(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    enabled: bool,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.set_is_doh_enabled(state.inner(), enabled).await
}

#[tauri::command]
#[tracing::instrument(level = "debug", skip(state, adapter_state), fields(name = %name))]
async fn bridge_set_color_scheme_name(
    state: State<'_, AppState>,
    adapter_state: State<'_, AdapterState>,
    name: String,
) -> Result<(), String> {
    let adapter = adapter_state.adapter.lock().await;
    adapter.set_color_scheme_name(state.inner(), &name).await
}

fn main() {
    let _log_guard = init_logging();
    let frontend_log_state = FrontendLogState::new();
    tracing::info!(
        frontend_log_path = %frontend_log_state.file_path.display(),
        "frontend log sink initialized"
    );

    tauri::Builder::default()
        .manage(AppState::default())
        .manage(AdapterState::default())
        .manage(frontend_log_state)
        .setup(|app| {
            tray::build_tray(app.handle())?;

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
            bridge_clear_error,
            bridge_frontend_log,
            bridge_fetch_users,
            bridge_login,
            bridge_open_captcha_window,
            bridge_close_captcha_window,
            bridge_captcha_token_captured,
            bridge_login_2fa,
            bridge_login_2passwords,
            bridge_login_abort,
            bridge_login_fido,
            bridge_fido_assertion_abort,
            bridge_get_hostname,
            bridge_get_mail_settings,
            bridge_set_mail_settings,
            bridge_is_port_free,
            bridge_logout_user,
            bridge_remove_user,
            bridge_set_user_split_mode,
            bridge_is_tls_certificate_installed,
            bridge_install_tls_certificate,
            bridge_export_tls_certificates,
            bridge_get_app_settings,
            bridge_set_is_autostart_on,
            bridge_set_is_beta_enabled,
            bridge_set_is_all_mail_visible,
            bridge_set_is_telemetry_disabled,
            bridge_set_disk_cache_path,
            bridge_set_is_doh_enabled,
            bridge_set_color_scheme_name
        ])
        .run(tauri::generate_context!())
        .expect("tauri runtime failed");
}
