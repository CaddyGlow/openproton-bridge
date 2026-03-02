use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch, Mutex};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::Stream;
use tonic::metadata::MetadataMap;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::api;
use crate::api::client::ProtonClient;
use crate::api::error::{any_human_verification_details, human_verification_details, ApiError};
use crate::api::types::{HumanVerificationDetails, Session};
use crate::bridge;
use crate::paths::RuntimePaths;
use crate::vault;

const SERVER_CONFIG_FILE: &str = "grpcServerConfig.json";
const MAIL_SETTINGS_FILE: &str = "grpc_mail_settings.json";
const APP_SETTINGS_FILE: &str = "grpc_app_settings.json";
const SERVER_TOKEN_METADATA_KEY: &str = "server-token";
const CAPTCHA_APPEAL_URL: &str = "https://proton.me/support/appeal-abuse";
const MAX_BUFFERED_STREAM_EVENTS: usize = 256;
const DEFAULT_EMAIL_CLIENT: &str = "NoClient/0.0.1";
const KEYCHAIN_HELPER_MACOS: &str = "macos-keychain";
const KEYCHAIN_HELPER_WINDOWS: &str = "windows-credentials";
const KEYCHAIN_HELPER_SECRET_SERVICE_DBUS: &str = "secret-service-dbus";
const KEYCHAIN_HELPER_SECRET_SERVICE: &str = "secret-service";
const KEYCHAIN_HELPER_PASS_APP: &str = "pass-app";

#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("grpc");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrpcServerConfig {
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "cert")]
    cert: String,
    #[serde(rename = "token")]
    token: String,
    #[serde(rename = "fileSocketPath")]
    file_socket_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrpcClientConfig {
    #[serde(rename = "token")]
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMailSettings {
    imap_port: i32,
    smtp_port: i32,
    use_ssl_for_imap: bool,
    use_ssl_for_smtp: bool,
}

impl Default for StoredMailSettings {
    fn default() -> Self {
        Self {
            imap_port: 1143,
            smtp_port: 1025,
            use_ssl_for_imap: false,
            use_ssl_for_smtp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAppSettings {
    show_on_startup: bool,
    is_autostart_on: bool,
    is_beta_enabled: bool,
    is_all_mail_visible: bool,
    is_telemetry_disabled: bool,
    disk_cache_path: String,
    is_doh_enabled: bool,
    color_scheme_name: String,
    is_automatic_update_on: bool,
    current_keychain: String,
    main_executable: String,
    forced_launcher: String,
}

impl StoredAppSettings {
    fn with_defaults_for(disk_cache_dir: &Path) -> Self {
        let default_keychain = vault::discover_available_keychains()
            .into_iter()
            .next()
            .unwrap_or_else(|| vault::KEYCHAIN_BACKEND_FILE.to_string());
        Self {
            show_on_startup: true,
            is_autostart_on: false,
            is_beta_enabled: false,
            is_all_mail_visible: true,
            is_telemetry_disabled: false,
            disk_cache_path: disk_cache_dir.display().to_string(),
            is_doh_enabled: true,
            color_scheme_name: "system".to_string(),
            is_automatic_update_on: true,
            current_keychain: default_keychain,
            main_executable: String::new(),
            forced_launcher: String::new(),
        }
    }
}

#[derive(Debug)]
struct PendingLogin {
    username: String,
    password: String,
    uid: String,
    access_token: String,
    refresh_token: String,
    client: ProtonClient,
    fido_authentication_options: Option<serde_json::Value>,
}

#[derive(Debug)]
struct PendingHumanVerification {
    username: String,
    details: HumanVerificationDetails,
}

struct GrpcState {
    runtime_paths: RuntimePaths,
    bind_host: String,
    active_disk_cache_path: Mutex<PathBuf>,
    event_tx: broadcast::Sender<pb::StreamEvent>,
    event_backlog: std::sync::Mutex<VecDeque<pb::StreamEvent>>,
    active_stream_stop: Mutex<Option<watch::Sender<bool>>>,
    pending_login: Mutex<Option<PendingLogin>>,
    pending_hv: Mutex<Option<PendingHumanVerification>>,
    shutdown_tx: watch::Sender<bool>,
    mail_settings: Mutex<StoredMailSettings>,
    app_settings: Mutex<StoredAppSettings>,
    sync_workers_enabled: bool,
    sync_event_workers: Mutex<Option<bridge::events::EventWorkerGroup>>,
}

#[derive(Clone)]
struct BridgeService {
    state: Arc<GrpcState>,
}

fn os_keyring_helpers() -> &'static [&'static str] {
    match std::env::consts::OS {
        "macos" => &[KEYCHAIN_HELPER_MACOS],
        "windows" => &[KEYCHAIN_HELPER_WINDOWS],
        "linux" => &[
            KEYCHAIN_HELPER_SECRET_SERVICE_DBUS,
            KEYCHAIN_HELPER_SECRET_SERVICE,
            KEYCHAIN_HELPER_PASS_APP,
        ],
        _ => &[vault::KEYCHAIN_BACKEND_KEYRING],
    }
}

fn keychain_helper_to_backend(helper: &str) -> Option<&'static str> {
    match helper.trim() {
        vault::KEYCHAIN_BACKEND_FILE => Some(vault::KEYCHAIN_BACKEND_FILE),
        vault::KEYCHAIN_BACKEND_KEYRING
        | KEYCHAIN_HELPER_MACOS
        | KEYCHAIN_HELPER_WINDOWS
        | KEYCHAIN_HELPER_SECRET_SERVICE_DBUS
        | KEYCHAIN_HELPER_SECRET_SERVICE
        | KEYCHAIN_HELPER_PASS_APP => Some(vault::KEYCHAIN_BACKEND_KEYRING),
        _ => None,
    }
}

fn available_keychain_helpers_with_backends(available_backends: &[String]) -> Vec<String> {
    let mut helpers = Vec::new();
    let keyring_available = available_backends
        .iter()
        .any(|backend| backend == vault::KEYCHAIN_BACKEND_KEYRING);

    if keyring_available {
        for helper in os_keyring_helpers() {
            if !helpers.iter().any(|candidate| candidate == helper) {
                helpers.push((*helper).to_string());
            }
        }
        if !helpers
            .iter()
            .any(|candidate| candidate == vault::KEYCHAIN_BACKEND_KEYRING)
        {
            helpers.push(vault::KEYCHAIN_BACKEND_KEYRING.to_string());
        }
    }

    if !helpers
        .iter()
        .any(|candidate| candidate == vault::KEYCHAIN_BACKEND_FILE)
    {
        helpers.push(vault::KEYCHAIN_BACKEND_FILE.to_string());
    }

    helpers
}

fn available_keychain_helpers() -> Vec<String> {
    let backends = vault::discover_available_keychains();
    available_keychain_helpers_with_backends(&backends)
}

impl BridgeService {
    fn new(state: Arc<GrpcState>) -> Self {
        Self { state }
    }

    fn settings_dir(&self) -> &Path {
        self.state.runtime_paths.settings_dir()
    }

    fn logs_dir(&self) -> PathBuf {
        self.state.runtime_paths.logs_dir()
    }

    fn grpc_mail_settings_path(&self) -> PathBuf {
        self.state.runtime_paths.grpc_mail_settings_path()
    }

    fn grpc_app_settings_path(&self) -> PathBuf {
        self.state.runtime_paths.grpc_app_settings_path()
    }

    async fn refresh_sync_workers(&self) -> anyhow::Result<()> {
        if !self.state.sync_workers_enabled {
            return Ok(());
        }

        let active_disk_cache_path = self.state.active_disk_cache_path.lock().await.clone();
        let next_group =
            maybe_start_grpc_sync_workers(&self.state.runtime_paths, self, &active_disk_cache_path)
                .await?;

        let previous_group = {
            let mut guard = self.state.sync_event_workers.lock().await;
            std::mem::replace(&mut *guard, next_group)
        };

        if let Some(group) = previous_group {
            group.shutdown().await;
        }

        Ok(())
    }

    async fn shutdown_sync_workers(&self) {
        let previous_group = {
            let mut guard = self.state.sync_event_workers.lock().await;
            guard.take()
        };
        if let Some(group) = previous_group {
            group.shutdown().await;
        }
    }

    async fn refresh_sync_workers_for_transition(&self, transition: &'static str) {
        if let Err(err) = self.refresh_sync_workers().await {
            warn!(
                transition,
                error = %err,
                "failed to refresh grpc sync workers during transition"
            );
        }
    }

    fn status_from_vault_error_with_events(&self, err: vault::VaultError) -> Status {
        if matches!(
            err,
            vault::VaultError::MissingVaultKey | vault::VaultError::KeychainAccess(_)
        ) {
            self.emit_keychain_rebuild();
        }
        status_from_vault_error(err)
    }

    async fn set_current_keychain_with_available(
        &self,
        keychain_raw: &str,
        available: &[String],
    ) -> Result<(), Status> {
        let result = async {
            let helper = keychain_raw.trim();
            if helper.is_empty() {
                return Err(Status::invalid_argument("keychain name is empty"));
            }
            let Some(backend) = keychain_helper_to_backend(helper) else {
                return Err(Status::invalid_argument(format!(
                    "unknown keychain helper: {helper}"
                )));
            };
            if !available.iter().any(|candidate| candidate == helper) {
                self.emit_keychain_has_no_keychain();
                return Err(Status::failed_precondition(format!(
                    "keychain helper unavailable on this host: {helper}"
                )));
            }
            vault::sync_vault_key_to_backend(self.settings_dir(), backend)
                .map_err(|err| self.status_from_vault_error_with_events(err))?;
            vault::set_keychain_helper(self.settings_dir(), helper)
                .map_err(|err| self.status_from_vault_error_with_events(err))?;
            let mut settings = self.state.app_settings.lock().await;
            settings.current_keychain = helper.to_string();
            save_app_settings(&self.grpc_app_settings_path(), &settings)
                .await
                .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
            Ok(())
        }
        .await;
        self.emit_keychain_change_finished();
        self.emit_show_main_window();
        let _ = self.state.shutdown_tx.send(true);
        result
    }

    fn emit_event(&self, event: pb::stream_event::Event) {
        let stream_event = pb::StreamEvent { event: Some(event) };
        if let Ok(mut backlog) = self.state.event_backlog.lock() {
            backlog.push_back(stream_event.clone());
            while backlog.len() > MAX_BUFFERED_STREAM_EVENTS {
                let _ = backlog.pop_front();
            }
        }
        let _ = self.state.event_tx.send(stream_event);
    }

    fn emit_login_error(&self, message: impl Into<String>) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::Error(pb::LoginErrorEvent {
                r#type: pb::LoginErrorType::ConnectionError as i32,
                message: message.into(),
            })),
        }));
    }

    fn emit_show_main_window(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ShowMainWindow(
                pb::ShowMainWindowEvent {},
            )),
        }));
    }

    fn emit_login_tfa_requested(&self, username: &str) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::TfaRequested(
                pb::LoginTfaRequestedEvent {
                    username: username.to_string(),
                },
            )),
        }));
    }

    fn emit_login_finished(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::Finished(pb::LoginFinishedEvent {
                user_id: user_id.to_string(),
                was_signed_out: false,
            })),
        }));
    }

    fn emit_user_changed(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::UserChanged(pb::UserChangedEvent {
                user_id: user_id.to_string(),
            })),
        }));
    }

    fn emit_sync_started(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncStartedEvent(
                pb::SyncStartedEvent {
                    user_id: user_id.to_string(),
                },
            )),
        }));
    }

    fn emit_sync_progress(&self, user_id: &str, progress: f64, elapsed_ms: i64, remaining_ms: i64) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncProgressEvent(
                pb::SyncProgressEvent {
                    user_id: user_id.to_string(),
                    progress,
                    elapsed_ms,
                    remaining_ms,
                },
            )),
        }));
    }

    fn emit_sync_finished(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncFinishedEvent(
                pb::SyncFinishedEvent {
                    user_id: user_id.to_string(),
                },
            )),
        }));
    }

    fn emit_user_disconnected(&self, username: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::UserDisconnected(
                pb::UserDisconnectedEvent {
                    username: username.to_string(),
                },
            )),
        }));
    }

    fn emit_mail_settings_changed(&self, settings: &StoredMailSettings) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(
                    pb::mail_server_settings_event::Event::MailServerSettingsChanged(
                        pb::MailServerSettingsChangedEvent {
                            settings: Some(pb::ImapSmtpSettings {
                                imap_port: settings.imap_port,
                                smtp_port: settings.smtp_port,
                                use_ssl_for_imap: settings.use_ssl_for_imap,
                                use_ssl_for_smtp: settings.use_ssl_for_smtp,
                            }),
                        },
                    ),
                ),
            },
        ));
    }

    fn emit_mail_settings_finished(&self) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(
                    pb::mail_server_settings_event::Event::ChangeMailServerSettingsFinished(
                        pb::ChangeMailServerSettingsFinishedEvent {},
                    ),
                ),
            },
        ));
    }

    fn emit_mail_settings_error(&self, error_type: pb::MailServerSettingsErrorType) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(pb::mail_server_settings_event::Event::Error(
                    pb::MailServerSettingsErrorEvent {
                        r#type: error_type as i32,
                    },
                )),
            },
        ));
    }

    fn emit_keychain_change_finished(&self) {
        self.emit_event(pb::stream_event::Event::Keychain(pb::KeychainEvent {
            event: Some(pb::keychain_event::Event::ChangeKeychainFinished(
                pb::ChangeKeychainFinishedEvent {},
            )),
        }));
    }

    fn emit_keychain_has_no_keychain(&self) {
        self.emit_event(pb::stream_event::Event::Keychain(pb::KeychainEvent {
            event: Some(pb::keychain_event::Event::HasNoKeychain(
                pb::HasNoKeychainEvent {},
            )),
        }));
    }

    fn emit_keychain_rebuild(&self) {
        self.emit_event(pb::stream_event::Event::Keychain(pb::KeychainEvent {
            event: Some(pb::keychain_event::Event::RebuildKeychain(
                pb::RebuildKeychainEvent {},
            )),
        }));
    }

    fn emit_toggle_autostart_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ToggleAutostartFinished(
                pb::ToggleAutostartFinishedEvent {},
            )),
        }));
    }

    fn emit_report_bug_success(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ReportBugSuccess(
                pb::ReportBugSuccessEvent {},
            )),
        }));
    }

    fn emit_report_bug_error(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ReportBugError(
                pb::ReportBugErrorEvent {},
            )),
        }));
    }

    fn emit_report_bug_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ReportBugFinished(
                pb::ReportBugFinishedEvent {},
            )),
        }));
    }

    fn emit_reset_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ResetFinished(
                pb::ResetFinishedEvent {},
            )),
        }));
    }

    fn emit_repair_started(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::RepairStarted(
                pb::RepairStartedEvent {},
            )),
        }));
    }

    fn emit_knowledge_base_suggestions(&self, suggestions: Vec<pb::KnowledgeBaseSuggestion>) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::KnowledgeBaseSuggestions(
                pb::KnowledgeBaseSuggestionsEvent { suggestions },
            )),
        }));
    }

    fn emit_disk_cache_path_changed(&self, path: &str) {
        self.emit_event(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
            event: Some(pb::disk_cache_event::Event::PathChanged(
                pb::DiskCachePathChangedEvent {
                    path: path.to_string(),
                },
            )),
        }));
    }

    fn emit_disk_cache_path_change_finished(&self) {
        self.emit_event(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
            event: Some(pb::disk_cache_event::Event::PathChangeFinished(
                pb::DiskCachePathChangeFinishedEvent {},
            )),
        }));
    }

    fn emit_disk_cache_error(&self, error_type: pb::DiskCacheErrorType) {
        self.emit_event(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
            event: Some(pb::disk_cache_event::Event::Error(
                pb::DiskCacheErrorEvent {
                    r#type: error_type as i32,
                },
            )),
        }));
    }

    async fn complete_login(
        &self,
        mut client: ProtonClient,
        uid: String,
        access_token: String,
        refresh_token: String,
        username: String,
        password: String,
    ) -> Result<Session, Status> {
        let user_resp = api::users::get_user(&client)
            .await
            .map_err(status_from_api_error)?;
        let user = &user_resp.user;

        let salts_resp = api::users::get_salts(&client)
            .await
            .map_err(status_from_api_error)?;

        let key_passphrase = {
            let mut derived = None;
            for key in user.keys.iter().filter(|k| k.active == 1) {
                match api::srp::salt_for_key(password.as_bytes(), &key.id, &salts_resp.key_salts) {
                    Ok(passphrase) => {
                        derived = Some(BASE64.encode(&passphrase));
                        break;
                    }
                    Err(err) => {
                        debug!(key_id = %key.id, error = %err, "key passphrase derivation attempt failed");
                    }
                }
            }

            if derived.is_none() {
                warn!("could not derive key passphrase from any active user key");
            }
            derived
        };

        let bridge_password = generate_bridge_password();
        let session = Session {
            uid: uid.clone(),
            access_token,
            refresh_token,
            email: user.email.clone(),
            display_name: if user.display_name.is_empty() {
                username
            } else {
                user.display_name.clone()
            },
            key_passphrase,
            bridge_password: Some(bridge_password),
        };

        vault::save_session(&session, self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        vault::set_default_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;

        client.set_auth(&session.uid, &session.access_token);

        self.emit_login_finished(&session.uid);
        self.emit_user_changed(&session.uid);
        self.refresh_sync_workers_for_transition("login").await;

        Ok(session)
    }
}

#[tonic::async_trait]
impl pb::bridge_server::Bridge for BridgeService {
    async fn check_tokens(&self, request: Request<String>) -> Result<Response<String>, Status> {
        let path = request.into_inner();
        if path.trim().is_empty() {
            return Err(Status::invalid_argument("client config path is empty"));
        }

        let payload = tokio::fs::read(&path)
            .await
            .map_err(|e| Status::not_found(format!("failed to read client config: {e}")))?;
        let cfg: GrpcClientConfig = serde_json::from_slice(&payload)
            .map_err(|e| Status::invalid_argument(format!("invalid client config json: {e}")))?;
        Ok(Response::new(cfg.token))
    }

    async fn add_log_entry(
        &self,
        request: Request<pb::AddLogEntryRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let level = pb::LogLevel::try_from(req.level).unwrap_or(pb::LogLevel::LogInfo);
        match level {
            pb::LogLevel::LogPanic | pb::LogLevel::LogFatal | pb::LogLevel::LogError => {
                tracing::error!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogWarn => {
                tracing::warn!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogInfo => {
                tracing::info!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogDebug => {
                tracing::debug!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogTrace => {
                tracing::trace!(target = req.r#package.as_str(), "{}", req.message);
            }
        }
        Ok(Response::new(()))
    }

    async fn gui_ready(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GuiReadyResponse>, Status> {
        let settings = self.state.app_settings.lock().await;
        self.emit_show_main_window();
        Ok(Response::new(pb::GuiReadyResponse {
            show_splash_screen: settings.show_on_startup,
        }))
    }

    async fn restart(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        self.emit_show_main_window();
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(()))
    }

    async fn trigger_repair(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        let service = self.clone();
        tokio::spawn(async move {
            match vault::list_sessions(service.settings_dir()) {
                Ok(sessions) => {
                    for session in sessions {
                        let checkpoint = vault::StoredEventCheckpoint {
                            last_event_id: String::new(),
                            last_event_ts: None,
                            sync_state: None,
                        };
                        if let Err(err) = vault::save_event_checkpoint_by_account_id(
                            service.settings_dir(),
                            &session.uid,
                            &checkpoint,
                        ) {
                            tracing::warn!(
                                user_id = %session.uid,
                                error = %err,
                                "failed to reset event checkpoint during repair"
                            );
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to list sessions during repair");
                }
            }

            service
                .refresh_sync_workers_for_transition("trigger_repair")
                .await;
            service.emit_repair_started();
            service.emit_show_main_window();
        });
        Ok(Response::new(()))
    }

    async fn trigger_reset(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        vault::remove_session(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let _ = tokio::fs::remove_file(self.grpc_mail_settings_path()).await;
        let _ = tokio::fs::remove_file(self.grpc_app_settings_path()).await;
        *self.state.pending_login.lock().await = None;
        *self.state.pending_hv.lock().await = None;
        self.refresh_sync_workers_for_transition("trigger_reset")
            .await;
        self.emit_reset_finished();
        Ok(Response::new(()))
    }

    async fn show_on_startup(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.show_on_startup))
    }

    async fn set_is_autostart_on(&self, request: Request<bool>) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_autostart_on = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        self.emit_toggle_autostart_finished();
        Ok(Response::new(()))
    }

    async fn is_autostart_on(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_autostart_on))
    }

    async fn set_is_beta_enabled(&self, request: Request<bool>) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_beta_enabled = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_beta_enabled(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_beta_enabled))
    }

    async fn set_is_all_mail_visible(
        &self,
        request: Request<bool>,
    ) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_all_mail_visible = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_all_mail_visible(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_all_mail_visible))
    }

    async fn set_is_telemetry_disabled(
        &self,
        request: Request<bool>,
    ) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_telemetry_disabled = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_telemetry_disabled(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_telemetry_disabled))
    }

    async fn disk_cache_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        let path = self.state.active_disk_cache_path.lock().await.clone();
        Ok(Response::new(path.display().to_string()))
    }

    async fn set_disk_cache_path(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let path = request.into_inner();
        if path.trim().is_empty() {
            return Err(Status::invalid_argument("disk cache path is empty"));
        }

        let target = PathBuf::from(path.trim());
        let current = self.state.active_disk_cache_path.lock().await.clone();
        if let Err(err) = move_disk_cache_payload(&current, &target).await {
            self.emit_disk_cache_error(pb::DiskCacheErrorType::CantMoveDiskCacheError);
            self.emit_disk_cache_path_change_finished();
            return Err(Status::internal(format!(
                "failed to move disk cache path: {err}"
            )));
        }

        *self.state.active_disk_cache_path.lock().await = target.clone();

        let mut settings = self.state.app_settings.lock().await;
        settings.disk_cache_path = target.display().to_string();
        if let Err(err) = save_app_settings(&self.grpc_app_settings_path(), &settings).await {
            self.emit_disk_cache_error(pb::DiskCacheErrorType::CantMoveDiskCacheError);
            self.emit_disk_cache_path_change_finished();
            return Err(Status::internal(format!(
                "failed to save app settings: {err}"
            )));
        }

        self.emit_disk_cache_path_changed(&settings.disk_cache_path);
        self.emit_disk_cache_path_change_finished();
        self.refresh_sync_workers_for_transition("set_disk_cache_path")
            .await;
        Ok(Response::new(()))
    }

    async fn set_is_do_h_enabled(&self, request: Request<bool>) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_doh_enabled = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_do_h_enabled(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_doh_enabled))
    }

    async fn set_color_scheme_name(
        &self,
        request: Request<String>,
    ) -> Result<Response<()>, Status> {
        let name = request.into_inner();
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("color scheme name is empty"));
        }
        let mut settings = self.state.app_settings.lock().await;
        settings.color_scheme_name = name;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn color_scheme_name(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.color_scheme_name.clone()))
    }

    async fn current_email_client(
        &self,
        _request: Request<()>,
    ) -> Result<Response<String>, Status> {
        Ok(Response::new(format!(
            "{DEFAULT_EMAIL_CLIENT} ({})",
            std::env::consts::OS
        )))
    }

    async fn logs_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        let path = self.logs_dir();
        tokio::fs::create_dir_all(&path)
            .await
            .map_err(|e| Status::internal(format!("failed to create logs directory: {e}")))?;
        Ok(Response::new(path.display().to_string()))
    }

    async fn license_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new(resolve_license_path()))
    }

    async fn release_notes_page_link(
        &self,
        _request: Request<()>,
    ) -> Result<Response<String>, Status> {
        Ok(Response::new(
            "https://github.com/ProtonMail/proton-bridge/releases".to_string(),
        ))
    }

    async fn dependency_licenses_link(
        &self,
        _request: Request<()>,
    ) -> Result<Response<String>, Status> {
        Ok(Response::new(
            "https://github.com/ProtonMail/proton-bridge/blob/master/COPYING_NOTES.md".to_string(),
        ))
    }

    async fn landing_page_link(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new("https://proton.me/mail/bridge".to_string()))
    }

    async fn report_bug(
        &self,
        request: Request<pb::ReportBugRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        tracing::warn!(
            title = %req.title,
            os_type = %req.os_type,
            os_version = %req.os_version,
            include_logs = req.include_logs,
            "bug report requested via grpc"
        );
        let service = self.clone();
        tokio::spawn(async move {
            if req.title.trim().is_empty() || req.description.trim().is_empty() {
                tracing::warn!("bug report rejected: missing title or description");
                service.emit_report_bug_error();
            } else {
                service.emit_report_bug_success();
            }
            service.emit_report_bug_finished();
        });
        Ok(Response::new(()))
    }

    async fn force_launcher(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let launcher = request.into_inner();
        let mut settings = self.state.app_settings.lock().await;
        settings.forced_launcher = launcher;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn set_main_executable(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let executable = request.into_inner();
        let mut settings = self.state.app_settings.lock().await;
        settings.main_executable = executable;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn request_knowledge_base_suggestions(
        &self,
        request: Request<String>,
    ) -> Result<Response<()>, Status> {
        let query = request.into_inner();
        tracing::info!(
            query = %query,
            "knowledge base suggestion request received"
        );
        let service = self.clone();
        tokio::spawn(async move {
            let trimmed = query.trim().to_string();
            if !trimmed.is_empty() {
                let encoded = trimmed.replace(' ', "+");
                service.emit_knowledge_base_suggestions(vec![pb::KnowledgeBaseSuggestion {
                    url: format!("https://proton.me/support/search?q={encoded}"),
                    title: format!("Search Proton support for \"{trimmed}\""),
                }]);
            } else {
                service.emit_knowledge_base_suggestions(Vec::new());
            }
        });
        Ok(Response::new(()))
    }

    async fn login(&self, request: Request<pb::LoginRequest>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        if username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        let password = String::from_utf8(req.password)
            .map_err(|_| Status::invalid_argument("password must be valid utf-8"))?;
        if password.is_empty() {
            return Err(Status::invalid_argument("password is required"));
        }

        let request_use_hv_details = req.use_hv_details.unwrap_or(false);
        let request_hv_token_override = req
            .human_verification_token
            .as_deref()
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_string);
        let mut hv_details = None;
        {
            let hv_guard = self.state.pending_hv.lock().await;
            if let Some(pending_hv) = hv_guard.as_ref() {
                if !username.eq_ignore_ascii_case(&pending_hv.username) {
                    if request_use_hv_details {
                        return Err(Status::invalid_argument(
                            "username does not match pending human verification",
                        ));
                    }
                } else {
                    hv_details = Some(pending_hv.details.clone());
                    if !request_use_hv_details {
                        info!(
                            username = %username,
                            "auto-reusing pending human verification details for login retry"
                        );
                    }
                }
            } else if request_use_hv_details {
                return Err(Status::failed_precondition(
                    "no pending human verification challenge",
                ));
            }
        }

        if let Some(token_override) = request_hv_token_override {
            let Some(details) = hv_details.as_mut() else {
                return Err(Status::failed_precondition(
                    "no pending human verification challenge for provided human verification token",
                ));
            };
            details.human_verification_token = token_override;
            info!(
                username = %username,
                token_len = details.human_verification_token.len(),
                "using explicit human verification token override for login"
            );
        }

        info!(
            username = %username,
            request_use_hv_details,
            using_hv_details = hv_details.is_some(),
            "starting grpc login attempt"
        );

        let mut client = ProtonClient::new().map_err(status_from_api_error)?;
        let auth = match api::auth::login(&mut client, &username, &password, hv_details.as_ref())
            .await
        {
            Ok(auth) => auth,
            Err(err) => {
                if let Some(hv) = human_verification_details(&err) {
                    let hv_url = hv.challenge_url();
                    info!(
                        username = %username,
                        methods = ?hv.human_verification_methods,
                        "received human verification challenge from Proton"
                    );
                    let mut pending_hv = self.state.pending_hv.lock().await;
                    *pending_hv = Some(PendingHumanVerification {
                        username: username.clone(),
                        details: hv,
                    });
                    self.emit_login_error(format!(
                        "human verification required; open {hv_url}, complete CAPTCHA, then retry login"
                    ));
                } else {
                    if matches!(&err, ApiError::Api { code: 12087, .. }) {
                        if let Some(hv) = any_human_verification_details(&err) {
                            let hv_url = hv.challenge_url();
                            let mut pending_hv = self.state.pending_hv.lock().await;
                            *pending_hv = Some(PendingHumanVerification {
                                username: username.clone(),
                                details: hv,
                            });
                            self.emit_login_error(format!(
                                "captcha validation failed; open {hv_url}, complete CAPTCHA again, then retry login. \
                                 If your client can provide the `pm_captcha` token, send it as `humanVerificationToken`."
                            ));
                        } else {
                            *self.state.pending_hv.lock().await = None;
                            self.emit_login_error(
                                "captcha validation failed; start login again to get a fresh challenge",
                            );
                        }
                    } else {
                        self.emit_login_error(err.to_string());
                    }
                    warn!(username = %username, error = %err, "grpc login failed");
                }
                return Err(status_from_api_error(err));
            }
        };
        info!(username = %username, "grpc login auth phase completed");
        *self.state.pending_hv.lock().await = None;

        if auth.two_factor.requires_second_factor() {
            let pending = PendingLogin {
                username: username.clone(),
                password,
                uid: auth.uid,
                access_token: auth.access_token,
                refresh_token: auth.refresh_token,
                client,
                fido_authentication_options: auth.two_factor.fido_authentication_options(),
            };
            *self.state.pending_login.lock().await = Some(pending);
            if auth.two_factor.totp_required() {
                self.emit_login_tfa_requested(&username);
            } else if auth.two_factor.fido_supported() {
                self.emit_login_error("security key authentication required; call LoginFido");
            } else {
                self.emit_login_error("second-factor authentication required");
            }
            return Ok(Response::new(()));
        }

        let session = self
            .complete_login(
                client,
                auth.uid,
                auth.access_token,
                auth.refresh_token,
                username,
                password,
            )
            .await?;
        debug!(email = %session.email, "login completed through grpc");
        Ok(Response::new(()))
    }

    async fn login2_fa(&self, request: Request<pb::LoginRequest>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        let code = String::from_utf8(req.password)
            .map_err(|_| Status::invalid_argument("2FA code must be valid utf-8"))?;

        info!(username = %username, "starting grpc 2FA submission");

        let mut pending_guard = self.state.pending_login.lock().await;
        let Some(pending) = pending_guard.take() else {
            return Err(Status::failed_precondition("no pending login for 2FA"));
        };

        if !username.is_empty() && !username.eq_ignore_ascii_case(&pending.username) {
            *pending_guard = Some(pending);
            return Err(Status::invalid_argument(
                "username does not match pending login",
            ));
        }

        if let Err(err) = api::auth::submit_2fa(&pending.client, code.trim()).await {
            *pending_guard = Some(pending);
            self.emit_login_error(err.to_string());
            warn!(username = %username, error = %err, "grpc 2FA submission failed");
            return Err(status_from_api_error(err));
        }
        info!(username = %username, "grpc 2FA submission accepted");

        drop(pending_guard);

        self.complete_login(
            pending.client,
            pending.uid,
            pending.access_token,
            pending.refresh_token,
            pending.username,
            pending.password,
        )
        .await?;
        info!(username = %username, "grpc 2FA login flow completed");
        Ok(Response::new(()))
    }

    async fn login2_passwords(
        &self,
        request: Request<pb::LoginRequest>,
    ) -> Result<Response<()>, Status> {
        self.login(request).await
    }

    async fn login_fido(&self, request: Request<pb::LoginRequest>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        if req.password.is_empty() {
            return Err(Status::invalid_argument(
                "FIDO assertion payload must not be empty",
            ));
        }

        let mut pending_guard = self.state.pending_login.lock().await;
        let Some(pending) = pending_guard.take() else {
            return Err(Status::failed_precondition("no pending login for FIDO"));
        };

        if !username.is_empty() && !username.eq_ignore_ascii_case(&pending.username) {
            *pending_guard = Some(pending);
            return Err(Status::invalid_argument(
                "username does not match pending login",
            ));
        }

        let Some(authentication_options) = pending.fido_authentication_options.clone() else {
            *pending_guard = Some(pending);
            return Err(Status::failed_precondition(
                "pending login has no FIDO challenge",
            ));
        };

        if let Err(err) =
            api::auth::submit_fido_2fa(&pending.client, &authentication_options, &req.password)
                .await
        {
            *pending_guard = Some(pending);
            self.emit_login_error(err.to_string());
            return Err(status_from_api_error(err));
        }

        drop(pending_guard);

        self.complete_login(
            pending.client,
            pending.uid,
            pending.access_token,
            pending.refresh_token,
            pending.username,
            pending.password,
        )
        .await?;

        Ok(Response::new(()))
    }

    async fn login_abort(
        &self,
        request: Request<pb::LoginAbortRequest>,
    ) -> Result<Response<()>, Status> {
        let username = request.into_inner().username;
        let mut pending = self.state.pending_login.lock().await;
        if pending
            .as_ref()
            .map(|item| username.is_empty() || item.username.eq_ignore_ascii_case(&username))
            .unwrap_or(false)
        {
            *pending = None;
            self.emit_login_error("login aborted");
        }
        drop(pending);
        if username.is_empty() {
            *self.state.pending_hv.lock().await = None;
        } else {
            let mut pending_hv = self.state.pending_hv.lock().await;
            if pending_hv
                .as_ref()
                .map(|item| item.username.eq_ignore_ascii_case(&username))
                .unwrap_or(false)
            {
                *pending_hv = None;
            }
        }
        Ok(Response::new(()))
    }

    async fn fido_assertion_abort(
        &self,
        request: Request<pb::LoginAbortRequest>,
    ) -> Result<Response<()>, Status> {
        let username = request.into_inner().username;
        let mut pending = self.state.pending_login.lock().await;
        let should_abort = pending
            .as_ref()
            .map(|item| {
                item.fido_authentication_options.is_some()
                    && (username.is_empty() || item.username.eq_ignore_ascii_case(&username))
            })
            .unwrap_or(false);
        if should_abort {
            *pending = None;
            self.emit_login_error("fido assertion aborted");
        }
        Ok(Response::new(()))
    }

    async fn get_user_list(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::UserListResponse>, Status> {
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let users = sessions
            .iter()
            .map(|session| {
                let split_mode =
                    vault::load_split_mode_by_account_id(self.settings_dir(), &session.uid)
                        .ok()
                        .flatten()
                        .unwrap_or(false);
                session_to_user(session, split_mode)
            })
            .collect();
        Ok(Response::new(pb::UserListResponse { users }))
    }

    async fn get_user(&self, request: Request<String>) -> Result<Response<pb::User>, Status> {
        let lookup = request.into_inner();
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(&lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
        let split_mode = vault::load_split_mode_by_account_id(self.settings_dir(), &session.uid)
            .ok()
            .flatten()
            .unwrap_or(false);
        Ok(Response::new(session_to_user(session, split_mode)))
    }

    async fn set_user_split_mode(
        &self,
        request: Request<pb::UserSplitModeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let account_id = sessions
            .iter()
            .find(|s| s.uid == req.user_id || s.email.eq_ignore_ascii_case(&req.user_id))
            .map(|s| s.uid.clone())
            .ok_or_else(|| Status::not_found("user not found"))?;

        vault::save_split_mode_by_account_id(self.settings_dir(), &account_id, req.active)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        self.emit_user_changed(&account_id);
        tracing::info!(
            user_id = %account_id,
            active = req.active,
            "set user split mode applied"
        );
        Ok(Response::new(()))
    }

    async fn send_bad_event_user_feedback(
        &self,
        request: Request<pb::UserBadEventFeedbackRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let lookup = req.user_id.trim();
        if lookup.is_empty() {
            return Err(Status::invalid_argument("user id is required"));
        }
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
        tracing::warn!(
            user_id = %session.uid,
            do_resync = req.do_resync,
            "user bad event feedback received"
        );

        if req.do_resync {
            self.refresh_sync_workers().await.map_err(|err| {
                Status::internal(format!("failed to refresh sync workers: {err}"))
            })?;
            return Ok(Response::new(()));
        }

        vault::remove_session_by_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        self.emit_user_disconnected(&session.email);
        self.refresh_sync_workers_for_transition("send_bad_event_user_feedback_logout")
            .await;
        Ok(Response::new(()))
    }

    async fn logout_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let value = request.into_inner();
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == value || s.email.eq_ignore_ascii_case(&value))
            .ok_or_else(|| Status::not_found("user not found"))?;

        vault::remove_session_by_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        self.emit_user_disconnected(&session.email);
        self.refresh_sync_workers_for_transition("logout_user")
            .await;
        Ok(Response::new(()))
    }

    async fn remove_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        self.logout_user(request).await
    }

    async fn configure_user_apple_mail(
        &self,
        request: Request<pb::ConfigureAppleMailRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let lookup = req.user_id.trim();
        if lookup.is_empty() {
            return Err(Status::invalid_argument("user id is required"));
        }
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
        let requested_address = req.address.trim();
        if !requested_address.is_empty() && !session.email.eq_ignore_ascii_case(requested_address) {
            return Err(Status::invalid_argument(
                "address must match a known user address",
            ));
        }

        let mut changed_settings = None;
        {
            let mut settings = self.state.mail_settings.lock().await;
            if !settings.use_ssl_for_smtp {
                settings.use_ssl_for_smtp = true;
                save_mail_settings(&self.grpc_mail_settings_path(), &settings)
                    .await
                    .map_err(|e| Status::internal(format!("failed to save mail settings: {e}")))?;
                changed_settings = Some(settings.clone());
            }
        }
        if let Some(settings) = changed_settings.as_ref() {
            self.emit_mail_settings_changed(settings);
        }

        tracing::info!(
            user_id = %session.uid,
            address = %if requested_address.is_empty() {
                session.email.as_str()
            } else {
                requested_address
            },
            "configure user apple mail requested; automatic platform integration is unavailable"
        );
        Err(Status::unimplemented(
            "Apple Mail auto-configuration is not implemented",
        ))
    }

    async fn check_update(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn install_update(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!("install update requested; triggering controlled shutdown");
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(()))
    }

    async fn set_is_automatic_update_on(
        &self,
        request: Request<bool>,
    ) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_automatic_update_on = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_automatic_update_on(
        &self,
        _request: Request<()>,
    ) -> Result<Response<bool>, Status> {
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_automatic_update_on))
    }

    async fn available_keychains(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::AvailableKeychainsResponse>, Status> {
        let keychains = available_keychain_helpers();
        Ok(Response::new(pb::AvailableKeychainsResponse { keychains }))
    }

    async fn set_current_keychain(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let keychain = request.into_inner();
        let available = available_keychain_helpers();
        self.set_current_keychain_with_available(&keychain, &available)
            .await?;
        Ok(Response::new(()))
    }

    async fn current_keychain(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        if let Some(helper) = vault::get_keychain_helper(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?
        {
            return Ok(Response::new(helper));
        }
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.current_keychain.clone()))
    }

    async fn mail_server_settings(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::ImapSmtpSettings>, Status> {
        let settings = self.state.mail_settings.lock().await.clone();
        Ok(Response::new(pb::ImapSmtpSettings {
            imap_port: settings.imap_port,
            smtp_port: settings.smtp_port,
            use_ssl_for_imap: settings.use_ssl_for_imap,
            use_ssl_for_smtp: settings.use_ssl_for_smtp,
        }))
    }

    async fn set_mail_server_settings(
        &self,
        request: Request<pb::ImapSmtpSettings>,
    ) -> Result<Response<()>, Status> {
        let incoming = request.into_inner();
        if let Some(status) = validate_port(incoming.imap_port) {
            return Err(status);
        }
        if let Some(status) = validate_port(incoming.smtp_port) {
            return Err(status);
        }

        if !is_port_free(incoming.imap_port as u16).await {
            self.emit_mail_settings_error(pb::MailServerSettingsErrorType::ImapPortChangeError);
            return Err(Status::failed_precondition("IMAP port is not available"));
        }
        if !is_port_free(incoming.smtp_port as u16).await {
            self.emit_mail_settings_error(pb::MailServerSettingsErrorType::SmtpPortChangeError);
            return Err(Status::failed_precondition("SMTP port is not available"));
        }

        let mut settings = self.state.mail_settings.lock().await;
        settings.imap_port = incoming.imap_port;
        settings.smtp_port = incoming.smtp_port;
        settings.use_ssl_for_imap = incoming.use_ssl_for_imap;
        settings.use_ssl_for_smtp = incoming.use_ssl_for_smtp;
        save_mail_settings(&self.grpc_mail_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save mail settings: {e}")))?;

        let snapshot = settings.clone();
        drop(settings);
        self.emit_mail_settings_changed(&snapshot);
        self.emit_mail_settings_finished();

        Ok(Response::new(()))
    }

    async fn hostname(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new(self.state.bind_host.clone()))
    }

    async fn is_port_free(&self, request: Request<i32>) -> Result<Response<bool>, Status> {
        let port = request.into_inner();
        if !(1..=65535).contains(&port) {
            return Ok(Response::new(false));
        }
        Ok(Response::new(is_port_free(port as u16).await))
    }

    async fn is_tls_certificate_installed(
        &self,
        _request: Request<()>,
    ) -> Result<Response<bool>, Status> {
        let (cert_path, key_path) = mail_cert_paths(self.settings_dir());
        Ok(Response::new(cert_path.exists() && key_path.exists()))
    }

    async fn install_tls_certificate(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        ensure_mail_tls_certificate(self.settings_dir())
            .await
            .map_err(|e| Status::internal(format!("failed to install TLS certificate: {e}")))?;
        Ok(Response::new(()))
    }

    async fn export_tls_certificates(
        &self,
        request: Request<String>,
    ) -> Result<Response<()>, Status> {
        let output_dir = request.into_inner();
        if output_dir.trim().is_empty() {
            return Err(Status::invalid_argument("output folder is required"));
        }

        ensure_mail_tls_certificate(self.settings_dir())
            .await
            .map_err(|e| Status::internal(format!("failed to ensure TLS certificate: {e}")))?;

        let (cert_path, key_path) = mail_cert_paths(self.settings_dir());
        let cert_bytes = tokio::fs::read(cert_path)
            .await
            .map_err(|e| Status::internal(format!("failed to read cert: {e}")))?;
        let key_bytes = tokio::fs::read(key_path)
            .await
            .map_err(|e| Status::internal(format!("failed to read key: {e}")))?;

        let target = PathBuf::from(output_dir);
        tokio::fs::create_dir_all(&target)
            .await
            .map_err(|e| Status::internal(format!("failed to create output folder: {e}")))?;
        tokio::fs::write(target.join("cert.pem"), cert_bytes)
            .await
            .map_err(|e| Status::internal(format!("failed to write cert: {e}")))?;
        tokio::fs::write(target.join("key.pem"), key_bytes)
            .await
            .map_err(|e| Status::internal(format!("failed to write key: {e}")))?;

        Ok(Response::new(()))
    }

    type RunEventStreamStream =
        Pin<Box<dyn Stream<Item = Result<pb::StreamEvent, Status>> + Send + 'static>>;

    async fn run_event_stream(
        &self,
        _request: Request<pb::EventStreamRequest>,
    ) -> Result<Response<Self::RunEventStreamStream>, Status> {
        let mut active = self.state.active_stream_stop.lock().await;
        if active.is_some() {
            return Err(Status::already_exists("the service is already streaming"));
        }

        let (stop_tx, mut stop_rx) = watch::channel(false);
        *active = Some(stop_tx);
        drop(active);

        let (mut rx, buffered_events) = {
            let backlog = self
                .state
                .event_backlog
                .lock()
                .map_err(|_| Status::internal("event backlog lock poisoned"))?;
            let buffered = backlog.iter().cloned().collect::<Vec<_>>();
            let rx = self.state.event_tx.subscribe();
            (rx, buffered)
        };
        let (out_tx, out_rx) = mpsc::channel::<Result<pb::StreamEvent, Status>>(32);
        let state = self.state.clone();

        tokio::spawn(async move {
            for buffered in buffered_events {
                if out_tx.send(Ok(buffered)).await.is_err() {
                    let mut active = state.active_stream_stop.lock().await;
                    *active = None;
                    return;
                }
            }
            loop {
                tokio::select! {
                    _ = out_tx.closed() => {
                        break;
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    recv = rx.recv() => {
                        match recv {
                            Ok(event) => {
                                if out_tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
            let mut active = state.active_stream_stop.lock().await;
            *active = None;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }

    async fn stop_event_stream(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        let active = self.state.active_stream_stop.lock().await;
        let Some(stop_tx) = active.as_ref() else {
            return Err(Status::not_found("the service is not streaming"));
        };
        let _ = stop_tx.send(true);
        Ok(Response::new(()))
    }

    async fn version(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new(env!("CARGO_PKG_VERSION").to_string()))
    }

    async fn go_os(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new(std::env::consts::OS.to_string()))
    }

    async fn quit(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(()))
    }
}

pub async fn run_server(runtime_paths: RuntimePaths, bind_host: String) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(runtime_paths.settings_dir())
        .await
        .with_context(|| {
            format!(
                "failed to create settings dir {}",
                runtime_paths.settings_dir().display()
            )
        })?;

    let listener = TcpListener::bind(format!("{bind_host}:0"))
        .await
        .with_context(|| format!("failed to bind gRPC listener on {bind_host}"))?;
    let port = listener
        .local_addr()
        .context("failed to read listener local address")?
        .port();

    let grpc_server_config_path = runtime_paths.grpc_server_config_path();
    let grpc_mail_settings_path = runtime_paths.grpc_mail_settings_path();
    let grpc_app_settings_path = runtime_paths.grpc_app_settings_path();
    let disk_cache_dir = runtime_paths.disk_cache_dir();

    let token = generate_server_token();
    let (cert_pem, key_pem) = generate_ephemeral_tls_cert()?;
    write_server_config(
        &grpc_server_config_path,
        &GrpcServerConfig {
            port,
            cert: cert_pem.clone(),
            token: token.clone(),
            file_socket_path: String::new(),
        },
    )
    .await?;

    let settings = load_mail_settings(&grpc_mail_settings_path).await?;
    let app_settings = load_app_settings(&grpc_app_settings_path, &disk_cache_dir).await?;
    let active_disk_cache_path = effective_disk_cache_path(&app_settings, &runtime_paths);
    tokio::fs::create_dir_all(&active_disk_cache_path)
        .await
        .with_context(|| {
            format!(
                "failed to create active disk cache path {}",
                active_disk_cache_path.display()
            )
        })?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, _) = broadcast::channel(128);
    let state = Arc::new(GrpcState {
        runtime_paths: runtime_paths.clone(),
        bind_host,
        active_disk_cache_path: Mutex::new(active_disk_cache_path),
        event_tx,
        event_backlog: std::sync::Mutex::new(VecDeque::new()),
        active_stream_stop: Mutex::new(None),
        pending_login: Mutex::new(None),
        pending_hv: Mutex::new(None),
        shutdown_tx: shutdown_tx.clone(),
        mail_settings: Mutex::new(settings),
        app_settings: Mutex::new(app_settings),
        sync_workers_enabled: true,
        sync_event_workers: Mutex::new(None),
    });

    let service = BridgeService::new(state);
    service
        .refresh_sync_workers()
        .await
        .context("failed to start grpc sync workers")?;
    let service_for_shutdown = service.clone();
    let expected_token = token;
    let bridge_svc =
        pb::bridge_server::BridgeServer::with_interceptor(service, move |req: Request<()>| {
            if let Some(status) = validate_server_token(req.metadata(), &expected_token) {
                return Err(status);
            }
            Ok(req)
        });

    let tls_identity = Identity::from_pem(cert_pem, key_pem);
    let shutdown_tx_ctrlc = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx_ctrlc.send(true);
    });

    info!(port, "grpc frontend service listening");

    let server_result = async {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(tls_identity))
            .context("failed to configure gRPC TLS")?
            .add_service(bridge_svc)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                wait_for_shutdown(shutdown_rx).await;
            })
            .await
            .context("gRPC server exited with error")
    }
    .await;

    service_for_shutdown.shutdown_sync_workers().await;

    server_result
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    loop {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

async fn maybe_start_grpc_sync_workers(
    runtime_paths: &RuntimePaths,
    service: &BridgeService,
    active_disk_cache_path: &Path,
) -> anyhow::Result<Option<bridge::events::EventWorkerGroup>> {
    let sessions = match vault::list_sessions(runtime_paths.settings_dir()) {
        Ok(sessions) => sessions,
        Err(err) => {
            warn!(
                error = %err,
                "failed to load sessions for grpc sync workers; skipping startup"
            );
            return Ok(None);
        }
    };

    if sessions.is_empty() {
        return Ok(None);
    }

    let mut account_registry = bridge::accounts::AccountRegistry::from_sessions(sessions.clone());
    for session in &sessions {
        let account_id = bridge::types::AccountId(session.uid.clone());
        if let Ok(split_mode) =
            vault::load_split_mode_by_account_id(runtime_paths.settings_dir(), &session.uid)
        {
            let _ = account_registry.set_split_mode(&account_id, split_mode.unwrap_or(false));
        }
    }

    let auth_router = bridge::auth_router::AuthRouter::new(account_registry);
    let runtime_accounts = Arc::new(bridge::accounts::RuntimeAccountRegistry::new(
        sessions,
        runtime_paths.settings_dir().to_path_buf(),
    ));
    let runtime_snapshot = runtime_accounts.snapshot().await;
    if runtime_snapshot.is_empty() {
        return Ok(None);
    }

    let store_root = active_disk_cache_path.join("imap-store");
    let store: Arc<dyn crate::imap::store::MessageStore> =
        crate::imap::store::PersistentStore::new(store_root)?;
    let checkpoint_store: bridge::events::SharedCheckpointStore = Arc::new(
        bridge::events::VaultCheckpointStore::new(runtime_paths.settings_dir().to_path_buf()),
    );

    let callback_service = service.clone();
    let sync_progress_callback: bridge::events::SyncProgressCallback =
        Arc::new(move |event| match event {
            bridge::events::SyncProgressUpdate::Started { user_id } => {
                callback_service.emit_sync_started(&user_id);
            }
            bridge::events::SyncProgressUpdate::Progress {
                user_id,
                progress,
                elapsed_ms,
                remaining_ms,
            } => {
                callback_service.emit_sync_progress(&user_id, progress, elapsed_ms, remaining_ms);
            }
            bridge::events::SyncProgressUpdate::Finished { user_id } => {
                callback_service.emit_sync_finished(&user_id);
            }
        });

    Ok(Some(
        bridge::events::start_event_worker_group_with_sync_progress(
            runtime_accounts,
            runtime_snapshot,
            "https://mail-api.proton.me".to_string(),
            auth_router,
            store,
            checkpoint_store,
            Some(sync_progress_callback),
            std::time::Duration::from_secs(30),
        ),
    ))
}

fn status_from_api_error(err: ApiError) -> Status {
    match err {
        ApiError::TwoFactorRequired => Status::failed_precondition("2FA required"),
        ApiError::NotLoggedIn => Status::unauthenticated("not logged in"),
        ApiError::SessionExpired => Status::unauthenticated("session expired"),
        ApiError::Auth(message) => Status::unauthenticated(message),
        ApiError::Api {
            code,
            message,
            details,
        } => match code {
            9001 => {
                let hv_url = details
                    .as_ref()
                    .and_then(|details| {
                        serde_json::from_value::<HumanVerificationDetails>(details.clone()).ok()
                    })
                    .filter(HumanVerificationDetails::is_usable)
                    .map(|details| details.challenge_url());
                let details_hint = hv_url
                    .map(|url| format!(" Open this URL to complete verification: {url}."))
                    .unwrap_or_default();
                Status::failed_precondition(format!(
                    "captcha required by Proton; complete CAPTCHA in Proton web/app, then retry login.{details_hint} \
If you cannot complete it, update Proton Bridge or contact support: {CAPTCHA_APPEAL_URL} \
(api error {code}: {message})"
                ))
            }
            12087 => {
                let hv_url = details
                    .as_ref()
                    .and_then(|details| {
                        serde_json::from_value::<HumanVerificationDetails>(details.clone()).ok()
                    })
                    .filter(HumanVerificationDetails::is_usable)
                    .map(|details| details.challenge_url());
                let details_hint = hv_url
                    .map(|url| format!(" Open this URL and complete CAPTCHA again: {url}."))
                    .unwrap_or_default();
                Status::failed_precondition(format!(
                    "captcha validation failed; complete CAPTCHA again, then retry login (or restart login for a new challenge).{details_hint} \
If your client captures the `pm_captcha` token, send it as `humanVerificationToken`. \
(api error {code}: {message})"
                ))
            }
            401 | 8002 | 10013 => Status::unauthenticated(format!("api error {code}: {message}")),
            _ => Status::internal(format!("api error {code}: {message}")),
        },
        ApiError::Http(err) => Status::unavailable(format!("http error: {err}")),
        ApiError::Json(err) => Status::internal(format!("json error: {err}")),
        ApiError::Io(err) => Status::internal(format!("io error: {err}")),
        ApiError::Srp(err) => Status::internal(format!("srp error: {err}")),
    }
}

fn status_from_vault_error(err: vault::VaultError) -> Status {
    match err {
        vault::VaultError::MissingVaultKey => Status::failed_precondition(
            "vault key is missing for an existing vault; restore keychain entry or vault.key",
        ),
        vault::VaultError::KeychainAccess(message) => Status::failed_precondition(format!(
            "keychain access failed while loading existing vault: {message}"
        )),
        other => Status::internal(format!("vault error: {other}")),
    }
}

fn session_to_user(session: &Session, split_mode: bool) -> pb::User {
    let avatar_text = session
        .email
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "U".to_string());

    pb::User {
        id: session.uid.clone(),
        username: session.email.clone(),
        avatar_text,
        state: pb::UserState::Connected as i32,
        split_mode,
        used_bytes: 0,
        total_bytes: 0,
        password: session
            .bridge_password
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        addresses: vec![session.email.clone()],
    }
}

fn validate_server_token(metadata: &MetadataMap, expected_token: &str) -> Option<Status> {
    let token = match metadata.get(SERVER_TOKEN_METADATA_KEY) {
        Some(token) => token,
        None => return Some(Status::unauthenticated("missing server-token metadata")),
    };
    let token = match token.to_str() {
        Ok(token) => token,
        Err(_) => return Some(Status::unauthenticated("invalid server-token metadata")),
    };
    if token != expected_token {
        return Some(Status::unauthenticated("invalid server-token"));
    }
    None
}

fn validate_port(port: i32) -> Option<Status> {
    if !(1..=65535).contains(&port) {
        return Some(Status::invalid_argument(format!(
            "port must be between 1 and 65535, got {port}"
        )));
    }
    None
}

async fn is_port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).await.is_ok()
}

fn generate_server_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn generate_bridge_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

fn resolve_license_path() -> String {
    resolve_license_path_with_exe(std::env::current_exe().ok().as_deref())
}

fn resolve_license_path_with_exe(exe_path: Option<&Path>) -> String {
    if let Some(exe_path) = exe_path {
        if let Some(exe_dir) = exe_path.parent() {
            let local_name = if std::env::consts::OS == "windows" {
                "LICENSE.txt"
            } else {
                "LICENSE"
            };
            let local_path = exe_dir.join(local_name);
            if local_path.exists() {
                return local_path.display().to_string();
            }

            if std::env::consts::OS == "macos" {
                let resources_path = exe_dir.join("..").join("Resources").join("LICENSE");
                if resources_path.exists() {
                    return resources_path.display().to_string();
                }
            }
        }
    }

    match std::env::consts::OS {
        "linux" => {
            let distro_path = PathBuf::from("/usr/share/doc/protonmail/bridge/LICENSE");
            if distro_path.exists() {
                distro_path.display().to_string()
            } else {
                "/usr/share/licenses/protonmail-bridge/LICENSE".to_string()
            }
        }
        "macos" => "/Applications/Proton Mail Bridge.app/Contents/Resources/LICENSE".to_string(),
        "windows" => "C:\\Program Files\\Proton\\Proton Mail Bridge\\LICENSE.txt".to_string(),
        _ => String::new(),
    }
}

fn generate_ephemeral_tls_cert() -> anyhow::Result<(String, String)> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .context("failed to generate gRPC self-signed certificate")?;
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

async fn write_server_config(path: &Path, cfg: &GrpcServerConfig) -> anyhow::Result<()> {
    let tmp_path = path.with_file_name(format!("{SERVER_CONFIG_FILE}.tmp"));
    let payload = serde_json::to_vec_pretty(cfg).context("failed to encode server config")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write temp server config {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, path)
        .await
        .with_context(|| format!("failed to rename server config to {}", path.display()))?;
    info!(path = %path.display(), "saved grpc server config");
    Ok(())
}

async fn load_mail_settings(path: &Path) -> anyhow::Result<StoredMailSettings> {
    if !path.exists() {
        return Ok(StoredMailSettings::default());
    }
    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&payload).with_context(|| format!("failed to parse {}", path.display()))
}

async fn save_mail_settings(path: &Path, settings: &StoredMailSettings) -> anyhow::Result<()> {
    let tmp_path = path.with_file_name(format!("{MAIL_SETTINGS_FILE}.tmp"));
    let payload = serde_json::to_vec_pretty(settings).context("failed to encode mail settings")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, path)
        .await
        .with_context(|| format!("failed to rename settings file {}", path.display()))?;
    Ok(())
}

async fn load_app_settings(
    path: &Path,
    disk_cache_dir: &Path,
) -> anyhow::Result<StoredAppSettings> {
    if !path.exists() {
        return Ok(StoredAppSettings::with_defaults_for(disk_cache_dir));
    }

    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&payload).with_context(|| format!("failed to parse {}", path.display()))
}

async fn save_app_settings(path: &Path, settings: &StoredAppSettings) -> anyhow::Result<()> {
    let tmp_path = path.with_file_name(format!("{APP_SETTINGS_FILE}.tmp"));
    let payload = serde_json::to_vec_pretty(settings).context("failed to encode app settings")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, path)
        .await
        .with_context(|| format!("failed to rename settings file {}", path.display()))?;
    Ok(())
}

fn effective_disk_cache_path(
    settings: &StoredAppSettings,
    runtime_paths: &RuntimePaths,
) -> PathBuf {
    let configured = settings.disk_cache_path.trim();
    if configured.is_empty() {
        return runtime_paths.disk_cache_dir();
    }
    PathBuf::from(configured)
}

async fn move_disk_cache_payload(current: &Path, target: &Path) -> anyhow::Result<()> {
    if current == target {
        tokio::fs::create_dir_all(target)
            .await
            .with_context(|| format!("failed to create disk cache path {}", target.display()))?;
        return Ok(());
    }

    if target.starts_with(current) {
        anyhow::bail!(
            "target disk cache path {} must not be inside current path {}",
            target.display(),
            current.display()
        );
    }

    tokio::fs::create_dir_all(target)
        .await
        .with_context(|| format!("failed to create disk cache path {}", target.display()))?;

    if tokio::fs::metadata(current).await.is_err() {
        return Ok(());
    }

    copy_dir_contents(current, target).await?;

    if let Err(err) = tokio::fs::remove_dir_all(current).await {
        warn!(
            error = %err,
            old_path = %current.display(),
            "failed to clean old disk cache path after successful move"
        );
    }

    Ok(())
}

async fn copy_dir_contents(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];

    while let Some((current_src, current_dst)) = stack.pop() {
        tokio::fs::create_dir_all(&current_dst)
            .await
            .with_context(|| format!("failed to create directory {}", current_dst.display()))?;

        let mut entries = tokio::fs::read_dir(&current_src)
            .await
            .with_context(|| format!("failed to read directory {}", current_src.display()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("failed reading entries for {}", current_src.display()))?
        {
            let src_path = entry.path();
            let dst_path = current_dst.join(entry.file_name());
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("failed to read file type for {}", src_path.display()))?;

            if file_type.is_dir() {
                stack.push((src_path, dst_path));
                continue;
            }

            if file_type.is_file() {
                tokio::fs::copy(&src_path, &dst_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to copy file from {} to {}",
                            src_path.display(),
                            dst_path.display()
                        )
                    })?;
            }
        }
    }

    Ok(())
}

fn mail_cert_paths(vault_dir: &Path) -> (PathBuf, PathBuf) {
    let cert_dir = vault_dir.join("tls");
    (cert_dir.join("cert.pem"), cert_dir.join("key.pem"))
}

async fn ensure_mail_tls_certificate(vault_dir: &Path) -> anyhow::Result<()> {
    let (cert_path, key_path) = mail_cert_paths(vault_dir);
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    let cert_dir = cert_path
        .parent()
        .context("invalid certificate directory")?
        .to_path_buf();
    tokio::fs::create_dir_all(&cert_dir)
        .await
        .with_context(|| format!("failed to create cert dir {}", cert_dir.display()))?;

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .context("failed to generate mail TLS certificate")?;
    tokio::fs::write(&cert_path, cert.cert.pem())
        .await
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    tokio::fs::write(&key_path, cert.key_pair.serialize_pem())
        .await
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;
    use std::time::Duration;
    use tokio_stream::StreamExt;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PROTON_FIXTURE_VAULT_ENC: &[u8] =
        include_bytes!("../../tests/fixtures/proton_profile_golden/vault.enc");
    const PROTON_FIXTURE_VAULT_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/proton_profile_golden/vault.key");
    const PROTON_FIXTURE_DEFAULT_EMAIL: &str =
        include_str!("../../tests/fixtures/proton_profile_golden/default_email");

    fn write_proton_golden_fixture(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vault.enc"), PROTON_FIXTURE_VAULT_ENC).unwrap();
        std::fs::write(dir.join("vault.key"), PROTON_FIXTURE_VAULT_KEY).unwrap();
        std::fs::write(
            dir.join("default_email"),
            PROTON_FIXTURE_DEFAULT_EMAIL.trim().as_bytes(),
        )
        .unwrap();
    }

    fn build_test_service_with_paths(runtime_paths: RuntimePaths) -> BridgeService {
        let app_settings = StoredAppSettings::with_defaults_for(&runtime_paths.disk_cache_dir());
        let active_disk_cache_path = effective_disk_cache_path(&app_settings, &runtime_paths);
        let (event_tx, _) = broadcast::channel(16);
        let (shutdown_tx, _) = watch::channel(false);
        let state = Arc::new(GrpcState {
            app_settings: Mutex::new(app_settings),
            runtime_paths,
            bind_host: "127.0.0.1".to_string(),
            active_disk_cache_path: Mutex::new(active_disk_cache_path),
            event_tx,
            event_backlog: std::sync::Mutex::new(VecDeque::new()),
            active_stream_stop: Mutex::new(None),
            pending_login: Mutex::new(None),
            pending_hv: Mutex::new(None),
            shutdown_tx,
            mail_settings: Mutex::new(StoredMailSettings::default()),
            sync_workers_enabled: false,
            sync_event_workers: Mutex::new(None),
        });
        BridgeService::new(state)
    }

    fn build_test_service(vault_dir: PathBuf) -> BridgeService {
        let runtime_paths = RuntimePaths::resolve(Some(&vault_dir)).unwrap();
        build_test_service_with_paths(runtime_paths)
    }

    async fn call_login_fido(
        service: &BridgeService,
        username: &str,
        payload: &[u8],
    ) -> Result<Response<()>, Status> {
        <BridgeService as pb::bridge_server::Bridge>::login_fido(
            service,
            Request::new(pb::LoginRequest {
                username: username.to_string(),
                password: payload.to_vec(),
                use_hv_details: None,
                human_verification_token: None,
            }),
        )
        .await
    }

    #[test]
    fn validate_server_token_works() {
        let mut meta = MetadataMap::new();
        meta.insert(SERVER_TOKEN_METADATA_KEY, "abc123".parse().unwrap());
        assert!(validate_server_token(&meta, "abc123").is_none());
        assert!(validate_server_token(&meta, "wrong").is_some());
    }

    #[test]
    fn status_from_api_error_maps_captcha_to_failed_precondition() {
        let status = status_from_api_error(ApiError::Api {
            code: 9001,
            message: "For security reasons, please complete CAPTCHA".to_string(),
            details: None,
        });
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().to_ascii_lowercase().contains("captcha"));
        assert!(status.message().contains(CAPTCHA_APPEAL_URL));
    }

    #[test]
    fn status_from_api_error_maps_invalid_credentials_to_unauthenticated() {
        let status = status_from_api_error(ApiError::Api {
            code: 8002,
            message: "Invalid credentials".to_string(),
            details: None,
        });
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn status_from_api_error_maps_captcha_validation_failed_to_failed_precondition() {
        let status = status_from_api_error(ApiError::Api {
            code: 12087,
            message: "CAPTCHA validation failed".to_string(),
            details: None,
        });
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().to_ascii_lowercase().contains("captcha"));
    }

    #[test]
    fn status_from_api_error_maps_captcha_details_to_verify_url() {
        let status = status_from_api_error(ApiError::Api {
            code: 9001,
            message: "Human verification required".to_string(),
            details: Some(json!({
                "HumanVerificationMethods": ["captcha"],
                "HumanVerificationToken": "token-123"
            })),
        });
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status
            .message()
            .contains("https://verify.proton.me/?methods=captcha&token=token-123"));
    }

    #[test]
    fn status_from_vault_error_maps_keychain_failures_to_failed_precondition() {
        let missing_key_status = status_from_vault_error(vault::VaultError::MissingVaultKey);
        assert_eq!(missing_key_status.code(), tonic::Code::FailedPrecondition);

        let keychain_status =
            status_from_vault_error(vault::VaultError::KeychainAccess("denied".to_string()));
        assert_eq!(keychain_status.code(), tonic::Code::FailedPrecondition);
        assert!(keychain_status.message().contains("denied"));
    }

    #[tokio::test]
    async fn status_from_vault_error_with_events_emits_rebuild_keychain() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let status =
            service.status_from_vault_error_with_events(vault::VaultError::MissingVaultKey);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::Keychain(pb::KeychainEvent {
                event: Some(pb::keychain_event::Event::RebuildKeychain(_)),
            })) => {}
            other => panic!("unexpected keychain rebuild event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mail_settings_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MAIL_SETTINGS_FILE);
        let settings = StoredMailSettings {
            imap_port: 1144,
            smtp_port: 1026,
            use_ssl_for_imap: true,
            use_ssl_for_smtp: true,
        };
        save_mail_settings(&path, &settings).await.unwrap();
        let loaded = load_mail_settings(&path).await.unwrap();
        assert_eq!(loaded.imap_port, 1144);
        assert_eq!(loaded.smtp_port, 1026);
        assert!(loaded.use_ssl_for_imap);
        assert!(loaded.use_ssl_for_smtp);
    }

    #[tokio::test]
    async fn app_settings_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APP_SETTINGS_FILE);
        let disk_cache_dir = dir.path().join("disk");
        let settings = StoredAppSettings {
            show_on_startup: false,
            is_autostart_on: true,
            is_beta_enabled: true,
            is_all_mail_visible: false,
            is_telemetry_disabled: true,
            disk_cache_path: disk_cache_dir.display().to_string(),
            is_doh_enabled: false,
            color_scheme_name: "light".to_string(),
            is_automatic_update_on: false,
            current_keychain: "file".to_string(),
            main_executable: "/tmp/bridge-bin".to_string(),
            forced_launcher: "thunderbird".to_string(),
        };
        save_app_settings(&path, &settings).await.unwrap();
        let loaded = load_app_settings(&path, &disk_cache_dir).await.unwrap();
        assert!(!loaded.show_on_startup);
        assert!(loaded.is_autostart_on);
        assert!(loaded.is_beta_enabled);
        assert!(!loaded.is_all_mail_visible);
        assert!(loaded.is_telemetry_disabled);
        assert!(!loaded.is_doh_enabled);
        assert_eq!(loaded.color_scheme_name, "light");
        assert!(!loaded.is_automatic_update_on);
        assert_eq!(loaded.current_keychain, "file");
        assert_eq!(loaded.main_executable, "/tmp/bridge-bin");
        assert_eq!(loaded.forced_launcher, "thunderbird");
    }

    #[tokio::test]
    async fn app_settings_defaults_use_provided_runtime_disk_cache_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APP_SETTINGS_FILE);
        let disk_cache_dir = dir.path().join("runtime-cache");

        let loaded = load_app_settings(&path, &disk_cache_dir).await.unwrap();
        assert_eq!(loaded.disk_cache_path, disk_cache_dir.display().to_string());
    }

    #[tokio::test]
    async fn logs_path_uses_runtime_logs_directory() {
        let root = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::from_bases(
            root.path().join("cfg"),
            root.path().join("data"),
            root.path().join("cache"),
        );
        let expected_logs_dir = runtime_paths.logs_dir();
        let settings_logs_dir = runtime_paths.settings_dir().join("logs");
        let service = build_test_service_with_paths(runtime_paths);

        let response =
            <BridgeService as pb::bridge_server::Bridge>::logs_path(&service, Request::new(()))
                .await
                .unwrap();

        let logs_path = PathBuf::from(response.into_inner());
        assert_eq!(logs_path, expected_logs_dir);
        assert!(expected_logs_dir.exists());
        assert!(!settings_logs_dir.exists());
    }

    #[test]
    fn resolve_license_path_with_exe_prefers_adjacent_license_file() {
        let dir = tempfile::tempdir().unwrap();
        let exe_path = dir.path().join("bridge-bin");
        std::fs::write(&exe_path, b"").unwrap();

        let license_name = if std::env::consts::OS == "windows" {
            "LICENSE.txt"
        } else {
            "LICENSE"
        };
        let license_path = dir.path().join(license_name);
        std::fs::write(&license_path, b"license").unwrap();

        let resolved = resolve_license_path_with_exe(Some(&exe_path));
        assert_eq!(resolved, license_path.display().to_string());
    }

    #[tokio::test]
    async fn current_email_client_uses_proton_default_user_agent_shape() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let current =
            <BridgeService as pb::bridge_server::Bridge>::current_email_client(
                &service,
                Request::new(()),
            )
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            current,
            format!("{DEFAULT_EMAIL_CLIENT} ({})", std::env::consts::OS)
        );
    }

    #[tokio::test]
    async fn sync_user_events_emit_expected_stream_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        service.emit_sync_started("uid-1");
        service.emit_sync_progress("uid-1", 0.42, 210, 290);
        service.emit_sync_finished("uid-1");

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
            }
            other => panic!("unexpected first sync event: {other:?}"),
        }

        let second = events.recv().await.unwrap();
        match second.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
                assert!((event.progress - 0.42).abs() < f64::EPSILON);
                assert_eq!(event.elapsed_ms, 210);
                assert_eq!(event.remaining_ms, 290);
            }
            other => panic!("unexpected second sync event: {other:?}"),
        }

        let third = events.recv().await.unwrap();
        match third.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
            }
            other => panic!("unexpected third sync event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn report_bug_emits_success_then_finished() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        <BridgeService as pb::bridge_server::Bridge>::report_bug(
            &service,
            Request::new(pb::ReportBugRequest {
                os_type: "linux".to_string(),
                os_version: "6.1".to_string(),
                title: "sample".to_string(),
                description: "details".to_string(),
                address: "alice@proton.me".to_string(),
                email_client: "thunderbird".to_string(),
                include_logs: true,
            }),
        )
        .await
        .unwrap();

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::ReportBugSuccess(_)),
            })) => {}
            other => panic!("unexpected first report bug event: {other:?}"),
        }

        let second = events.recv().await.unwrap();
        match second.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::ReportBugFinished(_)),
            })) => {}
            other => panic!("unexpected second report bug event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn report_bug_missing_required_fields_emits_error_then_finished() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        <BridgeService as pb::bridge_server::Bridge>::report_bug(
            &service,
            Request::new(pb::ReportBugRequest {
                os_type: "linux".to_string(),
                os_version: "6.1".to_string(),
                title: "   ".to_string(),
                description: "".to_string(),
                address: "alice@proton.me".to_string(),
                email_client: "thunderbird".to_string(),
                include_logs: true,
            }),
        )
        .await
        .unwrap();

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::ReportBugError(_)),
            })) => {}
            other => panic!("unexpected first report bug error event: {other:?}"),
        }

        let second = events.recv().await.unwrap();
        match second.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::ReportBugFinished(_)),
            })) => {}
            other => panic!("unexpected second report bug finished event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_knowledge_base_suggestions_emits_suggestions_event() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        <BridgeService as pb::bridge_server::Bridge>::request_knowledge_base_suggestions(
            &service,
            Request::new("imap login failure".to_string()),
        )
        .await
        .unwrap();

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::KnowledgeBaseSuggestions(event)),
            })) => {
                assert_eq!(event.suggestions.len(), 1);
                let suggestion = &event.suggestions[0];
                assert!(suggestion.url.contains("proton.me/support/search"));
                assert!(suggestion.url.contains("imap+login+failure"));
                assert!(suggestion.title.contains("imap login failure"));
            }
            other => panic!("unexpected knowledge base suggestion event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_knowledge_base_suggestions_empty_query_emits_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        <BridgeService as pb::bridge_server::Bridge>::request_knowledge_base_suggestions(
            &service,
            Request::new("   ".to_string()),
        )
        .await
        .unwrap();

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::KnowledgeBaseSuggestions(event)),
            })) => {
                assert!(event.suggestions.is_empty());
            }
            other => panic!("unexpected knowledge base suggestion event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_bad_event_user_feedback_requires_user_id() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let result = <BridgeService as pb::bridge_server::Bridge>::send_bad_event_user_feedback(
            &service,
            Request::new(pb::UserBadEventFeedbackRequest {
                user_id: "   ".to_string(),
                do_resync: false,
            }),
        )
        .await;

        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("user id is required"));
    }

    #[tokio::test]
    async fn send_bad_event_user_feedback_without_resync_logs_user_out_and_emits_disconnect() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();
        let session = Session {
            uid: "uid-bad-event-1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "bad-event@proton.me".to_string(),
            display_name: "Bad Event".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        <BridgeService as pb::bridge_server::Bridge>::send_bad_event_user_feedback(
            &service,
            Request::new(pb::UserBadEventFeedbackRequest {
                user_id: session.uid.clone(),
                do_resync: false,
            }),
        )
        .await
        .unwrap();

        assert!(vault::list_sessions(service.settings_dir())
            .unwrap()
            .is_empty());

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::UserDisconnected(disconnected)),
            })) => {
                assert_eq!(disconnected.username, session.email);
            }
            other => panic!("unexpected bad event feedback result event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_bad_event_user_feedback_with_resync_keeps_user_connected() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();
        let session = Session {
            uid: "uid-bad-event-2".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "resync@proton.me".to_string(),
            display_name: "Resync User".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        <BridgeService as pb::bridge_server::Bridge>::send_bad_event_user_feedback(
            &service,
            Request::new(pb::UserBadEventFeedbackRequest {
                user_id: session.uid.clone(),
                do_resync: true,
            }),
        )
        .await
        .unwrap();

        let sessions = vault::list_sessions(service.settings_dir()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].uid, session.uid);

        let recv_result = tokio::time::timeout(Duration::from_millis(200), events.recv()).await;
        assert!(
            recv_result.is_err(),
            "resync feedback should not emit disconnect event"
        );
    }

    #[tokio::test]
    async fn configure_user_apple_mail_rejects_unknown_user() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let result = <BridgeService as pb::bridge_server::Bridge>::configure_user_apple_mail(
            &service,
            Request::new(pb::ConfigureAppleMailRequest {
                user_id: "missing-user".to_string(),
                address: "missing@proton.me".to_string(),
            }),
        )
        .await;

        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("user not found"));
    }

    #[tokio::test]
    async fn configure_user_apple_mail_rejects_unknown_address() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-apple-mail-1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "apple-user@proton.me".to_string(),
            display_name: "Apple User".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        let result = <BridgeService as pb::bridge_server::Bridge>::configure_user_apple_mail(
            &service,
            Request::new(pb::ConfigureAppleMailRequest {
                user_id: session.uid.clone(),
                address: "different@proton.me".to_string(),
            }),
        )
        .await;

        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("known user address"));
    }

    #[tokio::test]
    async fn configure_user_apple_mail_enables_smtp_ssl_and_emits_settings_changed() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();
        let session = Session {
            uid: "uid-apple-mail-2".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "apple-config@proton.me".to_string(),
            display_name: "Apple Config".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        let result = <BridgeService as pb::bridge_server::Bridge>::configure_user_apple_mail(
            &service,
            Request::new(pb::ConfigureAppleMailRequest {
                user_id: session.uid.clone(),
                address: session.email.clone(),
            }),
        )
        .await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unimplemented);

        let settings = service.state.mail_settings.lock().await;
        assert!(settings.use_ssl_for_smtp);
        drop(settings);

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::MailServerSettings(pb::MailServerSettingsEvent {
                event:
                    Some(pb::mail_server_settings_event::Event::MailServerSettingsChanged(changed)),
            })) => {
                let emitted = changed.settings.expect("mail settings payload");
                assert!(emitted.use_ssl_for_smtp);
            }
            other => panic!("unexpected apple mail event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn available_keychains_uses_helper_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let response = <BridgeService as pb::bridge_server::Bridge>::available_keychains(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response
            .keychains
            .iter()
            .any(|helper| helper == vault::KEYCHAIN_BACKEND_FILE));
        assert_eq!(
            response.keychains,
            available_keychain_helpers_with_backends(&vault::discover_available_keychains())
        );
    }

    #[tokio::test]
    async fn set_current_keychain_rejects_unknown_helper() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let result = <BridgeService as pb::bridge_server::Bridge>::set_current_keychain(
            &service,
            Request::new("unsupported".to_string()),
        )
        .await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("unknown keychain helper"));

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::Keychain(pb::KeychainEvent {
                event: Some(pb::keychain_event::Event::ChangeKeychainFinished(_)),
            })) => {}
            other => panic!("unexpected keychain event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_current_keychain_accepts_discovered_backend() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();
        let mut shutdown = service.state.shutdown_tx.subscribe();
        let selected = vault::KEYCHAIN_BACKEND_FILE.to_string();

        <BridgeService as pb::bridge_server::Bridge>::set_current_keychain(
            &service,
            Request::new(selected.clone()),
        )
        .await
        .unwrap();

        let current = <BridgeService as pb::bridge_server::Bridge>::current_keychain(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(current, selected);
        assert!(service.settings_dir().join("vault.key").exists());
        shutdown.changed().await.unwrap();
        assert!(*shutdown.borrow_and_update());

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::Keychain(pb::KeychainEvent {
                event: Some(pb::keychain_event::Event::ChangeKeychainFinished(_)),
            })) => {}
            other => panic!("unexpected keychain event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_keychain_prefers_persisted_keychain_helper_file() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        vault::set_keychain_helper(service.settings_dir(), KEYCHAIN_HELPER_SECRET_SERVICE_DBUS)
            .unwrap();

        let current = <BridgeService as pb::bridge_server::Bridge>::current_keychain(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(current, KEYCHAIN_HELPER_SECRET_SERVICE_DBUS);
    }

    #[test]
    fn available_keychain_helpers_file_only_when_keyring_backend_missing() {
        let helpers =
            available_keychain_helpers_with_backends(&[vault::KEYCHAIN_BACKEND_FILE.to_string()]);
        assert_eq!(helpers, vec![vault::KEYCHAIN_BACKEND_FILE.to_string()]);
    }

    #[test]
    fn available_keychain_helpers_include_file_and_keyring_alias_when_available() {
        let helpers = available_keychain_helpers_with_backends(&[
            vault::KEYCHAIN_BACKEND_KEYRING.to_string(),
            vault::KEYCHAIN_BACKEND_FILE.to_string(),
        ]);

        assert!(helpers
            .iter()
            .any(|helper| helper == vault::KEYCHAIN_BACKEND_FILE));
        assert!(helpers
            .iter()
            .any(|helper| helper == vault::KEYCHAIN_BACKEND_KEYRING));
    }

    #[tokio::test]
    async fn set_current_keychain_known_but_unavailable_emits_has_no_keychain_and_finished() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let err = service
            .set_current_keychain_with_available(
                vault::KEYCHAIN_BACKEND_KEYRING,
                &[vault::KEYCHAIN_BACKEND_FILE.to_string()],
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("unavailable"));

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::Keychain(pb::KeychainEvent {
                event: Some(pb::keychain_event::Event::HasNoKeychain(_)),
            })) => {}
            other => panic!("unexpected first keychain event payload: {other:?}"),
        }

        let second = events.recv().await.unwrap();
        match second.event {
            Some(pb::stream_event::Event::Keychain(pb::KeychainEvent {
                event: Some(pb::keychain_event::Event::ChangeKeychainFinished(_)),
            })) => {}
            other => panic!("unexpected second keychain event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn trigger_repair_resets_event_checkpoints_and_emits_started() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();
        let session = Session {
            uid: "uid-repair-1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "repair@proton.me".to_string(),
            display_name: "Repair User".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();
        let checkpoint = vault::StoredEventCheckpoint {
            last_event_id: "event-123".to_string(),
            last_event_ts: Some(1_700_000_000),
            sync_state: Some("refresh_resync".to_string()),
        };
        vault::save_event_checkpoint_by_account_id(service.settings_dir(), &session.uid, &checkpoint)
            .unwrap();
        assert!(vault::load_event_checkpoint_by_account_id(service.settings_dir(), &session.uid)
            .unwrap()
            .is_some());

        <BridgeService as pb::bridge_server::Bridge>::trigger_repair(&service, Request::new(()))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if vault::load_event_checkpoint_by_account_id(service.settings_dir(), &session.uid)
                    .unwrap()
                    .is_none()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::RepairStarted(_)),
            })) => {}
            other => panic!("unexpected repair event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn trigger_reset_clears_state_and_emits_reset_finished() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let session = Session {
            uid: "uid-reset-1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "reset@proton.me".to_string(),
            display_name: "Reset User".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        tokio::fs::write(service.grpc_mail_settings_path(), b"{}")
            .await
            .unwrap();
        tokio::fs::write(service.grpc_app_settings_path(), b"{}")
            .await
            .unwrap();

        <BridgeService as pb::bridge_server::Bridge>::trigger_reset(&service, Request::new(()))
            .await
            .unwrap();

        assert!(vault::list_sessions(service.settings_dir())
            .unwrap()
            .is_empty());
        assert!(!service.grpc_mail_settings_path().exists());
        assert!(!service.grpc_app_settings_path().exists());

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::ResetFinished(_)),
            })) => {}
            other => panic!("unexpected trigger reset event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_event_stream_replays_buffered_sync_events_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        service.emit_sync_started("uid-1");
        service.emit_sync_progress("uid-1", 0.42, 210, 290);
        service.emit_sync_finished("uid-1");

        let mut stream = <BridgeService as pb::bridge_server::Bridge>::run_event_stream(
            &service,
            Request::new(pb::EventStreamRequest::default()),
        )
        .await
        .unwrap()
        .into_inner();

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match first.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected first stream event: {other:?}"),
        }

        let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match second.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
                assert!((event.progress - 0.42).abs() < f64::EPSILON);
                assert_eq!(event.elapsed_ms, 210);
                assert_eq!(event.remaining_ms, 290);
            }
            other => panic!("unexpected second stream event: {other:?}"),
        }

        let third = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match third.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected third stream event: {other:?}"),
        }

        <BridgeService as pb::bridge_server::Bridge>::stop_event_stream(&service, Request::new(()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn run_event_stream_rejects_second_stream_but_first_receives_sync() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let mut stream = <BridgeService as pb::bridge_server::Bridge>::run_event_stream(
            &service,
            Request::new(pb::EventStreamRequest::default()),
        )
        .await
        .unwrap()
        .into_inner();

        let second = <BridgeService as pb::bridge_server::Bridge>::run_event_stream(
            &service,
            Request::new(pb::EventStreamRequest::default()),
        )
        .await;
        let status = match second {
            Ok(_) => panic!("second stream should be rejected"),
            Err(status) => status,
        };
        assert_eq!(status.code(), tonic::Code::AlreadyExists);
        assert!(status.message().contains("already streaming"));

        service.emit_sync_started("uid-1");
        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match first.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected event for primary stream: {other:?}"),
        }

        <BridgeService as pb::bridge_server::Bridge>::stop_event_stream(&service, Request::new(()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stop_event_stream_without_active_stream_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let result = <BridgeService as pb::bridge_server::Bridge>::stop_event_stream(
            &service,
            Request::new(()),
        )
        .await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("not streaming"));
    }

    #[tokio::test]
    async fn stop_event_stream_closes_stream_and_late_sync_events_are_not_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut stream = <BridgeService as pb::bridge_server::Bridge>::run_event_stream(
            &service,
            Request::new(pb::EventStreamRequest::default()),
        )
        .await
        .unwrap()
        .into_inner();

        service.emit_sync_started("uid-1");
        service.emit_sync_progress("uid-1", 0.5, 50, 50);

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match first.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected first stream event: {other:?}"),
        }

        let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match second.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
                assert!((event.progress - 0.5).abs() < f64::EPSILON);
            }
            other => panic!("unexpected second stream event: {other:?}"),
        }

        <BridgeService as pb::bridge_server::Bridge>::stop_event_stream(&service, Request::new(()))
            .await
            .unwrap();

        let closed = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap();
        assert!(
            closed.is_none(),
            "stream should terminate after stop_event_stream"
        );

        service.emit_sync_finished("uid-1");

        let still_closed = tokio::time::timeout(Duration::from_millis(200), stream.next())
            .await
            .unwrap();
        assert!(
            still_closed.is_none(),
            "late sync events should not be delivered after stream termination"
        );
    }

    #[tokio::test]
    async fn run_event_stream_preserves_order_for_interleaved_multi_user_sync() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut stream = <BridgeService as pb::bridge_server::Bridge>::run_event_stream(
            &service,
            Request::new(pb::EventStreamRequest::default()),
        )
        .await
        .unwrap()
        .into_inner();

        service.emit_sync_started("uid-a");
        service.emit_sync_started("uid-b");
        service.emit_sync_progress("uid-a", 0.10, 10, 90);
        service.emit_sync_progress("uid-b", 0.20, 20, 80);
        service.emit_sync_finished("uid-a");
        service.emit_sync_finished("uid-b");

        let mut observed = Vec::new();
        for _ in 0..6 {
            let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            observed.push(next);
        }

        match &observed[0].event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-a"),
            other => panic!("unexpected first interleaved event: {other:?}"),
        }
        match &observed[1].event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-b"),
            other => panic!("unexpected second interleaved event: {other:?}"),
        }
        match &observed[2].event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-a");
                assert!((event.progress - 0.10).abs() < f64::EPSILON);
                assert_eq!(event.elapsed_ms, 10);
                assert_eq!(event.remaining_ms, 90);
            }
            other => panic!("unexpected third interleaved event: {other:?}"),
        }
        match &observed[3].event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-b");
                assert!((event.progress - 0.20).abs() < f64::EPSILON);
                assert_eq!(event.elapsed_ms, 20);
                assert_eq!(event.remaining_ms, 80);
            }
            other => panic!("unexpected fourth interleaved event: {other:?}"),
        }
        match &observed[4].event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-a"),
            other => panic!("unexpected fifth interleaved event: {other:?}"),
        }
        match &observed[5].event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-b"),
            other => panic!("unexpected sixth interleaved event: {other:?}"),
        }

        <BridgeService as pb::bridge_server::Bridge>::stop_event_stream(&service, Request::new(()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn set_disk_cache_path_moves_payload_and_updates_effective_path() {
        let root = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::from_bases(
            root.path().join("cfg"),
            root.path().join("data"),
            root.path().join("cache"),
        );
        let old_path = runtime_paths.disk_cache_dir();
        let service = build_test_service_with_paths(runtime_paths.clone());
        let mut events = service.state.event_tx.subscribe();

        let old_payload = old_path.join("nested").join("payload.txt");
        tokio::fs::create_dir_all(old_payload.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&old_payload, b"cache-payload")
            .await
            .unwrap();

        let new_path = root.path().join("moved-cache");
        <BridgeService as pb::bridge_server::Bridge>::set_disk_cache_path(
            &service,
            Request::new(new_path.display().to_string()),
        )
        .await
        .unwrap();

        let copied_payload = new_path.join("nested").join("payload.txt");
        assert_eq!(
            tokio::fs::read(&copied_payload).await.unwrap(),
            b"cache-payload"
        );
        assert!(!old_path.exists());

        let effective = <BridgeService as pb::bridge_server::Bridge>::disk_cache_path(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(effective, new_path.display().to_string());

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
                event: Some(pb::disk_cache_event::Event::PathChanged(changed)),
            })) => assert_eq!(changed.path, new_path.display().to_string()),
            other => panic!("unexpected first disk cache event: {other:?}"),
        }

        let second = events.recv().await.unwrap();
        match second.event {
            Some(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
                event: Some(pb::disk_cache_event::Event::PathChangeFinished(_)),
            })) => {}
            other => panic!("unexpected second disk cache event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_disk_cache_path_failure_emits_error_then_finished() {
        let root = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::from_bases(
            root.path().join("cfg"),
            root.path().join("data"),
            root.path().join("cache"),
        );
        let service = build_test_service_with_paths(runtime_paths.clone());
        let mut events = service.state.event_tx.subscribe();

        let target_file = root.path().join("not-a-directory");
        tokio::fs::write(&target_file, b"file").await.unwrap();

        let result = <BridgeService as pb::bridge_server::Bridge>::set_disk_cache_path(
            &service,
            Request::new(target_file.display().to_string()),
        )
        .await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Internal);

        let first = events.recv().await.unwrap();
        match first.event {
            Some(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
                event: Some(pb::disk_cache_event::Event::Error(err)),
            })) => assert_eq!(
                err.r#type,
                pb::DiskCacheErrorType::CantMoveDiskCacheError as i32
            ),
            other => panic!("unexpected first failure event: {other:?}"),
        }

        let second = events.recv().await.unwrap();
        match second.event {
            Some(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
                event: Some(pb::disk_cache_event::Event::PathChangeFinished(_)),
            })) => {}
            other => panic!("unexpected second failure event: {other:?}"),
        }

        let effective = <BridgeService as pb::bridge_server::Bridge>::disk_cache_path(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            effective,
            runtime_paths.disk_cache_dir().display().to_string()
        );
    }

    #[tokio::test]
    async fn login_fido_requires_pending_login() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let result = call_login_fido(&service, "alice@example.com", br#"{}"#).await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains("no pending login"));
    }

    #[tokio::test]
    async fn fido_assertion_abort_clears_matching_pending_fido_login() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let client = ProtonClient::with_base_url("http://127.0.0.1:1").unwrap();
        let pending = PendingLogin {
            username: "alice@example.com".to_string(),
            password: "mailbox-password".to_string(),
            uid: "uid-1".to_string(),
            access_token: "access-1".to_string(),
            refresh_token: "refresh-1".to_string(),
            client,
            fido_authentication_options: Some(json!({
                "publicKey": { "challenge": [1, 2, 3] }
            })),
        };
        *service.state.pending_login.lock().await = Some(pending);

        <BridgeService as pb::bridge_server::Bridge>::fido_assertion_abort(
            &service,
            Request::new(pb::LoginAbortRequest {
                username: "alice@example.com".to_string(),
            }),
        )
        .await
        .unwrap();

        assert!(service.state.pending_login.lock().await.is_none());

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::Login(pb::LoginEvent {
                event: Some(pb::login_event::Event::Error(err)),
            })) => {
                assert!(err.message.contains("fido assertion aborted"));
            }
            other => panic!("unexpected fido abort event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn fido_assertion_abort_keeps_non_matching_pending_login() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let client = ProtonClient::with_base_url("http://127.0.0.1:1").unwrap();
        let pending = PendingLogin {
            username: "alice@example.com".to_string(),
            password: "mailbox-password".to_string(),
            uid: "uid-1".to_string(),
            access_token: "access-1".to_string(),
            refresh_token: "refresh-1".to_string(),
            client,
            fido_authentication_options: Some(json!({
                "publicKey": { "challenge": [1, 2, 3] }
            })),
        };
        *service.state.pending_login.lock().await = Some(pending);

        <BridgeService as pb::bridge_server::Bridge>::fido_assertion_abort(
            &service,
            Request::new(pb::LoginAbortRequest {
                username: "bob@example.com".to_string(),
            }),
        )
        .await
        .unwrap();

        assert!(service.state.pending_login.lock().await.is_some());
        let recv_result = tokio::time::timeout(Duration::from_millis(200), events.recv()).await;
        assert!(
            recv_result.is_err(),
            "unexpected event emitted on non-match"
        );
    }

    #[tokio::test]
    async fn login_fido_preserves_pending_state_on_invalid_assertion_payload() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let client = ProtonClient::with_base_url("http://127.0.0.1:1").unwrap();
        let pending = PendingLogin {
            username: "alice@example.com".to_string(),
            password: "mailbox-password".to_string(),
            uid: "uid-1".to_string(),
            access_token: "access-1".to_string(),
            refresh_token: "refresh-1".to_string(),
            client,
            fido_authentication_options: Some(json!({
                "publicKey": { "challenge": [1, 2, 3] }
            })),
        };
        *service.state.pending_login.lock().await = Some(pending);

        let result = call_login_fido(&service, "alice@example.com", b"not-json").await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert!(status.message().contains("invalid FIDO assertion payload"));
        assert!(service.state.pending_login.lock().await.is_some());
    }

    #[tokio::test]
    async fn login_fido_success_completes_login_and_clears_pending_state() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/v4/2fa"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .and(body_partial_json(json!({
                "FIDO2": {
                    "CredentialID": [1, 2, 3]
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "Scopes": ["mail"]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "User": {
                    "ID": "uid-1",
                    "Name": "alice",
                    "DisplayName": "Alice",
                    "Email": "alice@example.com",
                    "Keys": []
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/core/v4/keys/salts"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "KeySalts": []
            })))
            .mount(&server)
            .await;

        let mut client = ProtonClient::with_base_url(&server.uri()).unwrap();
        client.set_auth("uid-1", "access-1");
        let pending = PendingLogin {
            username: "alice@example.com".to_string(),
            password: "mailbox-password".to_string(),
            uid: "uid-1".to_string(),
            access_token: "access-1".to_string(),
            refresh_token: "refresh-1".to_string(),
            client,
            fido_authentication_options: Some(json!({
                "publicKey": { "challenge": [1, 2, 3] }
            })),
        };
        *service.state.pending_login.lock().await = Some(pending);

        let payload = br#"{
            "rawId":"AQID",
            "response":{
                "clientDataJSON":"BAUG",
                "authenticatorData":"BwgJ",
                "signature":"CgsM"
            }
        }"#;
        call_login_fido(&service, "alice@example.com", payload)
            .await
            .unwrap();

        assert!(service.state.pending_login.lock().await.is_none());
        let sessions = vault::list_sessions(dir.path()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].uid, "uid-1");
        assert_eq!(sessions[0].email, "alice@example.com");
        assert!(sessions[0].bridge_password.is_some());
    }

    #[tokio::test]
    async fn parity_integration_proton_fixture_reuse_survives_service_restart() {
        let dir = tempfile::tempdir().unwrap();
        write_proton_golden_fixture(dir.path());
        let runtime_paths = RuntimePaths::resolve(Some(dir.path())).unwrap();

        let service = build_test_service_with_paths(runtime_paths.clone());
        let users_before = <BridgeService as pb::bridge_server::Bridge>::get_user_list(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(users_before.users.len(), 2);

        let restarted_service = build_test_service_with_paths(runtime_paths);
        let users_after = <BridgeService as pb::bridge_server::Bridge>::get_user_list(
            &restarted_service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(users_after.users.len(), 2);
        assert!(users_after.users.iter().any(|user| user.id == "uid-alpha"));
        assert!(users_after.users.iter().any(|user| user.id == "uid-beta"));
    }

    #[tokio::test]
    async fn parity_integration_login_then_logout_updates_user_list_and_emits_disconnect() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/v4/2fa"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .and(body_partial_json(json!({
                "FIDO2": {
                    "CredentialID": [1, 2, 3]
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "Scopes": ["mail"]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "User": {
                    "ID": "uid-1",
                    "Name": "alice",
                    "DisplayName": "Alice",
                    "Email": "alice@example.com",
                    "Keys": []
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/core/v4/keys/salts"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "KeySalts": []
            })))
            .mount(&server)
            .await;

        let mut client = ProtonClient::with_base_url(&server.uri()).unwrap();
        client.set_auth("uid-1", "access-1");
        *service.state.pending_login.lock().await = Some(PendingLogin {
            username: "alice@example.com".to_string(),
            password: "mailbox-password".to_string(),
            uid: "uid-1".to_string(),
            access_token: "access-1".to_string(),
            refresh_token: "refresh-1".to_string(),
            client,
            fido_authentication_options: Some(json!({
                "publicKey": { "challenge": [1, 2, 3] }
            })),
        });

        let payload = br#"{
            "rawId":"AQID",
            "response":{
                "clientDataJSON":"BAUG",
                "authenticatorData":"BwgJ",
                "signature":"CgsM"
            }
        }"#;
        call_login_fido(&service, "alice@example.com", payload)
            .await
            .unwrap();

        let users = <BridgeService as pb::bridge_server::Bridge>::get_user_list(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(users.users.len(), 1);
        assert_eq!(users.users[0].id, "uid-1");

        let mut events = service.state.event_tx.subscribe();
        <BridgeService as pb::bridge_server::Bridge>::logout_user(
            &service,
            Request::new("uid-1".to_string()),
        )
        .await
        .unwrap();

        let users_after = <BridgeService as pb::bridge_server::Bridge>::get_user_list(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(users_after.users.is_empty());

        let event = events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::UserDisconnected(disconnected)),
            })) => {
                assert_eq!(disconnected.username, "alice@example.com");
            }
            other => panic!("unexpected disconnect event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn parity_integration_disk_cache_move_persists_across_service_restart() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::resolve(Some(dir.path())).unwrap();
        let source_cache_root = runtime_paths.disk_cache_dir();
        tokio::fs::create_dir_all(source_cache_root.join("uid-1"))
            .await
            .unwrap();
        tokio::fs::write(source_cache_root.join("uid-1/message.eml"), b"hello")
            .await
            .unwrap();

        let service = build_test_service_with_paths(runtime_paths.clone());
        let target_cache_root = dir.path().join("cache-moved");
        <BridgeService as pb::bridge_server::Bridge>::set_disk_cache_path(
            &service,
            Request::new(target_cache_root.display().to_string()),
        )
        .await
        .unwrap();

        let restarted_service = build_test_service_with_paths(runtime_paths.clone());
        let loaded_settings = load_app_settings(
            &runtime_paths.settings_dir().join(APP_SETTINGS_FILE),
            &runtime_paths.disk_cache_dir(),
        )
        .await
        .unwrap();
        {
            let mut settings = restarted_service.state.app_settings.lock().await;
            *settings = loaded_settings.clone();
        }
        *restarted_service.state.active_disk_cache_path.lock().await =
            effective_disk_cache_path(&loaded_settings, &runtime_paths);

        let effective = <BridgeService as pb::bridge_server::Bridge>::disk_cache_path(
            &restarted_service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(effective, target_cache_root.display().to_string());
        assert_eq!(
            tokio::fs::read(target_cache_root.join("uid-1/message.eml"))
                .await
                .unwrap(),
            b"hello"
        );
    }

    #[tokio::test]
    async fn parity_integration_restart_and_quit_signal_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let restart_service = build_test_service(dir.path().to_path_buf());
        let mut restart_shutdown = restart_service.state.shutdown_tx.subscribe();
        let mut restart_events = restart_service.state.event_tx.subscribe();
        assert!(!*restart_shutdown.borrow());

        <BridgeService as pb::bridge_server::Bridge>::restart(&restart_service, Request::new(()))
            .await
            .unwrap();

        restart_shutdown.changed().await.unwrap();
        assert!(*restart_shutdown.borrow_and_update());
        let event = restart_events.recv().await.unwrap();
        match event.event {
            Some(pb::stream_event::Event::App(pb::AppEvent {
                event: Some(pb::app_event::Event::ShowMainWindow(_)),
            })) => {}
            other => panic!("unexpected restart app event: {other:?}"),
        }

        let quit_service = build_test_service(dir.path().to_path_buf());
        let mut quit_shutdown = quit_service.state.shutdown_tx.subscribe();
        assert!(!*quit_shutdown.borrow());

        <BridgeService as pb::bridge_server::Bridge>::quit(&quit_service, Request::new(()))
            .await
            .unwrap();

        quit_shutdown.changed().await.unwrap();
        assert!(*quit_shutdown.borrow_and_update());
    }
}
