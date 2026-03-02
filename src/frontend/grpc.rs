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
            current_keychain: "keyring".to_string(),
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

#[derive(Debug)]
struct GrpcState {
    runtime_paths: RuntimePaths,
    bind_host: String,
    active_disk_cache_path: Mutex<PathBuf>,
    event_tx: broadcast::Sender<pb::StreamEvent>,
    active_stream_stop: Mutex<Option<watch::Sender<bool>>>,
    pending_login: Mutex<Option<PendingLogin>>,
    pending_hv: Mutex<Option<PendingHumanVerification>>,
    shutdown_tx: watch::Sender<bool>,
    mail_settings: Mutex<StoredMailSettings>,
    app_settings: Mutex<StoredAppSettings>,
}

#[derive(Debug, Clone)]
struct BridgeService {
    state: Arc<GrpcState>,
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

    fn emit_event(&self, event: pb::stream_event::Event) {
        let _ = self
            .state
            .event_tx
            .send(pb::StreamEvent { event: Some(event) });
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

    fn emit_toggle_autostart_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ToggleAutostartFinished(
                pb::ToggleAutostartFinishedEvent {},
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

        vault::save_session(&session, self.settings_dir()).map_err(status_from_vault_error)?;
        vault::set_default_email(self.settings_dir(), &session.email)
            .map_err(status_from_vault_error)?;

        client.set_auth(&session.uid, &session.access_token);

        self.emit_login_finished(&session.uid);
        self.emit_user_changed(&session.uid);

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
        self.emit_repair_started();
        self.emit_show_main_window();
        Ok(Response::new(()))
    }

    async fn trigger_reset(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        vault::remove_session(self.settings_dir()).map_err(status_from_vault_error)?;
        let _ = tokio::fs::remove_file(self.grpc_mail_settings_path()).await;
        let _ = tokio::fs::remove_file(self.grpc_app_settings_path()).await;
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
        Ok(Response::new("openproton-bridge".to_string()))
    }

    async fn logs_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        let path = self.logs_dir();
        tokio::fs::create_dir_all(&path)
            .await
            .map_err(|e| Status::internal(format!("failed to create logs directory: {e}")))?;
        Ok(Response::new(path.display().to_string()))
    }

    async fn license_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new(
            self.settings_dir().join("LICENSE").display().to_string(),
        ))
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
        tracing::info!(
            query = %request.into_inner(),
            "knowledge base suggestion request received"
        );
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
        _request: Request<pb::LoginAbortRequest>,
    ) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn get_user_list(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::UserListResponse>, Status> {
        let sessions =
            vault::list_sessions(self.settings_dir()).map_err(status_from_vault_error)?;
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
        let sessions =
            vault::list_sessions(self.settings_dir()).map_err(status_from_vault_error)?;
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
        let sessions =
            vault::list_sessions(self.settings_dir()).map_err(status_from_vault_error)?;
        let account_id = sessions
            .iter()
            .find(|s| s.uid == req.user_id || s.email.eq_ignore_ascii_case(&req.user_id))
            .map(|s| s.uid.clone())
            .ok_or_else(|| Status::not_found("user not found"))?;

        vault::save_split_mode_by_account_id(self.settings_dir(), &account_id, req.active)
            .map_err(status_from_vault_error)?;
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
        tracing::warn!(
            user_id = %req.user_id,
            do_resync = req.do_resync,
            "user bad event feedback received"
        );
        Ok(Response::new(()))
    }

    async fn logout_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let value = request.into_inner();
        let sessions =
            vault::list_sessions(self.settings_dir()).map_err(status_from_vault_error)?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == value || s.email.eq_ignore_ascii_case(&value))
            .ok_or_else(|| Status::not_found("user not found"))?;

        vault::remove_session_by_email(self.settings_dir(), &session.email)
            .map_err(status_from_vault_error)?;
        self.emit_user_disconnected(&session.email);
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
        tracing::info!(
            user_id = %req.user_id,
            address = %req.address,
            "configure user apple mail requested; not yet integrated with system mail setup"
        );
        Ok(Response::new(()))
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
        Ok(Response::new(pb::AvailableKeychainsResponse {
            keychains: vec!["keyring".to_string(), "file".to_string()],
        }))
    }

    async fn set_current_keychain(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let keychain = request.into_inner();
        if keychain.trim().is_empty() {
            return Err(Status::invalid_argument("keychain name is empty"));
        }
        let mut settings = self.state.app_settings.lock().await;
        settings.current_keychain = keychain;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn current_keychain(&self, _request: Request<()>) -> Result<Response<String>, Status> {
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

        let mut rx = self.state.event_tx.subscribe();
        let (out_tx, out_rx) = mpsc::channel::<Result<pb::StreamEvent, Status>>(32);
        let state = self.state.clone();

        tokio::spawn(async move {
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
    let active_disk_cache_path_for_sync = active_disk_cache_path.clone();
    let state = Arc::new(GrpcState {
        runtime_paths: runtime_paths.clone(),
        bind_host,
        active_disk_cache_path: Mutex::new(active_disk_cache_path),
        event_tx,
        active_stream_stop: Mutex::new(None),
        pending_login: Mutex::new(None),
        pending_hv: Mutex::new(None),
        shutdown_tx: shutdown_tx.clone(),
        mail_settings: Mutex::new(settings),
        app_settings: Mutex::new(app_settings),
    });

    let service = BridgeService::new(state);
    let sync_event_service = service.clone();
    let sync_event_workers = maybe_start_grpc_sync_workers(
        &runtime_paths,
        &sync_event_service,
        &active_disk_cache_path_for_sync,
    )
    .await?;
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

    let server_result = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(tls_identity))
        .context("failed to configure gRPC TLS")?
        .add_service(bridge_svc)
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
            wait_for_shutdown(shutdown_rx).await;
        })
        .await
        .context("gRPC server exited with error");

    if let Some(workers) = sync_event_workers {
        workers.shutdown().await;
    }

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
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
            active_stream_stop: Mutex::new(None),
            pending_login: Mutex::new(None),
            pending_hv: Mutex::new(None),
            shutdown_tx,
            mail_settings: Mutex::new(StoredMailSettings::default()),
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
}
