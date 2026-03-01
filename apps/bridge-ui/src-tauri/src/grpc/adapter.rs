use super::config::{resolve_server_config_path, write_temp_client_token_file, GrpcServerConfig};
use super::pb;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tauri::{AppHandle, Emitter};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};
use tracing::{debug, info};
use uuid::Uuid;

type BridgeClient = pb::bridge_client::BridgeClient<InterceptedService<Channel, TokenInterceptor>>;

#[derive(Debug, Clone)]
struct TokenInterceptor {
    token: MetadataValue<Ascii>,
}

impl TokenInterceptor {
    fn new(token: &str) -> Result<Self, String> {
        let token_value = token
            .parse::<MetadataValue<Ascii>>()
            .map_err(|err| format!("invalid grpc server token: {err}"))?;

        Ok(Self { token: token_value })
    }
}

impl Interceptor for TokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("server-token", self.token.clone());
        Ok(request)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamTickEvent {
    pub timestamp: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub state: i32,
    pub split_mode: bool,
    pub addresses: Vec<String>,
    pub used_bytes: i64,
    pub total_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailSettings {
    pub imap_port: i32,
    pub smtp_port: i32,
    pub use_ssl_for_imap: bool,
    pub use_ssl_for_smtp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub is_autostart_on: bool,
    pub is_beta_enabled: bool,
    pub is_all_mail_visible: bool,
    pub is_telemetry_disabled: bool,
    pub disk_cache_path: String,
    pub is_doh_enabled: bool,
    pub color_scheme_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiEvent {
    pub level: String,
    pub code: String,
    pub message: String,
    pub refresh_hints: Vec<String>,
}

#[derive(Default)]
pub struct GrpcAdapter {
    stream_task: Option<JoinHandle<()>>,
    stop_tx: Option<oneshot::Sender<()>>,
    server_config: Option<GrpcServerConfig>,
}

impl GrpcAdapter {
    pub async fn connect(&mut self, app: AppHandle, state: AppState) -> Result<(), String> {
        if self.stream_task.is_some() {
            debug!("connect ignored because stream task is already running");
            return Ok(());
        }

        let explicit_path = state.snapshot().await.config_path;
        let config_path = resolve_server_config_path(explicit_path.as_deref().map(Path::new))?;
        let server_config = GrpcServerConfig::from_json_file(&config_path)?;
        info!(config_path = %config_path.display(), "starting grpc bridge connection");

        let mut client = connect_client(&server_config).await?;
        check_tokens(&mut client).await?;

        let request = pb::EventStreamRequest {
            client_platform: client_platform_name(),
        };
        let mut stream = client
            .run_event_stream(Request::new(request))
            .await
            .map_err(|err| format!("RunEventStream failed: {err}"))?
            .into_inner();

        state
            .update(|snapshot| {
                snapshot.connected = true;
                snapshot.stream_running = true;
                snapshot.last_error = None;
                snapshot.config_path = Some(config_path.display().to_string());
            })
            .await;

        let (stop_tx, mut stop_rx) = oneshot::channel();
        self.stop_tx = Some(stop_tx);
        self.server_config = Some(server_config);

        self.stream_task = Some(tokio::spawn(async move {
            let mut stream_error: Option<String> = None;

            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    next_item = stream.message() => {
                        match next_item {
                            Ok(Some(event)) => {
                                let payload = StreamTickEvent {
                                    timestamp: unix_timestamp_string(),
                                    message: summarize_stream_event(&event),
                                };
                                let _ = app.emit("bridge://stream-tick", payload);

                                if let Some(ui_event) = stream_ui_event(&event) {
                                    debug!(code = %ui_event.code, level = %ui_event.level, "emitting ui event");
                                    let _ = app.emit("bridge://ui-event", ui_event);
                                }

                                let (login_step, last_error) = stream_state_patch(&event);
                                if login_step.is_some() || last_error.is_some() {
                                    let snapshot = state
                                        .update(|snapshot| {
                                            if let Some(step) = login_step.clone() {
                                                snapshot.login_step = step;
                                            }
                                            if let Some(error) = last_error.clone() {
                                                snapshot.last_error = error;
                                            }
                                        })
                                        .await;
                                    let _ = app.emit("bridge://state-changed", snapshot);
                                }
                            }
                            Ok(None) => {
                                break;
                            }
                            Err(err) => {
                                stream_error = Some(format!("event stream error: {err}"));
                                break;
                            }
                        }
                    }
                }
            }

            let snapshot = state
                .update(|snapshot| {
                    snapshot.connected = false;
                    snapshot.stream_running = false;
                    if let Some(err) = stream_error.clone() {
                        snapshot.last_error = Some(err);
                    }
                })
                .await;

            let _ = app.emit("bridge://state-changed", snapshot);
            info!("grpc bridge stream stopped");
        }));

        Ok(())
    }

    pub async fn disconnect(&mut self) {
        info!("disconnect requested");
        if let Some(config) = self.server_config.clone() {
            if let Ok(mut client) = connect_client(&config).await {
                let _ = client.stop_event_stream(()).await;
            }
        }

        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }

        if let Some(handle) = self.stream_task.take() {
            let _ = handle.await;
        }

        self.server_config = None;
        info!("disconnect completed");
    }

    pub async fn fetch_users(&self, state: &AppState) -> Result<Vec<UserSummary>, String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        let users = client
            .get_user_list(())
            .await
            .map_err(|err| format!("GetUserList failed: {err}"))?
            .into_inner()
            .users
            .into_iter()
            .map(|user| UserSummary {
                id: user.id,
                username: user.username,
                state: user.state,
                split_mode: user.split_mode,
                addresses: user.addresses,
                used_bytes: user.used_bytes,
                total_bytes: user.total_bytes,
            })
            .collect();

        Ok(users)
    }

    pub async fn login(
        &self,
        state: &AppState,
        username: &str,
        secret: &str,
        use_hv_details: Option<bool>,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .login(pb::LoginRequest {
                username: username.to_string(),
                password: secret.as_bytes().to_vec(),
                use_hv_details,
            })
            .await
            .map_err(|err| format!("Login failed: {err}"))?;
        Ok(())
    }

    pub async fn login_2fa(
        &self,
        state: &AppState,
        username: &str,
        code: &str,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .login2_fa(pb::LoginRequest {
                username: username.to_string(),
                password: code.as_bytes().to_vec(),
                use_hv_details: None,
            })
            .await
            .map_err(|err| format!("Login2FA failed: {err}"))?;
        Ok(())
    }

    pub async fn login_2passwords(
        &self,
        state: &AppState,
        username: &str,
        mailbox_password: &str,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .login2_passwords(pb::LoginRequest {
                username: username.to_string(),
                password: mailbox_password.as_bytes().to_vec(),
                use_hv_details: None,
            })
            .await
            .map_err(|err| format!("Login2Passwords failed: {err}"))?;
        Ok(())
    }

    pub async fn login_abort(&self, state: &AppState, username: &str) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .login_abort(pb::LoginAbortRequest {
                username: username.to_string(),
            })
            .await
            .map_err(|err| format!("LoginAbort failed: {err}"))?;
        Ok(())
    }

    pub async fn login_fido(
        &self,
        state: &AppState,
        username: &str,
        assertion_payload: &[u8],
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .login_fido(pb::LoginRequest {
                username: username.to_string(),
                password: assertion_payload.to_vec(),
                use_hv_details: None,
            })
            .await
            .map_err(|err| format!("LoginFido failed: {err}"))?;
        Ok(())
    }

    pub async fn fido_assertion_abort(
        &self,
        state: &AppState,
        username: &str,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .fido_assertion_abort(pb::LoginAbortRequest {
                username: username.to_string(),
            })
            .await
            .map_err(|err| format!("FidoAssertionAbort failed: {err}"))?;
        Ok(())
    }

    pub async fn get_hostname(&self, state: &AppState) -> Result<String, String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .hostname(())
            .await
            .map_err(|err| format!("Hostname failed: {err}"))
            .map(tonic::Response::into_inner)
    }

    pub async fn get_mail_settings(&self, state: &AppState) -> Result<MailSettings, String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        let settings = client
            .mail_server_settings(())
            .await
            .map_err(|err| format!("MailServerSettings failed: {err}"))?
            .into_inner();

        Ok(MailSettings {
            imap_port: settings.imap_port,
            smtp_port: settings.smtp_port,
            use_ssl_for_imap: settings.use_ssl_for_imap,
            use_ssl_for_smtp: settings.use_ssl_for_smtp,
        })
    }

    pub async fn set_mail_settings(
        &self,
        state: &AppState,
        settings: MailSettings,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_mail_server_settings(pb::ImapSmtpSettings {
                imap_port: settings.imap_port,
                smtp_port: settings.smtp_port,
                use_ssl_for_imap: settings.use_ssl_for_imap,
                use_ssl_for_smtp: settings.use_ssl_for_smtp,
            })
            .await
            .map_err(|err| format!("SetMailServerSettings failed: {err}"))?;
        Ok(())
    }

    pub async fn is_port_free(&self, state: &AppState, port: i32) -> Result<bool, String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .is_port_free(port)
            .await
            .map_err(|err| format!("IsPortFree failed: {err}"))
            .map(tonic::Response::into_inner)
    }

    pub async fn logout_user(&self, state: &AppState, user_id: &str) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .logout_user(user_id.to_string())
            .await
            .map_err(|err| format!("LogoutUser failed: {err}"))?;
        Ok(())
    }

    pub async fn remove_user(&self, state: &AppState, user_id: &str) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .remove_user(user_id.to_string())
            .await
            .map_err(|err| format!("RemoveUser failed: {err}"))?;
        Ok(())
    }

    pub async fn set_user_split_mode(
        &self,
        state: &AppState,
        user_id: &str,
        active: bool,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_user_split_mode(pb::UserSplitModeRequest {
                user_id: user_id.to_string(),
                active,
            })
            .await
            .map_err(|err| format!("SetUserSplitMode failed: {err}"))?;
        Ok(())
    }

    pub async fn is_tls_certificate_installed(&self, state: &AppState) -> Result<bool, String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .is_tls_certificate_installed(())
            .await
            .map_err(|err| format!("IsTLSCertificateInstalled failed: {err}"))
            .map(tonic::Response::into_inner)
    }

    pub async fn install_tls_certificate(&self, state: &AppState) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .install_tls_certificate(())
            .await
            .map_err(|err| format!("InstallTLSCertificate failed: {err}"))?;
        Ok(())
    }

    pub async fn export_tls_certificates(
        &self,
        state: &AppState,
        output_dir: &str,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .export_tls_certificates(output_dir.to_string())
            .await
            .map_err(|err| format!("ExportTLSCertificates failed: {err}"))?;
        Ok(())
    }

    pub async fn get_app_settings(&self, state: &AppState) -> Result<AppSettings, String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;

        let is_autostart_on = client
            .is_autostart_on(())
            .await
            .map_err(|err| format!("IsAutostartOn failed: {err}"))?
            .into_inner();
        let is_beta_enabled = client
            .is_beta_enabled(())
            .await
            .map_err(|err| format!("IsBetaEnabled failed: {err}"))?
            .into_inner();
        let is_all_mail_visible = client
            .is_all_mail_visible(())
            .await
            .map_err(|err| format!("IsAllMailVisible failed: {err}"))?
            .into_inner();
        let is_telemetry_disabled = client
            .is_telemetry_disabled(())
            .await
            .map_err(|err| format!("IsTelemetryDisabled failed: {err}"))?
            .into_inner();
        let disk_cache_path = client
            .disk_cache_path(())
            .await
            .map_err(|err| format!("DiskCachePath failed: {err}"))?
            .into_inner();
        let is_doh_enabled = client
            .is_do_h_enabled(())
            .await
            .map_err(|err| format!("IsDoHEnabled failed: {err}"))?
            .into_inner();
        let color_scheme_name = client
            .color_scheme_name(())
            .await
            .map_err(|err| format!("ColorSchemeName failed: {err}"))?
            .into_inner();

        Ok(AppSettings {
            is_autostart_on,
            is_beta_enabled,
            is_all_mail_visible,
            is_telemetry_disabled,
            disk_cache_path,
            is_doh_enabled,
            color_scheme_name,
        })
    }

    pub async fn set_is_autostart_on(&self, state: &AppState, enabled: bool) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_is_autostart_on(enabled)
            .await
            .map_err(|err| format!("SetIsAutostartOn failed: {err}"))?;
        Ok(())
    }

    pub async fn set_is_beta_enabled(&self, state: &AppState, enabled: bool) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_is_beta_enabled(enabled)
            .await
            .map_err(|err| format!("SetIsBetaEnabled failed: {err}"))?;
        Ok(())
    }

    pub async fn set_is_all_mail_visible(
        &self,
        state: &AppState,
        enabled: bool,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_is_all_mail_visible(enabled)
            .await
            .map_err(|err| format!("SetIsAllMailVisible failed: {err}"))?;
        Ok(())
    }

    pub async fn set_is_telemetry_disabled(
        &self,
        state: &AppState,
        disabled: bool,
    ) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_is_telemetry_disabled(disabled)
            .await
            .map_err(|err| format!("SetIsTelemetryDisabled failed: {err}"))?;
        Ok(())
    }

    pub async fn set_disk_cache_path(&self, state: &AppState, path: &str) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_disk_cache_path(path.to_string())
            .await
            .map_err(|err| format!("SetDiskCachePath failed: {err}"))?;
        Ok(())
    }

    pub async fn set_is_doh_enabled(&self, state: &AppState, enabled: bool) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_is_do_h_enabled(enabled)
            .await
            .map_err(|err| format!("SetIsDoHEnabled failed: {err}"))?;
        Ok(())
    }

    pub async fn set_color_scheme_name(&self, state: &AppState, name: &str) -> Result<(), String> {
        let config = self.resolve_server_config(state).await?;
        let mut client = connect_client(&config).await?;
        client
            .set_color_scheme_name(name.to_string())
            .await
            .map_err(|err| format!("SetColorSchemeName failed: {err}"))?;
        Ok(())
    }

    async fn resolve_server_config(&self, state: &AppState) -> Result<GrpcServerConfig, String> {
        if let Some(config) = &self.server_config {
            return Ok(config.clone());
        }

        let explicit_path = state.snapshot().await.config_path;
        let config_path = resolve_server_config_path(explicit_path.as_deref().map(Path::new))?;
        GrpcServerConfig::from_json_file(&config_path)
    }
}

async fn connect_client(config: &GrpcServerConfig) -> Result<BridgeClient, String> {
    let port = match config.port {
        Some(port) => port,
        None => {
            if let Some(socket_path) = &config.file_socket_path {
                return Err(format!(
                    "grpc unix socket is not implemented yet in this UI adapter ({socket_path})"
                ));
            }

            return Err("grpc config is missing both port and fileSocketPath".to_string());
        }
    };

    let endpoint_url = format!("https://127.0.0.1:{port}");

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(config.cert.clone()))
        .domain_name("127.0.0.1");

    let endpoint = Endpoint::from_shared(endpoint_url)
        .map_err(|err| format!("invalid grpc endpoint: {err}"))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .tls_config(tls)
        .map_err(|err| format!("failed to configure grpc tls: {err}"))?;

    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("failed to connect grpc channel: {err}"))?;

    let interceptor = TokenInterceptor::new(&config.token)?;

    Ok(pb::bridge_client::BridgeClient::with_interceptor(
        channel,
        interceptor,
    ))
}

async fn check_tokens(client: &mut BridgeClient) -> Result<(), String> {
    let client_token = Uuid::new_v4().to_string();
    let token_file = write_temp_client_token_file(&client_token)?;

    let response: tonic::Response<String> = client
        .check_tokens(token_file.display().to_string())
        .await
        .map_err(|err| format!("CheckTokens failed: {err}"))?;

    let returned_token = response.into_inner();
    let result = if returned_token == client_token {
        debug!("CheckTokens roundtrip validated");
        Ok(())
    } else {
        Err("CheckTokens returned unexpected client token".to_string())
    };

    let _ = std::fs::remove_file(&token_file);

    result
}

fn summarize_stream_event(event: &pb::StreamEvent) -> String {
    let name = match event.event.as_ref() {
        Some(pb::stream_event::Event::App(_)) => "app",
        Some(pb::stream_event::Event::Login(_)) => "login",
        Some(pb::stream_event::Event::Update(_)) => "update",
        Some(pb::stream_event::Event::Cache(_)) => "cache",
        Some(pb::stream_event::Event::MailServerSettings(_)) => "mail_server_settings",
        Some(pb::stream_event::Event::Keychain(_)) => "keychain",
        Some(pb::stream_event::Event::Mail(_)) => "mail",
        Some(pb::stream_event::Event::User(_)) => "user",
        Some(pb::stream_event::Event::GenericError(_)) => "generic_error",
        None => "none",
    };

    format!("stream event: {name}")
}

pub fn stream_state_patch(event: &pb::StreamEvent) -> (Option<String>, Option<Option<String>>) {
    match event.event.as_ref() {
        Some(pb::stream_event::Event::Login(login)) => match login.event.as_ref() {
            Some(pb::login_event::Event::TfaRequested(_)) => (Some("2fa".to_string()), Some(None)),
            Some(pb::login_event::Event::FidoRequested(_)) => {
                (Some("fido".to_string()), Some(None))
            }
            Some(pb::login_event::Event::TfaOrFidoRequested(_)) => {
                (Some("2fa_or_fido".to_string()), Some(None))
            }
            Some(pb::login_event::Event::LoginFidoTouchRequested(_)) => {
                (Some("fido_touch".to_string()), Some(None))
            }
            Some(pb::login_event::Event::LoginFidoTouchCompleted(_)) => {
                (Some("fido".to_string()), Some(None))
            }
            Some(pb::login_event::Event::LoginFidoPinRequired(_)) => {
                (Some("fido_pin".to_string()), Some(None))
            }
            Some(pb::login_event::Event::TwoPasswordRequested(_))
            | Some(pb::login_event::Event::HvRequested(_)) => {
                (Some("mailbox_password".to_string()), Some(None))
            }
            Some(pb::login_event::Event::Finished(_))
            | Some(pb::login_event::Event::AlreadyLoggedIn(_)) => {
                (Some("done".to_string()), Some(None))
            }
            Some(pb::login_event::Event::Error(err)) => (
                Some("credentials".to_string()),
                Some(Some(login_error_message(err))),
            ),
            _ => (None, None),
        },
        Some(pb::stream_event::Event::MailServerSettings(settings)) => {
            match settings.event.as_ref() {
                Some(pb::mail_server_settings_event::Event::Error(err)) => {
                    (None, Some(Some(mail_settings_error_message(err))))
                }
                _ => (None, None),
            }
        }
        Some(pb::stream_event::Event::GenericError(err)) => {
            (None, Some(Some(generic_error_message(err))))
        }
        _ => (None, None),
    }
}

fn stream_ui_event(event: &pb::StreamEvent) -> Option<UiEvent> {
    match event.event.as_ref() {
        Some(pb::stream_event::Event::App(app)) => match app.event.as_ref() {
            Some(pb::app_event::Event::ToggleAutostartFinished(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "autostart_saved".to_string(),
                message: "Autostart updated".to_string(),
                refresh_hints: vec!["app_settings".to_string()],
            }),
            Some(pb::app_event::Event::CertificateInstallSuccess(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "tls_install_success".to_string(),
                message: "TLS certificate installed".to_string(),
                refresh_hints: vec!["tls".to_string()],
            }),
            Some(pb::app_event::Event::CertificateInstallCanceled(_)) => Some(UiEvent {
                level: "error".to_string(),
                code: "tls_install_canceled".to_string(),
                message: "TLS certificate install was canceled".to_string(),
                refresh_hints: vec!["tls".to_string()],
            }),
            Some(pb::app_event::Event::CertificateInstallFailed(_)) => Some(UiEvent {
                level: "error".to_string(),
                code: "tls_install_failed".to_string(),
                message: "TLS certificate install failed".to_string(),
                refresh_hints: vec!["tls".to_string()],
            }),
            _ => None,
        },
        Some(pb::stream_event::Event::Login(login)) => match login.event.as_ref() {
            Some(pb::login_event::Event::Finished(_))
            | Some(pb::login_event::Event::AlreadyLoggedIn(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "login_finished".to_string(),
                message: "Login completed".to_string(),
                refresh_hints: vec!["users".to_string()],
            }),
            Some(pb::login_event::Event::FidoRequested(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "fido_requested".to_string(),
                message: "FIDO assertion requested".to_string(),
                refresh_hints: vec![],
            }),
            Some(pb::login_event::Event::TfaOrFidoRequested(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "tfa_or_fido_requested".to_string(),
                message: "2FA or FIDO required".to_string(),
                refresh_hints: vec![],
            }),
            Some(pb::login_event::Event::LoginFidoTouchRequested(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "fido_touch_requested".to_string(),
                message: "Touch your security key".to_string(),
                refresh_hints: vec![],
            }),
            Some(pb::login_event::Event::LoginFidoTouchCompleted(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "fido_touch_completed".to_string(),
                message: "Security key touch received".to_string(),
                refresh_hints: vec![],
            }),
            Some(pb::login_event::Event::LoginFidoPinRequired(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "fido_pin_required".to_string(),
                message: "FIDO PIN required".to_string(),
                refresh_hints: vec![],
            }),
            Some(pb::login_event::Event::Error(err)) => Some(UiEvent {
                level: "error".to_string(),
                code: "login_error".to_string(),
                message: login_error_message(err),
                refresh_hints: vec![],
            }),
            _ => None,
        },
        Some(pb::stream_event::Event::Cache(cache)) => match cache.event.as_ref() {
            Some(pb::disk_cache_event::Event::PathChangeFinished(_))
            | Some(pb::disk_cache_event::Event::PathChanged(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "disk_cache_saved".to_string(),
                message: "Disk cache path updated".to_string(),
                refresh_hints: vec!["app_settings".to_string()],
            }),
            Some(pb::disk_cache_event::Event::Error(err)) => Some(UiEvent {
                level: "error".to_string(),
                code: "disk_cache_error".to_string(),
                message: disk_cache_error_message(err),
                refresh_hints: vec!["app_settings".to_string()],
            }),
            _ => None,
        },
        Some(pb::stream_event::Event::MailServerSettings(settings)) => {
            match settings.event.as_ref() {
                Some(pb::mail_server_settings_event::Event::ChangeMailServerSettingsFinished(
                    _,
                ))
                | Some(pb::mail_server_settings_event::Event::MailServerSettingsChanged(_)) => {
                    Some(UiEvent {
                        level: "info".to_string(),
                        code: "mail_settings_saved".to_string(),
                        message: "Mail settings updated".to_string(),
                        refresh_hints: vec!["mail_settings".to_string()],
                    })
                }
                Some(pb::mail_server_settings_event::Event::Error(err)) => Some(UiEvent {
                    level: "error".to_string(),
                    code: "mail_settings_error".to_string(),
                    message: mail_settings_error_message(err),
                    refresh_hints: vec!["mail_settings".to_string()],
                }),
                _ => None,
            }
        }
        Some(pb::stream_event::Event::User(user)) => match user.event.as_ref() {
            Some(pb::user_event::Event::ToggleSplitModeFinished(_))
            | Some(pb::user_event::Event::UserChanged(_))
            | Some(pb::user_event::Event::UserDisconnected(_)) => Some(UiEvent {
                level: "info".to_string(),
                code: "users_updated".to_string(),
                message: "User state updated".to_string(),
                refresh_hints: vec!["users".to_string()],
            }),
            _ => None,
        },
        Some(pb::stream_event::Event::GenericError(err)) => Some(UiEvent {
            level: "error".to_string(),
            code: "generic_error".to_string(),
            message: generic_error_message(err),
            refresh_hints: vec![],
        }),
        _ => None,
    }
}

fn login_error_message(err: &pb::LoginErrorEvent) -> String {
    if err.message.trim().is_empty() {
        format!("login error ({})", err.r#type)
    } else {
        err.message.clone()
    }
}

fn mail_settings_error_message(err: &pb::MailServerSettingsErrorEvent) -> String {
    let kind = pb::MailServerSettingsErrorType::try_from(err.r#type)
        .ok()
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|| format!("UNKNOWN_MAIL_SETTINGS_ERROR_{}", err.r#type));
    format!("mail settings error ({kind})")
}

fn disk_cache_error_message(err: &pb::DiskCacheErrorEvent) -> String {
    let kind = pb::DiskCacheErrorType::try_from(err.r#type)
        .ok()
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|| format!("UNKNOWN_DISK_CACHE_ERROR_{}", err.r#type));
    format!("disk cache error ({kind})")
}

fn generic_error_message(err: &pb::GenericErrorEvent) -> String {
    let code = pb::ErrorCode::try_from(err.code)
        .ok()
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|| format!("UNKNOWN_ERROR_{}", err.code));
    format!("bridge error ({code})")
}

fn client_platform_name() -> String {
    format!("{}-tauri", std::env::consts::OS)
}

fn unix_timestamp_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    format!("[{now}]")
}
