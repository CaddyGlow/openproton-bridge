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
use crate::api::error::ApiError;
use crate::api::types::Session;
use crate::vault;

const SERVER_CONFIG_FILE: &str = "grpcServerConfig.json";
const MAIL_SETTINGS_FILE: &str = "grpc_mail_settings.json";
const SERVER_TOKEN_METADATA_KEY: &str = "server-token";

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

#[derive(Debug)]
struct PendingLogin {
    username: String,
    password: String,
    uid: String,
    access_token: String,
    refresh_token: String,
    client: ProtonClient,
}

#[derive(Debug)]
struct GrpcState {
    vault_dir: PathBuf,
    bind_host: String,
    event_tx: broadcast::Sender<pb::StreamEvent>,
    active_stream_stop: Mutex<Option<watch::Sender<bool>>>,
    pending_login: Mutex<Option<PendingLogin>>,
    shutdown_tx: watch::Sender<bool>,
    mail_settings: Mutex<StoredMailSettings>,
}

#[derive(Debug, Clone)]
struct BridgeService {
    state: Arc<GrpcState>,
}

impl BridgeService {
    fn new(state: Arc<GrpcState>) -> Self {
        Self { state }
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
                message: message.into(),
            })),
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

    fn emit_mail_settings_error(&self, message: impl Into<String>) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(pb::mail_server_settings_event::Event::Error(
                    pb::MailServerSettingsErrorEvent {
                        message: message.into(),
                    },
                )),
            },
        ));
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

        let key_passphrase = if let Some(primary_key) = user.keys.iter().find(|k| k.active == 1) {
            match api::srp::salt_for_key(
                password.as_bytes(),
                &primary_key.id,
                &salts_resp.key_salts,
            ) {
                Ok(passphrase) => Some(BASE64.encode(&passphrase)),
                Err(err) => {
                    warn!(error = %err, "could not derive key passphrase");
                    None
                }
            }
        } else {
            None
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

        vault::save_session(&session, &self.state.vault_dir).map_err(status_from_vault_error)?;
        vault::set_default_email(&self.state.vault_dir, &session.email)
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

        let mut client = ProtonClient::new().map_err(status_from_api_error)?;
        let auth = match api::auth::login(&mut client, &username, &password).await {
            Ok(auth) => auth,
            Err(err) => {
                self.emit_login_error(err.to_string());
                return Err(status_from_api_error(err));
            }
        };

        if auth.two_factor.totp_required() {
            let pending = PendingLogin {
                username: username.clone(),
                password,
                uid: auth.uid,
                access_token: auth.access_token,
                refresh_token: auth.refresh_token,
                client,
            };
            *self.state.pending_login.lock().await = Some(pending);
            self.emit_login_tfa_requested(&username);
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

    async fn login2_passwords(
        &self,
        request: Request<pb::LoginRequest>,
    ) -> Result<Response<()>, Status> {
        self.login(request).await
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
        Ok(Response::new(()))
    }

    async fn get_user_list(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::UserListResponse>, Status> {
        let sessions =
            vault::list_sessions(&self.state.vault_dir).map_err(status_from_vault_error)?;
        let users = sessions.iter().map(session_to_user).collect();
        Ok(Response::new(pb::UserListResponse { users }))
    }

    async fn get_user(&self, request: Request<String>) -> Result<Response<pb::User>, Status> {
        let lookup = request.into_inner();
        let sessions =
            vault::list_sessions(&self.state.vault_dir).map_err(status_from_vault_error)?;
        let session = sessions
            .iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(&lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
        Ok(Response::new(session_to_user(session)))
    }

    async fn logout_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let value = request.into_inner();
        let sessions =
            vault::list_sessions(&self.state.vault_dir).map_err(status_from_vault_error)?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == value || s.email.eq_ignore_ascii_case(&value))
            .ok_or_else(|| Status::not_found("user not found"))?;

        vault::remove_session_by_email(&self.state.vault_dir, &session.email)
            .map_err(status_from_vault_error)?;
        self.emit_user_disconnected(&session.email);
        Ok(Response::new(()))
    }

    async fn remove_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        self.logout_user(request).await
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
            self.emit_mail_settings_error("IMAP port is not available");
            return Err(Status::failed_precondition("IMAP port is not available"));
        }
        if !is_port_free(incoming.smtp_port as u16).await {
            self.emit_mail_settings_error("SMTP port is not available");
            return Err(Status::failed_precondition("SMTP port is not available"));
        }

        let mut settings = self.state.mail_settings.lock().await;
        settings.imap_port = incoming.imap_port;
        settings.smtp_port = incoming.smtp_port;
        settings.use_ssl_for_imap = incoming.use_ssl_for_imap;
        settings.use_ssl_for_smtp = incoming.use_ssl_for_smtp;
        save_mail_settings(&self.state.vault_dir, &settings)
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
        let (cert_path, key_path) = mail_cert_paths(&self.state.vault_dir);
        Ok(Response::new(cert_path.exists() && key_path.exists()))
    }

    async fn install_tls_certificate(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        ensure_mail_tls_certificate(&self.state.vault_dir)
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

        ensure_mail_tls_certificate(&self.state.vault_dir)
            .await
            .map_err(|e| Status::internal(format!("failed to ensure TLS certificate: {e}")))?;

        let (cert_path, key_path) = mail_cert_paths(&self.state.vault_dir);
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

pub async fn run_server(vault_dir: PathBuf, bind_host: String) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(&vault_dir)
        .await
        .with_context(|| format!("failed to create vault dir {}", vault_dir.display()))?;

    let listener = TcpListener::bind(format!("{bind_host}:0"))
        .await
        .with_context(|| format!("failed to bind gRPC listener on {bind_host}"))?;
    let port = listener
        .local_addr()
        .context("failed to read listener local address")?
        .port();

    let token = generate_server_token();
    let (cert_pem, key_pem) = generate_ephemeral_tls_cert()?;
    write_server_config(
        &vault_dir,
        &GrpcServerConfig {
            port,
            cert: cert_pem.clone(),
            token: token.clone(),
            file_socket_path: String::new(),
        },
    )
    .await?;

    let settings = load_mail_settings(&vault_dir).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, _) = broadcast::channel(128);
    let state = Arc::new(GrpcState {
        vault_dir: vault_dir.clone(),
        bind_host,
        event_tx,
        active_stream_stop: Mutex::new(None),
        pending_login: Mutex::new(None),
        shutdown_tx: shutdown_tx.clone(),
        mail_settings: Mutex::new(settings),
    });

    let service = BridgeService::new(state);
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

fn status_from_api_error(err: ApiError) -> Status {
    match err {
        ApiError::TwoFactorRequired => Status::failed_precondition("2FA required"),
        ApiError::NotLoggedIn => Status::unauthenticated("not logged in"),
        ApiError::SessionExpired => Status::unauthenticated("session expired"),
        ApiError::Auth(message) => Status::unauthenticated(message),
        ApiError::Api { code, message } => Status::internal(format!("api error {code}: {message}")),
        ApiError::Http(err) => Status::unavailable(format!("http error: {err}")),
        ApiError::Json(err) => Status::internal(format!("json error: {err}")),
        ApiError::Io(err) => Status::internal(format!("io error: {err}")),
        ApiError::Srp(err) => Status::internal(format!("srp error: {err}")),
    }
}

fn status_from_vault_error(err: vault::VaultError) -> Status {
    Status::internal(format!("vault error: {err}"))
}

fn session_to_user(session: &Session) -> pb::User {
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
        split_mode: false,
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

async fn write_server_config(dir: &Path, cfg: &GrpcServerConfig) -> anyhow::Result<()> {
    let path = dir.join(SERVER_CONFIG_FILE);
    let tmp_path = dir.join(format!("{SERVER_CONFIG_FILE}.tmp"));
    let payload = serde_json::to_vec_pretty(cfg).context("failed to encode server config")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write temp server config {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, &path)
        .await
        .with_context(|| format!("failed to rename server config to {}", path.display()))?;
    info!(path = %path.display(), "saved grpc server config");
    Ok(())
}

async fn load_mail_settings(dir: &Path) -> anyhow::Result<StoredMailSettings> {
    let path = dir.join(MAIL_SETTINGS_FILE);
    if !path.exists() {
        return Ok(StoredMailSettings::default());
    }
    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&payload).with_context(|| format!("failed to parse {}", path.display()))
}

async fn save_mail_settings(dir: &Path, settings: &StoredMailSettings) -> anyhow::Result<()> {
    let path = dir.join(MAIL_SETTINGS_FILE);
    let tmp_path = dir.join(format!("{MAIL_SETTINGS_FILE}.tmp"));
    let payload = serde_json::to_vec_pretty(settings).context("failed to encode mail settings")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, &path)
        .await
        .with_context(|| format!("failed to rename settings file {}", path.display()))?;
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

    #[test]
    fn validate_server_token_works() {
        let mut meta = MetadataMap::new();
        meta.insert(SERVER_TOKEN_METADATA_KEY, "abc123".parse().unwrap());
        assert!(validate_server_token(&meta, "abc123").is_none());
        assert!(validate_server_token(&meta, "wrong").is_some());
    }

    #[tokio::test]
    async fn mail_settings_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let settings = StoredMailSettings {
            imap_port: 1144,
            smtp_port: 1026,
            use_ssl_for_imap: true,
            use_ssl_for_smtp: true,
        };
        save_mail_settings(dir.path(), &settings).await.unwrap();
        let loaded = load_mail_settings(dir.path()).await.unwrap();
        assert_eq!(loaded.imap_port, 1144);
        assert_eq!(loaded.smtp_port, 1026);
        assert!(loaded.use_ssl_for_imap);
        assert!(loaded.use_ssl_for_smtp);
    }
}
