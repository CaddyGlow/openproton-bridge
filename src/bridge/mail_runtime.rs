use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD;
use base64::Engine;
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::api;
use crate::api::types::Session;
use crate::imap;
use crate::paths::RuntimePaths;
use crate::smtp;
use crate::vault;

#[derive(Debug, Clone)]
pub struct MailRuntimeConfig {
    pub bind_host: String,
    pub imap_port: u16,
    pub smtp_port: u16,
    pub disable_tls: bool,
    pub use_ssl_for_imap: bool,
    pub use_ssl_for_smtp: bool,
    pub event_poll_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailRuntimeTransition {
    Startup,
    SettingsChange,
}

impl MailRuntimeTransition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::SettingsChange => "settings_change",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailProtocol {
    Imap,
    Smtp,
}

#[derive(Debug, thiserror::Error)]
pub enum MailRuntimeStartError {
    #[error("failed to bind IMAP listener on {addr}: {source}")]
    ImapBind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind SMTP listener on {addr}: {source}")]
    SmtpBind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Prepare(#[from] anyhow::Error),
}

impl MailRuntimeStartError {
    pub fn protocol(&self) -> Option<MailProtocol> {
        match self {
            Self::ImapBind { .. } => Some(MailProtocol::Imap),
            Self::SmtpBind { .. } => Some(MailProtocol::Smtp),
            Self::Prepare(_) => None,
        }
    }
}

pub struct MailRuntimeHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    config: MailRuntimeConfig,
    active_sessions: Vec<Session>,
    runtime_snapshot: Vec<super::accounts::RuntimeAccountInfo>,
}

impl MailRuntimeHandle {
    pub fn is_finished(&self) -> bool {
        self.join_handle.is_finished()
    }

    pub fn config(&self) -> &MailRuntimeConfig {
        &self.config
    }

    pub fn active_sessions(&self) -> &[Session] {
        &self.active_sessions
    }

    pub fn runtime_snapshot(&self) -> &[super::accounts::RuntimeAccountInfo] {
        &self.runtime_snapshot
    }

    pub async fn wait(self) -> anyhow::Result<()> {
        match self.join_handle.await {
            Ok(result) => result,
            Err(err) => Err(anyhow::Error::new(err).context("mail runtime join failed")),
        }
    }

    pub async fn stop(mut self) -> anyhow::Result<()> {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        self.wait().await
    }
}

pub async fn start(
    runtime_paths: RuntimePaths,
    config: MailRuntimeConfig,
    transition: MailRuntimeTransition,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
) -> Result<MailRuntimeHandle, MailRuntimeStartError> {
    let prepared = prepare_runtime_context(&runtime_paths, &config).await?;

    let imap_addr = format!("{}:{}", config.bind_host, config.imap_port);
    let smtp_addr = format!("{}:{}", config.bind_host, config.smtp_port);

    let imap_listener = TcpListener::bind(&imap_addr)
        .await
        .map_err(|source| MailRuntimeStartError::ImapBind {
            addr: imap_addr.clone(),
            source,
        })?;
    let smtp_listener = TcpListener::bind(&smtp_addr)
        .await
        .map_err(|source| MailRuntimeStartError::SmtpBind {
            addr: smtp_addr.clone(),
            source,
        })?;

    log_protocol_start(MailProtocol::Imap, &config, transition);
    log_protocol_start(MailProtocol::Smtp, &config, transition);

    let active_sessions = prepared.active_sessions.clone();
    let runtime_snapshot = prepared.runtime_snapshot.clone();
    let (stop_tx, stop_rx) = oneshot::channel();

    let join_handle = tokio::spawn(run_runtime(
        prepared,
        config.clone(),
        transition,
        imap_listener,
        smtp_listener,
        stop_rx,
        notify_tx,
    ));

    Ok(MailRuntimeHandle {
        stop_tx: Some(stop_tx),
        join_handle,
        config,
        active_sessions,
        runtime_snapshot,
    })
}

struct PreparedMailRuntime {
    active_sessions: Vec<Session>,
    imap_config: Arc<imap::session::SessionConfig>,
    smtp_config: Arc<smtp::session::SmtpSessionConfig>,
    runtime_accounts: Arc<super::accounts::RuntimeAccountRegistry>,
    runtime_snapshot: Vec<super::accounts::RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: super::auth_router::AuthRouter,
    event_store: Arc<dyn imap::store::MessageStore>,
    checkpoint_store: super::events::SharedCheckpointStore,
    poll_interval: Duration,
}

async fn prepare_runtime_context(
    runtime_paths: &RuntimePaths,
    config: &MailRuntimeConfig,
) -> anyhow::Result<PreparedMailRuntime> {
    if config.disable_tls {
        let addr: IpAddr = config.bind_host.parse().context("invalid bind address")?;
        if !addr.is_loopback() {
            anyhow::bail!(
                "refusing to run without TLS on non-loopback address {}. \
                 Use 127.0.0.1 with --no-tls, or remove --no-tls for STARTTLS.",
                config.bind_host
            );
        }
    }

    let settings_dir = runtime_paths.settings_dir();
    let sessions = vault::list_sessions(settings_dir).context("failed to load sessions")?;
    if sessions.is_empty() {
        anyhow::bail!("not logged in -- run `openproton-bridge login` first");
    }

    let mut active_sessions = Vec::new();
    for mut session in sessions {
        if session.access_token.is_empty() {
            let email = session.email.clone();
            match refresh_session(session, settings_dir).await {
                Ok(refreshed) => session = refreshed,
                Err(err) => {
                    tracing::warn!(
                        email = %email,
                        error = %err,
                        "skipping account: failed to refresh token"
                    );
                    continue;
                }
            }
        }

        if session.bridge_password.is_none() {
            let bridge_password = generate_bridge_password();
            session.bridge_password = Some(bridge_password);
            vault::save_session(&session, settings_dir)?;
        }

        active_sessions.push(session);
    }

    if active_sessions.is_empty() {
        anyhow::bail!("no usable accounts available after token refresh");
    }

    let mut account_registry =
        super::accounts::AccountRegistry::from_sessions(active_sessions.clone());
    for session in &active_sessions {
        let account_id = super::types::AccountId(session.uid.clone());
        let split_mode = match vault::load_split_mode_by_account_id(settings_dir, &session.uid) {
            Ok(Some(enabled)) => enabled,
            Ok(None) => false,
            Err(err) => {
                tracing::warn!(
                    email = %session.email,
                    error = %err,
                    "failed to load split mode setting, defaulting to combined"
                );
                false
            }
        };
        let _ = account_registry.set_split_mode(&account_id, split_mode);

        let client = match api::client::ProtonClient::authenticated_with_mode(
            session.api_mode.base_url(),
            session.api_mode,
            &session.uid,
            &session.access_token,
        ) {
            Ok(client) => client,
            Err(err) => {
                tracing::warn!(
                    email = %session.email,
                    error = %err,
                    "skipping address index refresh for account"
                );
                continue;
            }
        };

        match api::users::get_addresses(&client).await {
            Ok(addresses) => {
                for address in addresses.addresses {
                    if address.status == 1 {
                        account_registry.add_address_email(&account_id, &address.email);
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    email = %session.email,
                    error = %err,
                    "failed to refresh address index for account"
                );
            }
        }
    }

    let auth_router = super::auth_router::AuthRouter::new(account_registry);
    let runtime_accounts = Arc::new(super::accounts::RuntimeAccountRegistry::new(
        active_sessions.clone(),
        settings_dir.to_path_buf(),
    ));
    let runtime_snapshot = runtime_accounts.snapshot().await;
    let api_base_url = "https://mail-api.proton.me".to_string();

    let bootstrap_account_ids = active_sessions
        .iter()
        .map(|session| session.uid.clone())
        .collect::<Vec<_>>();
    let gluon_bootstrap = vault::load_gluon_store_bootstrap(settings_dir, &bootstrap_account_ids)
        .context("failed to resolve gluon vault bindings for store bootstrap")?;
    let gluon_paths = runtime_paths.gluon_paths(Some(gluon_bootstrap.gluon_dir.as_str()));
    tracing::debug!(
        gluon_dir = %gluon_paths.root().display(),
        accounts = gluon_bootstrap.accounts.len(),
        "resolved gluon store bootstrap context"
    );

    let account_storage_ids = gluon_bootstrap
        .accounts
        .iter()
        .map(|account| (account.account_id.clone(), account.storage_user_id.clone()))
        .collect();
    let store: Arc<dyn imap::store::MessageStore> = imap::store::new_runtime_message_store(
        gluon_paths.root().to_path_buf(),
        account_storage_ids,
    )
    .context("failed to initialize runtime IMAP store")?;
    let event_store = store.clone();

    let imap_config = Arc::new(imap::session::SessionConfig {
        api_base_url: api_base_url.clone(),
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
        store,
    });

    let smtp_config = Arc::new(smtp::session::SmtpSessionConfig {
        api_base_url: api_base_url.clone(),
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
    });

    if !config.disable_tls {
        let cert_dir = settings_dir.join("tls");
        let _imap_server = imap::server::ImapServer::new().with_tls(&cert_dir)?;
        let _smtp_server = smtp::server::SmtpServer::new().with_tls(&cert_dir)?;
    } else {
        imap::server::clear_runtime_tls_config();
        smtp::server::clear_runtime_tls_config();
    }

    Ok(PreparedMailRuntime {
        active_sessions,
        imap_config,
        smtp_config,
        runtime_accounts,
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store: Arc::new(super::events::VaultCheckpointStore::new(
            settings_dir.to_path_buf(),
        )),
        poll_interval: config.event_poll_interval,
    })
}

async fn run_runtime(
    prepared: PreparedMailRuntime,
    config: MailRuntimeConfig,
    transition: MailRuntimeTransition,
    imap_listener: TcpListener,
    smtp_listener: TcpListener,
    shutdown_rx: oneshot::Receiver<()>,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
) -> anyhow::Result<()> {
    let PreparedMailRuntime {
        imap_config,
        smtp_config,
        runtime_accounts,
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store,
        poll_interval,
        ..
    } = prepared;

    let account_lookup: HashMap<String, String> = runtime_snapshot
        .iter()
        .map(|info| (info.account_id.0.clone(), info.email.clone()))
        .collect();
    let notify_for_callback = notify_tx.clone();
    let sync_progress_callback: super::events::SyncProgressCallback =
        Arc::new(move |event| match event {
            super::events::SyncProgressUpdate::Started { user_id } => {
                let label = account_lookup
                    .get(&user_id)
                    .cloned()
                    .unwrap_or_else(|| user_id.clone());
                tracing::info!(user_id = %user_id, "account sync started");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let _ = tx.send(format!("[event] sync started: {label}"));
                }
            }
            super::events::SyncProgressUpdate::Progress {
                user_id,
                progress,
                elapsed_ms: _,
                remaining_ms: _,
            } => {
                tracing::debug!(user_id = %user_id, progress, "account sync progress");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let label = account_lookup
                        .get(&user_id)
                        .cloned()
                        .unwrap_or_else(|| user_id.clone());
                    let _ = tx.send(format!("[event] sync progress: {label} ({:.1}%)", progress * 100.0));
                }
            }
            super::events::SyncProgressUpdate::Finished { user_id } => {
                let label = account_lookup
                    .get(&user_id)
                    .cloned()
                    .unwrap_or_else(|| user_id.clone());
                tracing::info!(user_id = %user_id, "account sync finished");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let _ = tx.send(format!("[event] sync finished: {label}"));
                }
            }
        });

    let event_workers = super::events::start_event_worker_group_with_sync_progress(
        runtime_accounts.clone(),
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store,
        Some(sync_progress_callback),
        poll_interval,
    );

    let health_task = tokio::spawn(report_runtime_health_periodically(
        runtime_accounts,
        notify_tx.clone(),
    ));
    let mut imap_task = tokio::spawn(async move {
        imap::server::run_server_with_listener(imap_listener, imap_config).await
    });
    let mut smtp_task = tokio::spawn(async move {
        smtp::server::run_server_with_listener(smtp_listener, smtp_config).await
    });

    let mut shutdown_rx = shutdown_rx;
    let serve_result: anyhow::Result<()> = tokio::select! {
        _ = &mut shutdown_rx => {
            Ok(())
        }
        result = &mut imap_task => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("IMAP server task failed")),
            }
        }
        result = &mut smtp_task => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("SMTP server task failed")),
            }
        }
    };

    log_protocol_stopping(MailProtocol::Imap, &config, transition);
    log_protocol_stopping(MailProtocol::Smtp, &config, transition);

    if !imap_task.is_finished() {
        imap_task.abort();
    }
    if !smtp_task.is_finished() {
        smtp_task.abort();
    }
    let _ = imap_task.await;
    let _ = smtp_task.await;

    health_task.abort();
    let _ = health_task.await;
    event_workers.shutdown().await;

    tracing::info!(
        port = config.imap_port,
        ssl = config.use_ssl_for_imap,
        transition = transition.as_str(),
        "IMAP server listener closed"
    );
    tracing::info!(
        port = config.smtp_port,
        ssl = config.use_ssl_for_smtp,
        transition = transition.as_str(),
        "SMTP server listener closed"
    );

    if let Some(tx) = notify_tx.as_ref() {
        if serve_result.is_ok() {
            let _ = tx.send("[event] serve runtime stopped".to_string());
        }
    }

    serve_result
}

fn log_protocol_start(
    protocol: MailProtocol,
    config: &MailRuntimeConfig,
    transition: MailRuntimeTransition,
) {
    match (protocol, transition) {
        (MailProtocol::Imap, MailRuntimeTransition::SettingsChange) => {
            tracing::info!(
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                transition = transition.as_str(),
                "Restarting IMAP server"
            );
        }
        (MailProtocol::Smtp, MailRuntimeTransition::SettingsChange) => {
            tracing::info!(
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                transition = transition.as_str(),
                "Restarting SMTP server"
            );
        }
        (MailProtocol::Imap, _) => {
            tracing::info!(
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                transition = transition.as_str(),
                "Starting IMAP server"
            );
        }
        (MailProtocol::Smtp, _) => {
            tracing::info!(
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                transition = transition.as_str(),
                "Starting SMTP server"
            );
        }
    }
}

fn log_protocol_stopping(
    protocol: MailProtocol,
    config: &MailRuntimeConfig,
    transition: MailRuntimeTransition,
) {
    match protocol {
        MailProtocol::Imap => {
            tracing::info!(
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                transition = transition.as_str(),
                "Stopping IMAP server"
            );
        }
        MailProtocol::Smtp => {
            tracing::info!(
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                transition = transition.as_str(),
                "Stopping SMTP server"
            );
        }
    }
}

pub fn log_bridge_start_failure(protocol: MailProtocol, config: &MailRuntimeConfig, error: &str) {
    match protocol {
        MailProtocol::Imap => {
            tracing::warn!(
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                error = %error,
                "Failed to start IMAP server on bridge start"
            );
        }
        MailProtocol::Smtp => {
            tracing::warn!(
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                error = %error,
                "Failed to start SMTP server on bridge start"
            );
        }
    }
}

async fn refresh_session(session: Session, settings_dir: &std::path::Path) -> anyhow::Result<Session> {
    tracing::info!(
        pkg = "bridge/token",
        user_id = %session.uid,
        email = %session.email,
        "access token missing, refreshing via stored refresh token"
    );
    let (auth, refreshed_api_mode) = api::auth::refresh_auth_with_mode_fallback(
        session.api_mode,
        &session.uid,
        &session.refresh_token,
        None,
    )
    .await
    .map_err(|err| {
        tracing::warn!(
            pkg = "bridge/token",
            user_id = %session.uid,
            email = %session.email,
            error = %err,
            "stored refresh token exchange failed"
        );
        err
    })?;
    tracing::info!(
        pkg = "bridge/token",
        user_id = %auth.uid,
        "stored refresh token exchange completed"
    );

    let mut refreshed = Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        api_mode: refreshed_api_mode,
        ..session
    };

    let mut canonical_user_id = None;
    let client = api::client::ProtonClient::authenticated_with_mode(
        refreshed.api_mode.base_url(),
        refreshed.api_mode,
        &refreshed.uid,
        &refreshed.access_token,
    )?;
    match api::users::get_user(&client).await {
        Ok(user_resp) => {
            canonical_user_id = Some(user_resp.user.id.clone());
            if !user_resp.user.email.trim().is_empty() {
                refreshed.email = user_resp.user.email.clone();
            }
            if !user_resp.user.display_name.trim().is_empty() {
                refreshed.display_name = user_resp.user.display_name.clone();
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to refresh canonical user context after token refresh");
        }
    }

    vault::save_session_with_user_id(&refreshed, canonical_user_id.as_deref(), settings_dir)?;
    tracing::info!(
        pkg = "bridge/token",
        user_id = %refreshed.uid,
        email = %refreshed.email,
        "session token refresh persisted"
    );
    Ok(refreshed)
}

fn generate_bridge_password() -> String {
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    BASE64_URL_NO_PAD.encode(token)
}

async fn report_runtime_health_periodically(
    runtime_accounts: Arc<super::accounts::RuntimeAccountRegistry>,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
) {
    use tokio::time::{interval, MissedTickBehavior};

    let mut ticker = interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;
    let mut previous_health = HashMap::new();

    loop {
        ticker.tick().await;
        let snapshot = runtime_accounts.snapshot().await;
        let mut healthy = 0usize;
        let mut degraded = 0usize;
        let mut unavailable = 0usize;

        for info in &snapshot {
            match info.health {
                super::accounts::AccountHealth::Healthy => healthy += 1,
                super::accounts::AccountHealth::Degraded => degraded += 1,
                super::accounts::AccountHealth::Unavailable => unavailable += 1,
            }
        }

        tracing::info!(
            total_accounts = snapshot.len(),
            healthy,
            degraded,
            unavailable,
            "runtime account health snapshot"
        );

        let mut seen_account_ids = std::collections::HashSet::new();

        for info in &snapshot {
            seen_account_ids.insert(info.account_id.0.clone());
            let previous = previous_health.insert(info.account_id.0.clone(), info.health);
            if let Some(tx) = notify_tx.as_ref() {
                if previous != Some(info.health) {
                    let is_baseline_healthy =
                        previous.is_none() && matches!(info.health, super::accounts::AccountHealth::Healthy);
                    if !is_baseline_healthy {
                        let _ = tx.send(format!(
                            "[event] account health: {} ({}) -> {:?}",
                            info.email, info.account_id.0, info.health
                        ));
                    }
                }
            }

            if matches!(info.health, super::accounts::AccountHealth::Unavailable) {
                tracing::warn!(
                    account_id = %info.account_id.0,
                    email = %info.email,
                    health = ?info.health,
                    "account unavailable while server is running"
                );
            } else {
                tracing::debug!(
                    account_id = %info.account_id.0,
                    email = %info.email,
                    health = ?info.health,
                    "account runtime health detail"
                );
            }
        }

        previous_health.retain(|account_id, _| seen_account_ids.contains(account_id));
    }
}
