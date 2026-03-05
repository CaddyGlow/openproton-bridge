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
use crate::pim::store::PimStore;
use crate::pim::{sync_calendar, sync_contacts};
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

const PIM_RECONCILE_TICK_INTERVAL: Duration = Duration::from_secs(10 * 60);
const PIM_CONTACTS_RECONCILE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const PIM_CALENDAR_RECONCILE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

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

    let imap_listener =
        TcpListener::bind(&imap_addr)
            .await
            .map_err(|source| MailRuntimeStartError::ImapBind {
                addr: imap_addr.clone(),
                source,
            })?;
    let smtp_listener =
        TcpListener::bind(&smtp_addr)
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
    pim_stores: HashMap<String, Arc<PimStore>>,
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
    let mut prefetched_auth_material = Vec::new();
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

        let user_keys = match api::users::get_user(&client).await {
            Ok(user_resp) => Some(user_resp.user.keys),
            Err(err) => {
                tracing::warn!(
                    email = %session.email,
                    error = %err,
                    "failed to prefetch user keys for IMAP login cache"
                );
                None
            }
        };

        match api::users::get_addresses(&client).await {
            Ok(addresses_resp) => {
                for address in &addresses_resp.addresses {
                    if address.status == 1 {
                        account_registry.add_address_email(&account_id, &address.email);
                    }
                }
                if let Some(user_keys) = user_keys {
                    prefetched_auth_material.push((
                        account_id.clone(),
                        Arc::new(super::accounts::RuntimeAuthMaterial {
                            user_keys,
                            addresses: addresses_resp.addresses,
                        }),
                    ));
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
    for (account_id, material) in prefetched_auth_material {
        let _ = runtime_accounts
            .set_auth_material(&account_id, material)
            .await;
    }
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
    let mut pim_stores = HashMap::new();
    for account in &gluon_bootstrap.accounts {
        let pim_store = PimStore::new(gluon_paths.account_db_path(&account.storage_user_id))
            .with_context(|| {
                format!(
                    "failed to initialize PIM store for account {}",
                    account.account_id
                )
            })?;
        pim_stores.insert(account.account_id.clone(), Arc::new(pim_store));
    }

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
        pim_stores,
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
        pim_stores,
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
                    let _ = tx.send(format!(
                        "[event] sync progress: {label} ({:.1}%)",
                        progress * 100.0
                    ));
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

    let pim_stores_for_reconcile = pim_stores.clone();
    let event_workers = super::events::start_event_worker_group_with_sync_progress_and_pim(
        runtime_accounts.clone(),
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store,
        pim_stores,
        Some(sync_progress_callback),
        poll_interval,
    );

    let pim_reconcile_task = tokio::spawn(run_pim_reconcile_periodically(
        runtime_accounts.clone(),
        pim_stores_for_reconcile,
        notify_tx.clone(),
    ));
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
    pim_reconcile_task.abort();
    let _ = pim_reconcile_task.await;
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
                service = "server-manager",
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                transition = transition.as_str(),
                msg = "Restarting IMAP server",
                "Restarting IMAP server"
            );
        }
        (MailProtocol::Smtp, MailRuntimeTransition::SettingsChange) => {
            tracing::info!(
                service = "server-manager",
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                transition = transition.as_str(),
                msg = "Restarting SMTP server",
                "Restarting SMTP server"
            );
        }
        (MailProtocol::Imap, _) => {
            tracing::info!(
                service = "server-manager",
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                transition = transition.as_str(),
                msg = "Starting IMAP server",
                "Starting IMAP server"
            );
        }
        (MailProtocol::Smtp, _) => {
            tracing::info!(
                service = "server-manager",
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                transition = transition.as_str(),
                msg = "Starting SMTP server",
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
                service = "server-manager",
                port = config.imap_port,
                ssl = config.use_ssl_for_imap,
                transition = transition.as_str(),
                msg = "Stopping IMAP server",
                "Stopping IMAP server"
            );
        }
        MailProtocol::Smtp => {
            tracing::info!(
                service = "server-manager",
                port = config.smtp_port,
                ssl = config.use_ssl_for_smtp,
                transition = transition.as_str(),
                msg = "Stopping SMTP server",
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

async fn refresh_session(
    session: Session,
    settings_dir: &std::path::Path,
) -> anyhow::Result<Session> {
    let refresh_lock = super::token_refresh::lock_for_account(&session.uid);
    let _refresh_guard = refresh_lock.lock().await;
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
        handle_startup_refresh_failure(&session, &err);
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

fn handle_startup_refresh_failure(session: &Session, err: &api::error::ApiError) {
    if !api::error::is_invalid_refresh_token_error(err) {
        return;
    }

    tracing::warn!(
        pkg = "bridge/token",
        user_id = %session.uid,
        email = %session.email,
        "stored refresh token is invalid; keeping account session in vault"
    );
}

fn generate_bridge_password() -> String {
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    BASE64_URL_NO_PAD.encode(token)
}

async fn run_pim_reconcile_periodically(
    runtime_accounts: Arc<super::accounts::RuntimeAccountRegistry>,
    pim_stores: HashMap<String, Arc<PimStore>>,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
) {
    use tokio::time::{interval, MissedTickBehavior};

    let mut ticker = interval(PIM_RECONCILE_TICK_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let snapshot = runtime_accounts.snapshot().await;
        for account in snapshot {
            let Some(store) = pim_stores.get(&account.account_id.0) else {
                continue;
            };

            if !is_pim_contacts_due(store).unwrap_or(true)
                && !is_pim_calendar_due(store).unwrap_or(true)
            {
                continue;
            }

            let session = match runtime_accounts
                .with_valid_access_token(&account.account_id)
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    tracing::debug!(
                        account_id = %account.account_id.0,
                        email = %account.email,
                        error = %err,
                        "skipping periodic PIM reconciliation: no valid session"
                    );
                    continue;
                }
            };

            let client = match api::client::ProtonClient::authenticated_with_mode(
                session.api_mode.base_url(),
                session.api_mode,
                &session.uid,
                &session.access_token,
            ) {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!(
                        account_id = %account.account_id.0,
                        email = %account.email,
                        error = %err,
                        "failed to initialize API client for periodic PIM reconciliation"
                    );
                    let _ = runtime_accounts
                        .set_health(
                            &account.account_id,
                            super::accounts::AccountHealth::Degraded,
                        )
                        .await;
                    continue;
                }
            };

            if is_pim_contacts_due(store).unwrap_or(true) {
                match sync_contacts::bootstrap_contacts(&client, store, 0).await {
                    Ok(summary) => {
                        tracing::info!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            contacts_seen = summary.contacts_seen,
                            contacts_soft_deleted = summary.contacts_soft_deleted,
                            contacts_upserted = summary.contacts_upserted,
                            "periodic contacts reconciliation completed"
                        );
                        if let Some(tx) = notify_tx.as_ref() {
                            let _ = tx.send(format!(
                                "[event] contacts reconciled: {} ({})",
                                account.email, account.account_id.0
                            ));
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            error = %err,
                            "periodic contacts reconciliation failed"
                        );
                        let _ = runtime_accounts
                            .set_health(
                                &account.account_id,
                                super::accounts::AccountHealth::Degraded,
                            )
                            .await;
                    }
                }
            }

            if is_pim_calendar_due(store).unwrap_or(true) {
                match sync_calendar::bootstrap_calendars(
                    &client,
                    store,
                    &api::calendar::CalendarEventsQuery::default(),
                )
                .await
                {
                    Ok(summary) => {
                        tracing::info!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            calendars_seen = summary.calendars_seen,
                            calendars_soft_deleted = summary.calendars_soft_deleted,
                            events_upserted = summary.events_upserted,
                            "periodic calendar reconciliation completed"
                        );
                        if let Some(tx) = notify_tx.as_ref() {
                            let _ = tx.send(format!(
                                "[event] calendars reconciled: {} ({})",
                                account.email, account.account_id.0
                            ));
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            error = %err,
                            "periodic calendar reconciliation failed"
                        );
                        let _ = runtime_accounts
                            .set_health(
                                &account.account_id,
                                super::accounts::AccountHealth::Degraded,
                            )
                            .await;
                    }
                }
            }
        }
    }
}

fn is_pim_contacts_due(store: &PimStore) -> anyhow::Result<bool> {
    is_sync_scope_due(
        store,
        "contacts.last_full_sync_ms",
        PIM_CONTACTS_RECONCILE_INTERVAL,
    )
}

fn is_pim_calendar_due(store: &PimStore) -> anyhow::Result<bool> {
    is_sync_scope_due(
        store,
        "calendar.last_full_sync_ms",
        PIM_CALENDAR_RECONCILE_INTERVAL,
    )
}

fn is_sync_scope_due(store: &PimStore, scope: &str, interval: Duration) -> anyhow::Result<bool> {
    let now_ms = unix_now_millis() as i64;
    let Some(last_sync_ms) = store.get_sync_state_int(scope)? else {
        return Ok(true);
    };
    if last_sync_ms <= 0 {
        return Ok(true);
    }

    let due_after_ms = interval.as_millis() as i64;
    Ok(now_ms.saturating_sub(last_sync_ms) >= due_after_ms)
}

fn unix_now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
                    let is_baseline_healthy = previous.is_none()
                        && matches!(info.health, super::accounts::AccountHealth::Healthy);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{handle_startup_refresh_failure, is_sync_scope_due, Session};
    use crate::api::error::ApiError;
    use crate::api::types::ApiMode;
    use crate::pim::store::PimStore;

    fn session(uid: &str, email: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: String::new(),
            refresh_token: format!("refresh-{uid}"),
            email: email.to_string(),
            display_name: uid.to_string(),
            api_mode: ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-password".to_string()),
        }
    }

    fn pim_store() -> PimStore {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("account.db");
        Box::leak(Box::new(tmp));
        PimStore::new(db_path).unwrap()
    }

    #[test]
    fn startup_invalid_refresh_failure_keeps_persisted_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session = session("uid-1", "alice@proton.me");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let err = ApiError::Api {
            code: 10013,
            message: "Invalid refresh token".to_string(),
            details: None,
        };
        handle_startup_refresh_failure(&session, &err);

        let persisted = crate::vault::load_session_by_email(tmp.path(), "alice@proton.me").is_ok();
        assert!(persisted);
    }

    #[test]
    fn startup_non_invalid_refresh_failure_keeps_persisted_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session = session("uid-1", "alice@proton.me");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let err = ApiError::Auth("temporary auth failure".to_string());
        handle_startup_refresh_failure(&session, &err);

        let persisted = crate::vault::load_session_by_email(tmp.path(), "alice@proton.me").is_ok();
        assert!(persisted);
    }

    #[test]
    fn startup_invalid_refresh_failure_keeps_session_when_email_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let stored = session("uid-1", "stored@proton.me");
        crate::vault::save_session(&stored, tmp.path()).unwrap();

        let err = ApiError::Api {
            code: 10013,
            message: "Invalid refresh token".to_string(),
            details: None,
        };
        handle_startup_refresh_failure(&stored, &err);

        assert!(crate::vault::load_session_by_account_id(tmp.path(), "uid-1").is_ok());
    }

    #[test]
    fn pim_scope_due_when_sync_state_missing() {
        let store = pim_store();
        let due = is_sync_scope_due(
            &store,
            "contacts.last_full_sync_ms",
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(due);
    }

    #[test]
    fn pim_scope_not_due_when_recent() {
        let store = pim_store();
        let now_ms = super::unix_now_millis() as i64;
        store
            .set_sync_state_int("contacts.last_full_sync_ms", now_ms)
            .unwrap();
        let due = is_sync_scope_due(
            &store,
            "contacts.last_full_sync_ms",
            Duration::from_secs(24 * 60 * 60),
        )
        .unwrap();
        assert!(!due);
    }

    #[test]
    fn pim_scope_due_when_stale() {
        let store = pim_store();
        let now_ms = super::unix_now_millis() as i64;
        let stale_ms = now_ms - (3 * 24 * 60 * 60 * 1000);
        store
            .set_sync_state_int("contacts.last_full_sync_ms", stale_ms)
            .unwrap();
        let due = is_sync_scope_due(
            &store,
            "contacts.last_full_sync_ms",
            Duration::from_secs(24 * 60 * 60),
        )
        .unwrap();
        assert!(due);
    }
}
