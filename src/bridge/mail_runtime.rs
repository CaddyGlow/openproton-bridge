use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
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
use crate::bridge::calendar_notify::{CalendarChangeNotifier, SharedCalendarChangeNotifier};
use crate::dav;
use crate::imap;
use crate::paths::RuntimePaths;
use crate::pim::store::PimStore;
use crate::pim::{sync_calendar, sync_contacts};
use crate::smtp;
use crate::vault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavTlsMode {
    None,
    StartTls,
}

impl DavTlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StartTls => "starttls",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MailRuntimeConfig {
    pub bind_host: String,
    pub imap_port: u16,
    pub smtp_port: u16,
    pub dav_enable: bool,
    pub dav_port: u16,
    pub dav_tls_mode: DavTlsMode,
    pub disable_tls: bool,
    pub use_ssl_for_imap: bool,
    pub use_ssl_for_smtp: bool,
    pub api_base_url: String,
    pub event_poll_interval: Duration,
    pub pim_reconcile_tick_interval: Duration,
    pub pim_contacts_reconcile_interval: Duration,
    pub pim_calendar_reconcile_interval: Duration,
    pub pim_calendar_horizon_reconcile_interval: Duration,
}

pub const DEFAULT_IMAP_IMPLICIT_TLS_PORT: u16 = 1993;
pub const DEFAULT_SMTP_IMPLICIT_TLS_PORT: u16 = 1465;

pub const DEFAULT_PIM_RECONCILE_TICK_INTERVAL: Duration = Duration::from_secs(10 * 60);
pub const DEFAULT_PIM_CONTACTS_RECONCILE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
pub const DEFAULT_PIM_CALENDAR_RECONCILE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
pub const DEFAULT_PIM_CALENDAR_HORIZON_RECONCILE_INTERVAL: Duration =
    Duration::from_secs(12 * 60 * 60);

#[derive(Debug, Clone, Default)]
pub struct PimReconcileMetricsSnapshot {
    pub sweeps_total: u64,
    pub last_sweep_elapsed_ms: u64,
    pub last_sweep_completed_at_ms: i64,
    pub accounts_seen_total: u64,
    pub accounts_with_store_total: u64,
    pub accounts_skipped_no_session_total: u64,
    pub client_init_failures_total: u64,
    pub contacts_runs_due_total: u64,
    pub contacts_success_total: u64,
    pub contacts_failures_total: u64,
    pub calendar_full_runs_due_total: u64,
    pub calendar_full_success_total: u64,
    pub calendar_full_failures_total: u64,
    pub calendar_horizon_runs_due_total: u64,
    pub calendar_horizon_success_total: u64,
    pub calendar_horizon_failures_total: u64,
    pub contacts_rows_upserted_total: u64,
    pub contacts_rows_soft_deleted_total: u64,
    pub calendar_rows_upserted_total: u64,
    pub calendar_rows_soft_deleted_total: u64,
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
    Dav,
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
    #[error("failed to bind IMAP implicit TLS listener on {addr}: {source}")]
    ImapImplicitTlsBind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind SMTP implicit TLS listener on {addr}: {source}")]
    SmtpImplicitTlsBind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind DAV listener on {addr}: {source}")]
    DavBind {
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
            Self::ImapImplicitTlsBind { .. } => Some(MailProtocol::Imap),
            Self::SmtpImplicitTlsBind { .. } => Some(MailProtocol::Smtp),
            Self::DavBind { .. } => Some(MailProtocol::Dav),
            Self::Prepare(_) => None,
        }
    }
}

pub struct MailRuntimeHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    config: MailRuntimeConfig,
    active_sessions: Vec<Session>,
    runtime_accounts: Arc<super::accounts::RuntimeAccountRegistry>,
    runtime_snapshot: Vec<super::accounts::RuntimeAccountInfo>,
    pim_reconcile_metrics: Arc<std::sync::RwLock<PimReconcileMetricsSnapshot>>,
    imap_connector: Arc<dyn imap::gluon_connector::GluonImapConnector>,
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

    pub fn runtime_accounts(&self) -> Arc<super::accounts::RuntimeAccountRegistry> {
        self.runtime_accounts.clone()
    }

    pub fn runtime_snapshot(&self) -> &[super::accounts::RuntimeAccountInfo] {
        &self.runtime_snapshot
    }

    pub fn pim_reconcile_metrics(&self) -> PimReconcileMetricsSnapshot {
        self.pim_reconcile_metrics
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    pub fn imap_connector(&self) -> Arc<dyn imap::gluon_connector::GluonImapConnector> {
        self.imap_connector.clone()
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
    session_manager: Arc<super::session_manager::SessionManager>,
    config: MailRuntimeConfig,
    transition: MailRuntimeTransition,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
    external_sync_callback: Option<super::events::SyncProgressCallback>,
) -> Result<MailRuntimeHandle, MailRuntimeStartError> {
    let prepared = prepare_runtime_context(&runtime_paths, session_manager, &config).await?;

    let imap_addr = format!("{}:{}", config.bind_host, config.imap_port);
    let smtp_addr = format!("{}:{}", config.bind_host, config.smtp_port);
    let imap_implicit_tls_addr = format!("{}:{}", config.bind_host, DEFAULT_IMAP_IMPLICIT_TLS_PORT);
    let smtp_implicit_tls_addr = format!("{}:{}", config.bind_host, DEFAULT_SMTP_IMPLICIT_TLS_PORT);
    let dav_addr = format!("{}:{}", config.bind_host, config.dav_port);

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
    let imap_implicit_tls_listener = if !config.disable_tls && config.use_ssl_for_imap {
        Some(
            TcpListener::bind(&imap_implicit_tls_addr)
                .await
                .map_err(|source| MailRuntimeStartError::ImapImplicitTlsBind {
                    addr: imap_implicit_tls_addr.clone(),
                    source,
                })?,
        )
    } else {
        None
    };
    let smtp_implicit_tls_listener = if !config.disable_tls && config.use_ssl_for_smtp {
        Some(
            TcpListener::bind(&smtp_implicit_tls_addr)
                .await
                .map_err(|source| MailRuntimeStartError::SmtpImplicitTlsBind {
                    addr: smtp_implicit_tls_addr.clone(),
                    source,
                })?,
        )
    } else {
        None
    };
    let dav_listener = if config.dav_enable {
        Some(TcpListener::bind(&dav_addr).await.map_err(|source| {
            MailRuntimeStartError::DavBind {
                addr: dav_addr.clone(),
                source,
            }
        })?)
    } else {
        None
    };
    log_protocol_start(MailProtocol::Imap, &config, transition);
    log_protocol_start(MailProtocol::Smtp, &config, transition);
    if config.dav_enable {
        log_protocol_start(MailProtocol::Dav, &config, transition);
    }
    log_implicit_tls_start(&config, transition);

    let active_sessions = prepared.active_sessions.clone();
    let runtime_accounts = prepared.runtime_accounts.clone();
    let runtime_snapshot = prepared.runtime_snapshot.clone();
    let pim_reconcile_metrics = Arc::new(std::sync::RwLock::new(
        PimReconcileMetricsSnapshot::default(),
    ));
    let imap_connector = prepared.imap_config.gluon_connector.clone();
    let (stop_tx, stop_rx) = oneshot::channel();

    let join_handle = tokio::spawn(run_runtime(
        prepared,
        config.clone(),
        transition,
        imap_listener,
        smtp_listener,
        imap_implicit_tls_listener,
        smtp_implicit_tls_listener,
        dav_listener,
        stop_rx,
        notify_tx,
        external_sync_callback,
        pim_reconcile_metrics.clone(),
    ));

    Ok(MailRuntimeHandle {
        stop_tx: Some(stop_tx),
        join_handle,
        config,
        active_sessions,
        runtime_accounts,
        runtime_snapshot,
        pim_reconcile_metrics,
        imap_connector,
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
    event_mailbox_view: Arc<dyn imap::mailbox_view::GluonMailboxView>,
    pim_stores: HashMap<String, Arc<PimStore>>,
    checkpoint_store: super::events::SharedCheckpointStore,
    poll_interval: Duration,
    pim_reconcile_tick_interval: Duration,
    pim_contacts_reconcile_interval: Duration,
    pim_calendar_reconcile_interval: Duration,
    pim_calendar_horizon_reconcile_interval: Duration,
    settings_dir: PathBuf,
}

async fn prepare_runtime_context(
    runtime_paths: &RuntimePaths,
    session_manager: Arc<super::session_manager::SessionManager>,
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
    let sessions = session_manager
        .load_sessions_from_vault()
        .await
        .context("failed to load sessions")?;
    if sessions.is_empty() {
        anyhow::bail!("not logged in -- run `openproton-bridge login` first");
    }

    let mut active_sessions = Vec::new();
    for session in sessions {
        let account_id = super::types::AccountId(session.uid.clone());
        let mut session = if session.access_token.is_empty() {
            let email = session.email.clone();
            match session_manager.with_valid_access_token(&account_id).await {
                Ok(refreshed) => refreshed,
                Err(err) => {
                    tracing::warn!(
                        email = %email,
                        error = %err,
                        "skipping account: failed to refresh token"
                    );
                    continue;
                }
            }
        } else {
            session
        };

        if session.bridge_password.is_none() {
            let bridge_password = generate_bridge_password();
            session.bridge_password = Some(bridge_password);
            session_manager
                .persist_session(session.clone(), None)
                .await
                .context("failed to persist generated bridge password")?;
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
    let runtime_accounts = session_manager.runtime_accounts();
    for (account_id, material) in prefetched_auth_material {
        let _ = runtime_accounts
            .set_auth_material(&account_id, material)
            .await;
    }
    let runtime_snapshot = runtime_accounts.snapshot().await;
    let api_base_url = config.api_base_url.clone();

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

    // Ensure gluon directories exist before opening any stores (including
    // read-only ones that would otherwise fail with MissingCacheRoot).
    ensure_gluon_dirs_and_sync_state(&gluon_bootstrap, gluon_paths.root(), settings_dir);

    let mailbox_catalog =
        imap::mailbox_catalog::RuntimeMailboxCatalog::new(runtime_accounts.clone());
    let mailbox_view = build_mailbox_view(&gluon_bootstrap, gluon_paths.root())
        .context("failed to initialize IMAP mailbox view backend")?;
    let mailbox_mutation = build_mailbox_mutation(&gluon_bootstrap, gluon_paths.root())
        .context("failed to initialize IMAP mailbox mutation backend")?;
    let event_mailbox_view = build_event_mailbox_view(&gluon_bootstrap, gluon_paths.root())
        .context("failed to initialize event mailbox view backend")?;
    let gluon_connector = build_gluon_connector(&gluon_bootstrap, gluon_paths.root())
        .context("failed to initialize Gluon connector backend")?;

    let schema_init_store =
        build_gluon_mail_compatible_store(&gluon_bootstrap, gluon_paths.root(), false)
            .context("failed to open store for eager schema init")?;
    for account in &gluon_bootstrap.accounts {
        if let Err(err) = schema_init_store.initialize_upstream_schema(&account.storage_user_id) {
            tracing::warn!(
                account_id = %account.account_id,
                error = %err,
                "failed to eagerly initialize upstream mail schema"
            );
        }
    }

    let contacts_paths = {
        let mut root = gluon_paths.root().to_path_buf();
        root.pop();
        crate::paths::GluonPaths::new(root.join("gluon-contacts"))
    };
    let calendar_paths = {
        let mut root = gluon_paths.root().to_path_buf();
        root.pop();
        crate::paths::GluonPaths::new(root.join("gluon-calendar"))
    };
    std::fs::create_dir_all(contacts_paths.backend_db_dir())?;
    std::fs::create_dir_all(calendar_paths.backend_db_dir())?;

    let mut pim_stores = HashMap::new();
    for account in &gluon_bootstrap.accounts {
        let contacts_db = contacts_paths.account_db_path(&account.storage_user_id);
        let calendar_db = calendar_paths.account_db_path(&account.storage_user_id);
        let pim_store = PimStore::new(contacts_db, calendar_db).with_context(|| {
            format!(
                "failed to initialize PIM store for account {}",
                account.account_id
            )
        })?;
        pim_stores.insert(account.account_id.clone(), Arc::new(pim_store));
    }

    let connector = super::imap_connector::ProtonImapConnector::new(
        api_base_url.clone(),
        auth_router.clone(),
        runtime_accounts.clone(),
    );
    let imap_config = Arc::new(imap::session::SessionConfig {
        connector,
        gluon_connector,
        mailbox_catalog,
        mailbox_mutation,
        mailbox_view,
        recent_tracker: imap::session::RecentTracker::new(),
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
        match config.dav_tls_mode {
            DavTlsMode::None => dav::server::clear_runtime_tls_config(),
            DavTlsMode::StartTls => dav::server::install_runtime_tls_config_from_dir(&cert_dir)?,
        }
    } else {
        imap::server::clear_runtime_tls_config();
        smtp::server::clear_runtime_tls_config();
        dav::server::clear_runtime_tls_config();
    }

    Ok(PreparedMailRuntime {
        active_sessions,
        imap_config,
        smtp_config,
        runtime_accounts,
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_mailbox_view,
        pim_stores,
        checkpoint_store: Arc::new(super::events::VaultCheckpointStore::new(
            settings_dir.to_path_buf(),
        )),
        poll_interval: config.event_poll_interval,
        pim_reconcile_tick_interval: config.pim_reconcile_tick_interval,
        pim_contacts_reconcile_interval: config.pim_contacts_reconcile_interval,
        pim_calendar_reconcile_interval: config.pim_calendar_reconcile_interval,
        pim_calendar_horizon_reconcile_interval: config.pim_calendar_horizon_reconcile_interval,
        settings_dir: settings_dir.to_path_buf(),
    })
}

fn build_mailbox_view(
    gluon_bootstrap: &vault::GluonStoreBootstrap,
    gluon_root: &std::path::Path,
) -> anyhow::Result<Arc<dyn imap::mailbox_view::GluonMailboxView>> {
    let store = build_gluon_mail_compatible_store(gluon_bootstrap, gluon_root, true)?;
    Ok(imap::gluon_mailbox_view::GluonMailMailboxView::new(
        Arc::new(store),
    ))
}

fn build_mailbox_mutation(
    gluon_bootstrap: &vault::GluonStoreBootstrap,
    gluon_root: &std::path::Path,
) -> anyhow::Result<Arc<dyn imap::mailbox_mutation::GluonMailboxMutation>> {
    let store = build_gluon_mail_compatible_store(gluon_bootstrap, gluon_root, false)?;
    Ok(imap::gluon_mailbox_mutation::GluonMailMailboxMutation::new(
        Arc::new(store),
    ))
}

fn build_event_mailbox_view(
    gluon_bootstrap: &vault::GluonStoreBootstrap,
    gluon_root: &std::path::Path,
) -> anyhow::Result<Arc<dyn imap::mailbox_view::GluonMailboxView>> {
    let store = build_gluon_mail_compatible_store(gluon_bootstrap, gluon_root, true)?;
    Ok(imap::gluon_mailbox_view::GluonMailMailboxView::new(
        Arc::new(store),
    ))
}

fn build_gluon_connector(
    gluon_bootstrap: &vault::GluonStoreBootstrap,
    gluon_root: &std::path::Path,
) -> anyhow::Result<Arc<dyn imap::gluon_connector::GluonImapConnector>> {
    let store = build_gluon_mail_compatible_store(gluon_bootstrap, gluon_root, false)?;
    Ok(imap::gluon_connector::GluonMailConnector::new(Arc::new(
        store,
    )))
}

/// Ensures gluon directories exist and resets sync state for any account
/// whose SQLite database is missing. This handles two scenarios:
///
/// - The entire `gluon/` directory was deleted: directories are recreated so
///   read-only store opens don't fail with `MissingCacheRoot`.
/// - Only `gluon/backend` was deleted: the DB files are gone but sync state
///   (stored outside gluon/ in settings_dir and vault) still reports "synced".
///   Clearing the sync state file forces a full re-sync on next event loop run.
fn ensure_gluon_dirs_and_sync_state(
    gluon_bootstrap: &vault::GluonStoreBootstrap,
    gluon_root: &std::path::Path,
    settings_dir: &std::path::Path,
) {
    let layout = gluon_rs_mail::CacheLayout::new(gluon_root);
    if let Err(err) = layout.ensure_base_dirs() {
        tracing::error!(
            gluon_dir = %gluon_root.display(),
            error = %err,
            "failed to create gluon base directories"
        );
        return;
    }

    for account in &gluon_bootstrap.accounts {
        let account_paths = match layout.account_paths(&account.storage_user_id) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(
                    account_id = %account.account_id,
                    error = %err,
                    "failed to resolve gluon account paths"
                );
                continue;
            }
        };

        // Create per-account blob store directory.
        if let Err(err) = std::fs::create_dir_all(account_paths.store_dir()) {
            tracing::warn!(
                account_id = %account.account_id,
                error = %err,
                "failed to create account store directory"
            );
        }

        // If the SQLite DB is missing, the sync state is stale -- clear it
        // so the event worker performs a full re-sync.
        if !account_paths.primary_db_path().exists() {
            let user_id = vault::get_user_id_by_account_id(settings_dir, &account.account_id);
            if let Ok(uid) = user_id {
                if let Err(err) = super::sync_state::clear_sync_state(settings_dir, &uid) {
                    tracing::warn!(
                        account_id = %account.account_id,
                        error = %err,
                        "failed to clear stale sync state"
                    );
                } else {
                    tracing::info!(
                        account_id = %account.account_id,
                        db_path = %account_paths.primary_db_path().display(),
                        "gluon database missing, cleared sync state to trigger full re-sync"
                    );
                }
            }
        }
    }
}

pub(crate) fn build_gluon_mail_compatible_store(
    gluon_bootstrap: &vault::GluonStoreBootstrap,
    gluon_root: &std::path::Path,
    read_only: bool,
) -> anyhow::Result<gluon_rs_mail::CompatibleStore> {
    let accounts = gluon_bootstrap
        .accounts
        .iter()
        .map(|account| {
            let key = gluon_rs_mail::GluonKey::try_from_slice(&account.gluon_key)
                .with_context(|| format!("invalid Gluon key for account {}", account.account_id))?;
            Ok(gluon_rs_mail::AccountBootstrap::new(
                account.account_id.clone(),
                account.storage_user_id.clone(),
                key,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let bootstrap = gluon_rs_mail::StoreBootstrap::new(
        gluon_rs_mail::CacheLayout::new(gluon_root),
        gluon_rs_mail::CompatibilityTarget::default(),
        accounts,
    );
    if read_only {
        gluon_rs_mail::CompatibleStore::open_read_only(bootstrap)
    } else {
        gluon_rs_mail::CompatibleStore::open(bootstrap)
    }
    .context("open gluon-rs-mail compatible store")
}

#[allow(clippy::too_many_arguments)]
async fn run_runtime(
    prepared: PreparedMailRuntime,
    config: MailRuntimeConfig,
    transition: MailRuntimeTransition,
    imap_listener: TcpListener,
    smtp_listener: TcpListener,
    imap_implicit_tls_listener: Option<TcpListener>,
    smtp_implicit_tls_listener: Option<TcpListener>,
    dav_listener: Option<TcpListener>,
    shutdown_rx: oneshot::Receiver<()>,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
    external_sync_callback: Option<super::events::SyncProgressCallback>,
    pim_reconcile_metrics: Arc<std::sync::RwLock<PimReconcileMetricsSnapshot>>,
) -> anyhow::Result<()> {
    let PreparedMailRuntime {
        imap_config,
        smtp_config,
        runtime_accounts,
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_mailbox_view,
        pim_stores,
        checkpoint_store,
        poll_interval,
        pim_reconcile_tick_interval,
        pim_contacts_reconcile_interval,
        pim_calendar_reconcile_interval,
        pim_calendar_horizon_reconcile_interval,
        settings_dir,
        ..
    } = prepared;

    let account_lookup: HashMap<String, String> = runtime_snapshot
        .iter()
        .map(|info| (info.account_id.0.clone(), info.email.clone()))
        .collect();
    let notify_for_callback = notify_tx.clone();
    let sync_progress_callback: super::events::SyncProgressCallback = Arc::new(move |event| {
        match &event {
            super::events::SyncProgressUpdate::Started { user_id } => {
                let label = account_lookup
                    .get(user_id)
                    .cloned()
                    .unwrap_or_else(|| user_id.clone());
                tracing::info!(user_id = %user_id, "account sync started");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let _ = tx.send(format!("[event] sync started: {label}"));
                }
            }
            super::events::SyncProgressUpdate::Progress {
                user_id, progress, ..
            } => {
                tracing::debug!(user_id = %user_id, progress, "account sync progress");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let label = account_lookup
                        .get(user_id)
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
                    .get(user_id)
                    .cloned()
                    .unwrap_or_else(|| user_id.clone());
                tracing::info!(user_id = %user_id, "account sync finished");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let _ = tx.send(format!("[event] sync finished: {label}"));
                }
            }
        }
        if let Some(ref cb) = external_sync_callback {
            cb(event);
        }
    });

    let calendar_notifier: SharedCalendarChangeNotifier = Arc::new(CalendarChangeNotifier::new());

    let pim_stores_for_reconcile = pim_stores.clone();
    let dav_pim_stores = pim_stores.clone();
    let dav_auth_router = auth_router.clone();
    let event_workers = {
        let notifier = calendar_notifier.clone();
        super::events::start_event_worker_group_with_sync_progress_and_pim_and_connector(
            runtime_accounts.clone(),
            runtime_snapshot,
            api_base_url,
            auth_router,
            event_mailbox_view,
            imap_config.gluon_connector.clone(),
            checkpoint_store,
            pim_stores,
            Some(sync_progress_callback),
            poll_interval,
            Some(settings_dir),
            Some(notifier),
        )
    };

    let pim_reconcile_task = tokio::spawn(run_pim_reconcile_periodically(
        runtime_accounts.clone(),
        pim_stores_for_reconcile,
        pim_reconcile_tick_interval,
        pim_contacts_reconcile_interval,
        pim_calendar_reconcile_interval,
        pim_calendar_horizon_reconcile_interval,
        config.dav_enable,
        notify_tx.clone(),
        pim_reconcile_metrics,
        if config.dav_enable {
            Some(calendar_notifier.clone())
        } else {
            None
        },
    ));
    let health_task = tokio::spawn(report_runtime_health_periodically(
        runtime_accounts.clone(),
        notify_tx.clone(),
    ));
    let imap_config_for_starttls = imap_config.clone();
    let smtp_config_for_starttls = smtp_config.clone();
    let mut imap_task = tokio::spawn(async move {
        imap::server::run_server_with_listener(imap_listener, imap_config_for_starttls).await
    });
    let mut smtp_task = tokio::spawn(async move {
        smtp::server::run_server_with_listener(smtp_listener, smtp_config_for_starttls).await
    });
    let mut imap_implicit_tls_task = imap_implicit_tls_listener.map(|listener| {
        let imap_config = imap_config.clone();
        tokio::spawn(async move {
            imap::server::run_server_with_listener_implicit_tls(listener, imap_config).await
        })
    });
    let mut smtp_implicit_tls_task = smtp_implicit_tls_listener.map(|listener| {
        let smtp_config = smtp_config.clone();
        tokio::spawn(async move {
            smtp::server::run_server_with_listener_implicit_tls(listener, smtp_config).await
        })
    });
    let push_subscription_store = dav::push::PushSubscriptionStore::new();
    let vapid_keys = Arc::new(dav::push_crypto::VapidKeyPair::generate());

    let mut dav_task = dav_listener.map(|listener| {
        let config = dav::server::DavServerConfig {
            auth_router: dav_auth_router,
            pim_stores: dav_pim_stores,
            runtime_accounts: Some(runtime_accounts.clone()),
            push_subscriptions: Some(push_subscription_store.clone()),
            vapid_keys: Some(vapid_keys.clone()),
        };
        tokio::spawn(async move {
            dav::server::run_server_with_listener_and_config(listener, config).await
        })
    });

    // WebDAV-Push notification sender task
    let push_sender_task = if config.dav_enable {
        let push_rx = calendar_notifier.subscribe();
        let push_store = push_subscription_store.clone();
        let push_vapid = vapid_keys.clone();
        let push_http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        Some(tokio::spawn(dav::push_send::run_push_sender(
            push_rx, push_store, push_vapid, push_http,
        )))
    } else {
        None
    };

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
        result = async { imap_implicit_tls_task.as_mut().expect("imap implicit tls task missing despite guard").await }, if imap_implicit_tls_task.is_some() => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("IMAP implicit TLS server task failed")),
            }
        }
        result = async { smtp_implicit_tls_task.as_mut().expect("smtp implicit tls task missing despite guard").await }, if smtp_implicit_tls_task.is_some() => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("SMTP implicit TLS server task failed")),
            }
        }
        result = async { dav_task.as_mut().expect("dav task missing despite guard").await }, if dav_task.is_some() => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("DAV server task failed")),
            }
        }
    };

    log_protocol_stopping(MailProtocol::Imap, &config, transition);
    log_protocol_stopping(MailProtocol::Smtp, &config, transition);
    if config.dav_enable {
        log_protocol_stopping(MailProtocol::Dav, &config, transition);
    }
    log_implicit_tls_stopping(&config, transition);

    if !imap_task.is_finished() {
        imap_task.abort();
    }
    if !smtp_task.is_finished() {
        smtp_task.abort();
    }
    if let Some(task) = dav_task.as_mut() {
        if !task.is_finished() {
            task.abort();
        }
    }
    if let Some(task) = imap_implicit_tls_task.as_mut() {
        if !task.is_finished() {
            task.abort();
        }
    }
    if let Some(task) = smtp_implicit_tls_task.as_mut() {
        if !task.is_finished() {
            task.abort();
        }
    }
    let _ = imap_task.await;
    let _ = smtp_task.await;
    if let Some(task) = imap_implicit_tls_task {
        let _ = task.await;
    }
    if let Some(task) = smtp_implicit_tls_task {
        let _ = task.await;
    }
    if let Some(task) = dav_task {
        let _ = task.await;
    }

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
    if config.use_ssl_for_imap && !config.disable_tls {
        tracing::info!(
            port = DEFAULT_IMAP_IMPLICIT_TLS_PORT,
            transition = transition.as_str(),
            "IMAP implicit TLS listener closed"
        );
    }
    if config.use_ssl_for_smtp && !config.disable_tls {
        tracing::info!(
            port = DEFAULT_SMTP_IMPLICIT_TLS_PORT,
            transition = transition.as_str(),
            "SMTP implicit TLS listener closed"
        );
    }
    if config.dav_enable {
        tracing::info!(
            port = config.dav_port,
            tls_mode = config.dav_tls_mode.as_str(),
            transition = transition.as_str(),
            "DAV server listener closed"
        );
    }

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
        (MailProtocol::Dav, MailRuntimeTransition::SettingsChange) => {
            tracing::info!(
                service = "server-manager",
                port = config.dav_port,
                tls_mode = config.dav_tls_mode.as_str(),
                transition = transition.as_str(),
                msg = "Restarting DAV server",
                "Restarting DAV server"
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
        (MailProtocol::Dav, _) => {
            tracing::info!(
                service = "server-manager",
                port = config.dav_port,
                tls_mode = config.dav_tls_mode.as_str(),
                transition = transition.as_str(),
                msg = "Starting DAV server",
                "Starting DAV server"
            );
        }
    }
}

fn log_implicit_tls_start(config: &MailRuntimeConfig, transition: MailRuntimeTransition) {
    if config.disable_tls {
        return;
    }
    if config.use_ssl_for_imap {
        tracing::info!(
            service = "server-manager",
            port = DEFAULT_IMAP_IMPLICIT_TLS_PORT,
            transition = transition.as_str(),
            msg = "Starting IMAP implicit TLS server",
            "Starting IMAP implicit TLS server"
        );
    }
    if config.use_ssl_for_smtp {
        tracing::info!(
            service = "server-manager",
            port = DEFAULT_SMTP_IMPLICIT_TLS_PORT,
            transition = transition.as_str(),
            msg = "Starting SMTP implicit TLS server",
            "Starting SMTP implicit TLS server"
        );
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
        MailProtocol::Dav => {
            tracing::info!(
                service = "server-manager",
                port = config.dav_port,
                tls_mode = config.dav_tls_mode.as_str(),
                transition = transition.as_str(),
                msg = "Stopping DAV server",
                "Stopping DAV server"
            );
        }
    }
}

fn log_implicit_tls_stopping(config: &MailRuntimeConfig, transition: MailRuntimeTransition) {
    if config.disable_tls {
        return;
    }
    if config.use_ssl_for_imap {
        tracing::info!(
            service = "server-manager",
            port = DEFAULT_IMAP_IMPLICIT_TLS_PORT,
            transition = transition.as_str(),
            msg = "Stopping IMAP implicit TLS server",
            "Stopping IMAP implicit TLS server"
        );
    }
    if config.use_ssl_for_smtp {
        tracing::info!(
            service = "server-manager",
            port = DEFAULT_SMTP_IMPLICIT_TLS_PORT,
            transition = transition.as_str(),
            msg = "Stopping SMTP implicit TLS server",
            "Stopping SMTP implicit TLS server"
        );
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
        MailProtocol::Dav => {
            tracing::warn!(
                port = config.dav_port,
                tls_mode = config.dav_tls_mode.as_str(),
                error = %error,
                "Failed to start DAV server on bridge start"
            );
        }
    }
}

fn generate_bridge_password() -> String {
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    BASE64_URL_NO_PAD.encode(token)
}

#[cfg(test)]
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

#[allow(clippy::too_many_arguments)]
async fn run_pim_reconcile_periodically(
    runtime_accounts: Arc<super::accounts::RuntimeAccountRegistry>,
    pim_stores: HashMap<String, Arc<PimStore>>,
    reconcile_tick_interval: Duration,
    contacts_reconcile_interval: Duration,
    calendar_reconcile_interval: Duration,
    calendar_horizon_reconcile_interval: Duration,
    eager_calendar_warmup: bool,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
    metrics_snapshot: Arc<std::sync::RwLock<PimReconcileMetricsSnapshot>>,
    calendar_notifier: Option<SharedCalendarChangeNotifier>,
) {
    use tokio::time::{interval, MissedTickBehavior};

    let mut ticker = interval(reconcile_tick_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut first_sweep = true;

    loop {
        ticker.tick().await;
        let started_at = std::time::Instant::now();
        let mut metrics = PimReconcileSweepMetrics::default();
        let snapshot = runtime_accounts.snapshot().await;
        metrics.accounts_seen = snapshot.len();
        for account in snapshot {
            let Some(store) = pim_stores.get(&account.account_id.0) else {
                continue;
            };
            metrics.accounts_with_store += 1;

            let raw_contacts_due = match is_pim_contacts_due(store, contacts_reconcile_interval) {
                Ok(due) => due,
                Err(err) => {
                    tracing::warn!(
                        account_id = %account.account_id.0,
                        email = %account.email,
                        error = %err,
                        "failed to evaluate contacts reconciliation schedule; forcing run"
                    );
                    true
                }
            };
            let raw_calendar_full_due =
                match is_pim_calendar_due(store, calendar_reconcile_interval) {
                    Ok(due) => due,
                    Err(err) => {
                        tracing::warn!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            error = %err,
                            "failed to evaluate calendar full reconciliation schedule; forcing run"
                        );
                        true
                    }
                };
            let raw_calendar_horizon_due =
                match is_pim_calendar_horizon_due(store, calendar_horizon_reconcile_interval) {
                    Ok(due) => due,
                    Err(err) => {
                        tracing::warn!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            error = %err,
                            "failed to evaluate calendar horizon schedule; forcing run"
                        );
                        true
                    }
                };
            let force_calendar_full_due =
                should_force_startup_calendar_warmup(first_sweep, eager_calendar_warmup, store);
            let raw_calendar_full_due = raw_calendar_full_due || force_calendar_full_due;
            if force_calendar_full_due {
                tracing::info!(
                    account_id = %account.account_id.0,
                    email = %account.email,
                    "forcing startup calendar warmup because DAV is enabled and no prior sync"
                );
            }
            if !raw_contacts_due && !raw_calendar_full_due && !raw_calendar_horizon_due {
                continue;
            }

            let session = match runtime_accounts
                .with_valid_access_token(&account.account_id)
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    metrics.accounts_skipped_no_session += 1;
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
                    metrics.client_init_failures += 1;
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

            let mut contacts_due = raw_contacts_due;
            let mut calendar_full_due = raw_calendar_full_due;
            let mut calendar_horizon_due = raw_calendar_horizon_due;
            match api::auth::get_granted_scopes(&client).await {
                Ok(granted_scopes) => {
                    let contacts_enabled = api::auth::has_scope(&granted_scopes, "contacts");
                    let calendar_enabled = api::auth::has_scope(&granted_scopes, "calendar");

                    if contacts_due && !contacts_enabled {
                        contacts_due = false;
                        tracing::debug!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            "skipping periodic contacts reconciliation due to missing contacts scope"
                        );
                    }
                    if calendar_full_due && !calendar_enabled {
                        calendar_full_due = false;
                        tracing::debug!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            "skipping periodic calendar reconciliation due to missing calendar scope"
                        );
                    }
                    if calendar_horizon_due && !calendar_enabled {
                        calendar_horizon_due = false;
                        tracing::debug!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            "skipping periodic calendar horizon refresh due to missing calendar scope"
                        );
                    }
                }
                Err(err) => {
                    contacts_due = false;
                    calendar_full_due = false;
                    calendar_horizon_due = false;
                    tracing::warn!(
                        account_id = %account.account_id.0,
                        email = %account.email,
                        error = %err,
                        "failed to fetch granted auth scopes; skipping periodic contacts/calendar reconciliation"
                    );
                }
            }

            if contacts_due {
                metrics.contacts_runs_due += 1;
            }
            if calendar_full_due {
                metrics.calendar_full_runs_due += 1;
            }
            if calendar_horizon_due {
                metrics.calendar_horizon_runs_due += 1;
            }
            if !contacts_due && !calendar_full_due && !calendar_horizon_due {
                continue;
            }

            if contacts_due {
                match sync_contacts::bootstrap_contacts(&client, store, 0).await {
                    Ok(summary) => {
                        metrics.contacts_success += 1;
                        metrics.contacts_rows_upserted += summary.contacts_upserted;
                        metrics.contacts_rows_soft_deleted += summary.contacts_soft_deleted;
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
                        metrics.contacts_failures += 1;
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

            if calendar_full_due {
                match sync_calendar::bootstrap_calendars(
                    &client,
                    store,
                    &api::calendar::CalendarEventsQuery::default(),
                )
                .await
                {
                    Ok(summary) => {
                        metrics.calendar_full_success += 1;
                        metrics.calendar_rows_upserted += summary.events_upserted;
                        metrics.calendar_rows_soft_deleted +=
                            summary.calendars_soft_deleted + summary.events_soft_deleted;
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
                        if summary.events_upserted > 0 || summary.events_soft_deleted > 0 {
                            if let Some(ref notifier) = calendar_notifier {
                                notifier.notify_account(&account.account_id.0);
                            }
                        }
                    }
                    Err(err) => {
                        metrics.calendar_full_failures += 1;
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
            } else if calendar_horizon_due {
                match sync_calendar::refresh_calendar_event_horizon(
                    &client,
                    store,
                    &api::calendar::CalendarEventsQuery::default(),
                )
                .await
                {
                    Ok(summary) => {
                        metrics.calendar_horizon_success += 1;
                        metrics.calendar_rows_upserted += summary.events_upserted;
                        metrics.calendar_rows_soft_deleted += summary.events_soft_deleted;
                        tracing::info!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            calendars_scanned = summary.calendars_scanned,
                            events_upserted = summary.events_upserted,
                            "periodic calendar event horizon refresh completed"
                        );
                        if summary.events_upserted > 0 || summary.events_soft_deleted > 0 {
                            if let Some(ref notifier) = calendar_notifier {
                                notifier.notify_account(&account.account_id.0);
                            }
                        }
                    }
                    Err(err) => {
                        metrics.calendar_horizon_failures += 1;
                        tracing::warn!(
                            account_id = %account.account_id.0,
                            email = %account.email,
                            error = %err,
                            "periodic calendar event horizon refresh failed"
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
        tracing::info!(
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            accounts_seen = metrics.accounts_seen,
            accounts_with_store = metrics.accounts_with_store,
            accounts_skipped_no_session = metrics.accounts_skipped_no_session,
            client_init_failures = metrics.client_init_failures,
            contacts_runs_due = metrics.contacts_runs_due,
            contacts_success = metrics.contacts_success,
            contacts_failures = metrics.contacts_failures,
            calendar_full_runs_due = metrics.calendar_full_runs_due,
            calendar_full_success = metrics.calendar_full_success,
            calendar_full_failures = metrics.calendar_full_failures,
            calendar_horizon_runs_due = metrics.calendar_horizon_runs_due,
            calendar_horizon_success = metrics.calendar_horizon_success,
            calendar_horizon_failures = metrics.calendar_horizon_failures,
            contacts_rows_upserted = metrics.contacts_rows_upserted,
            contacts_rows_soft_deleted = metrics.contacts_rows_soft_deleted,
            calendar_rows_upserted = metrics.calendar_rows_upserted,
            calendar_rows_soft_deleted = metrics.calendar_rows_soft_deleted,
            "pim reconciliation sweep metrics"
        );
        if let Ok(mut snapshot) = metrics_snapshot.write() {
            let elapsed_ms = started_at.elapsed().as_millis() as u64;
            snapshot.sweeps_total = snapshot.sweeps_total.saturating_add(1);
            snapshot.last_sweep_elapsed_ms = elapsed_ms;
            snapshot.last_sweep_completed_at_ms = unix_now_millis() as i64;
            snapshot.accounts_seen_total = snapshot
                .accounts_seen_total
                .saturating_add(metrics.accounts_seen as u64);
            snapshot.accounts_with_store_total = snapshot
                .accounts_with_store_total
                .saturating_add(metrics.accounts_with_store as u64);
            snapshot.accounts_skipped_no_session_total = snapshot
                .accounts_skipped_no_session_total
                .saturating_add(metrics.accounts_skipped_no_session as u64);
            snapshot.client_init_failures_total = snapshot
                .client_init_failures_total
                .saturating_add(metrics.client_init_failures as u64);
            snapshot.contacts_runs_due_total = snapshot
                .contacts_runs_due_total
                .saturating_add(metrics.contacts_runs_due as u64);
            snapshot.contacts_success_total = snapshot
                .contacts_success_total
                .saturating_add(metrics.contacts_success as u64);
            snapshot.contacts_failures_total = snapshot
                .contacts_failures_total
                .saturating_add(metrics.contacts_failures as u64);
            snapshot.calendar_full_runs_due_total = snapshot
                .calendar_full_runs_due_total
                .saturating_add(metrics.calendar_full_runs_due as u64);
            snapshot.calendar_full_success_total = snapshot
                .calendar_full_success_total
                .saturating_add(metrics.calendar_full_success as u64);
            snapshot.calendar_full_failures_total = snapshot
                .calendar_full_failures_total
                .saturating_add(metrics.calendar_full_failures as u64);
            snapshot.calendar_horizon_runs_due_total = snapshot
                .calendar_horizon_runs_due_total
                .saturating_add(metrics.calendar_horizon_runs_due as u64);
            snapshot.calendar_horizon_success_total = snapshot
                .calendar_horizon_success_total
                .saturating_add(metrics.calendar_horizon_success as u64);
            snapshot.calendar_horizon_failures_total = snapshot
                .calendar_horizon_failures_total
                .saturating_add(metrics.calendar_horizon_failures as u64);
            snapshot.contacts_rows_upserted_total = snapshot
                .contacts_rows_upserted_total
                .saturating_add(metrics.contacts_rows_upserted as u64);
            snapshot.contacts_rows_soft_deleted_total = snapshot
                .contacts_rows_soft_deleted_total
                .saturating_add(metrics.contacts_rows_soft_deleted as u64);
            snapshot.calendar_rows_upserted_total = snapshot
                .calendar_rows_upserted_total
                .saturating_add(metrics.calendar_rows_upserted as u64);
            snapshot.calendar_rows_soft_deleted_total = snapshot
                .calendar_rows_soft_deleted_total
                .saturating_add(metrics.calendar_rows_soft_deleted as u64);
        }
        first_sweep = false;
    }
}

fn should_force_startup_calendar_warmup(
    first_sweep: bool,
    eager_calendar_warmup: bool,
    store: &PimStore,
) -> bool {
    if !first_sweep || !eager_calendar_warmup {
        return false;
    }
    !store.calendar().is_synced().unwrap_or(false)
}

#[derive(Debug, Default)]
struct PimReconcileSweepMetrics {
    accounts_seen: usize,
    accounts_with_store: usize,
    accounts_skipped_no_session: usize,
    client_init_failures: usize,
    contacts_runs_due: usize,
    contacts_success: usize,
    contacts_failures: usize,
    calendar_full_runs_due: usize,
    calendar_full_success: usize,
    calendar_full_failures: usize,
    calendar_horizon_runs_due: usize,
    calendar_horizon_success: usize,
    calendar_horizon_failures: usize,
    contacts_rows_upserted: usize,
    contacts_rows_soft_deleted: usize,
    calendar_rows_upserted: usize,
    calendar_rows_soft_deleted: usize,
}

fn is_pim_contacts_due(store: &PimStore, interval: Duration) -> anyhow::Result<bool> {
    is_sync_scope_due(store, "contacts.last_full_sync_ms", interval)
}

fn is_pim_calendar_due(store: &PimStore, interval: Duration) -> anyhow::Result<bool> {
    is_sync_scope_due(store, "calendar.last_full_sync_ms", interval)
}

fn is_pim_calendar_horizon_due(store: &PimStore, interval: Duration) -> anyhow::Result<bool> {
    is_sync_scope_due(store, "calendar.last_horizon_sync_ms", interval)
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
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        build_gluon_mail_compatible_store, handle_startup_refresh_failure, is_sync_scope_due,
        Session,
    };
    use crate::api::error::ApiError;
    use crate::api::types::ApiMode;
    use crate::bridge::accounts::{AccountHealth, RuntimeAccountRegistry};
    use crate::bridge::types::AccountId;
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

    fn session_with_access_token(uid: &str, email: &str, access_token: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: access_token.to_string(),
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
        let contacts_db = tmp.path().join("contacts.db");
        let calendar_db = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        PimStore::new(contacts_db, calendar_db).unwrap()
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

    #[test]
    fn build_gluon_mail_compatible_store_preserves_bootstrap_bindings() {
        let tmp = tempfile::tempdir().unwrap();
        let gluon_root = tmp.path().join("gluon");
        std::fs::create_dir_all(&gluon_root).unwrap();

        let bootstrap = crate::vault::GluonStoreBootstrap {
            gluon_dir: gluon_root.display().to_string(),
            accounts: vec![crate::vault::GluonAccountBootstrap {
                account_id: "account-1".to_string(),
                storage_user_id: "user-1".to_string(),
                gluon_key: [9u8; 32],
                gluon_ids: HashMap::new(),
            }],
        };

        let store = build_gluon_mail_compatible_store(&bootstrap, &gluon_root, true).unwrap();
        assert_eq!(store.bootstrap().accounts.len(), 1);
        assert_eq!(store.bootstrap().accounts[0].account_id, "account-1");
        assert_eq!(store.bootstrap().accounts[0].storage_user_id, "user-1");
    }

    #[tokio::test]
    async fn periodic_pim_reconcile_skips_when_not_due() {
        let account_id = AccountId("uid-1".to_string());
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![
            session_with_access_token("uid-1", "alice@proton.me", "\x00invalid"),
        ]));
        let store = Arc::new(pim_store());
        let now_ms = super::unix_now_millis() as i64;
        store
            .set_sync_state_int("contacts.last_full_sync_ms", now_ms)
            .unwrap();
        store
            .set_sync_state_int("calendar.last_full_sync_ms", now_ms)
            .unwrap();
        store
            .set_sync_state_int("calendar.last_horizon_sync_ms", now_ms)
            .unwrap();

        let mut pim_stores = HashMap::new();
        pim_stores.insert(account_id.0.clone(), store);
        let metrics = Arc::new(std::sync::RwLock::new(
            super::PimReconcileMetricsSnapshot::default(),
        ));

        let task = tokio::spawn(super::run_pim_reconcile_periodically(
            runtime_accounts.clone(),
            pim_stores,
            Duration::from_millis(20),
            Duration::from_secs(24 * 60 * 60),
            Duration::from_secs(24 * 60 * 60),
            Duration::from_secs(12 * 60 * 60),
            false,
            None,
            metrics.clone(),
            None,
        ));

        tokio::time::sleep(Duration::from_millis(90)).await;
        task.abort();
        let _ = task.await;

        assert_eq!(
            runtime_accounts.get_health(&account_id).await,
            Some(AccountHealth::Healthy)
        );

        let snapshot = metrics.read().unwrap().clone();
        assert!(snapshot.sweeps_total >= 1);
        assert_eq!(snapshot.contacts_runs_due_total, 0);
        assert_eq!(snapshot.calendar_full_runs_due_total, 0);
        assert_eq!(snapshot.calendar_horizon_runs_due_total, 0);
        assert_eq!(snapshot.client_init_failures_total, 0);
    }

    #[tokio::test]
    async fn periodic_pim_reconcile_skips_when_scope_discovery_fails() {
        let account_id = AccountId("uid-1".to_string());
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![
            session_with_access_token("uid-1", "alice@proton.me", "\x00invalid"),
        ]));
        let store = Arc::new(pim_store());

        let mut pim_stores = HashMap::new();
        pim_stores.insert(account_id.0.clone(), store);
        let metrics = Arc::new(std::sync::RwLock::new(
            super::PimReconcileMetricsSnapshot::default(),
        ));

        let task = tokio::spawn(super::run_pim_reconcile_periodically(
            runtime_accounts.clone(),
            pim_stores,
            Duration::from_millis(20),
            Duration::from_secs(24 * 60 * 60),
            Duration::from_secs(24 * 60 * 60),
            Duration::from_secs(12 * 60 * 60),
            false,
            None,
            metrics.clone(),
            None,
        ));

        tokio::time::sleep(Duration::from_millis(90)).await;

        task.abort();
        let _ = task.await;

        assert_eq!(
            runtime_accounts.get_health(&account_id).await,
            Some(AccountHealth::Healthy)
        );

        let snapshot = metrics.read().unwrap().clone();
        assert_eq!(snapshot.client_init_failures_total, 0);
        assert_eq!(snapshot.contacts_runs_due_total, 0);
        assert_eq!(snapshot.calendar_full_runs_due_total, 0);
        assert_eq!(snapshot.calendar_horizon_runs_due_total, 0);
    }

    #[test]
    fn startup_calendar_warmup_is_forced_only_on_first_sweep_when_not_synced() {
        let store = pim_store();

        // First sweep + eager + not synced -> force
        assert!(super::should_force_startup_calendar_warmup(
            true, true, &store
        ));
        // Not first sweep -> no force
        assert!(!super::should_force_startup_calendar_warmup(
            false, true, &store
        ));
        // Not eager -> no force
        assert!(!super::should_force_startup_calendar_warmup(
            true, false, &store
        ));

        // Mark calendar as synced
        store
            .set_sync_state_int("calendar.last_full_sync_ms", 1700000000)
            .unwrap();

        // First sweep + eager + already synced -> no force
        assert!(!super::should_force_startup_calendar_warmup(
            true, true, &store
        ));
    }
}
