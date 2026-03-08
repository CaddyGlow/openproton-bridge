use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use anyhow::Context;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL_NO_PAD};
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc, watch, Mutex, Semaphore};
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::Stream;
use tonic::metadata::MetadataMap;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::api;
use crate::api::client::ProtonClient;
use crate::api::error::{any_human_verification_details, human_verification_details, ApiError};
use crate::api::types::{HumanVerificationDetails, Session};
use crate::bridge;
use crate::client_config;
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
const OPTIMIZE_CACHE_CONCURRENCY: usize = 4;
const OPTIMIZE_CACHE_CONCURRENCY_MAX: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptAction {
    InitiateShutdown,
    ForceExit,
}

fn next_interrupt_action(shutdown_requested: bool) -> InterruptAction {
    if shutdown_requested {
        InterruptAction::ForceExit
    } else {
        InterruptAction::InitiateShutdown
    }
}

#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("grpc");
}
pub mod client;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMailSettings {
    imap_port: i32,
    smtp_port: i32,
    use_ssl_for_imap: bool,
    use_ssl_for_smtp: bool,
    #[serde(default = "default_pim_reconcile_tick_secs")]
    pim_reconcile_tick_secs: i32,
    #[serde(default = "default_pim_contacts_reconcile_secs")]
    pim_contacts_reconcile_secs: i32,
    #[serde(default = "default_pim_calendar_reconcile_secs")]
    pim_calendar_reconcile_secs: i32,
    #[serde(default = "default_pim_calendar_horizon_reconcile_secs")]
    pim_calendar_horizon_reconcile_secs: i32,
}

impl Default for StoredMailSettings {
    fn default() -> Self {
        Self {
            imap_port: 1143,
            smtp_port: 1025,
            use_ssl_for_imap: false,
            use_ssl_for_smtp: false,
            pim_reconcile_tick_secs: default_pim_reconcile_tick_secs(),
            pim_contacts_reconcile_secs: default_pim_contacts_reconcile_secs(),
            pim_calendar_reconcile_secs: default_pim_calendar_reconcile_secs(),
            pim_calendar_horizon_reconcile_secs: default_pim_calendar_horizon_reconcile_secs(),
        }
    }
}

const fn default_pim_reconcile_tick_secs() -> i32 {
    600
}

const fn default_pim_contacts_reconcile_secs() -> i32 {
    86400
}

const fn default_pim_calendar_reconcile_secs() -> i32 {
    86400
}

const fn default_pim_calendar_horizon_reconcile_secs() -> i32 {
    43200
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
    api_mode: crate::api::types::ApiMode,
    required_scopes: Vec<String>,
    auth_granted_scopes: Vec<String>,
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
    session_access_tokens: Mutex<HashMap<String, String>>,
    shutdown_tx: watch::Sender<bool>,
    mail_settings: Mutex<StoredMailSettings>,
    runtime_supervisor: Arc<bridge::runtime_supervisor::RuntimeSupervisor>,
    mail_runtime_transition_lock: Mutex<()>,
    app_settings: Mutex<StoredAppSettings>,
    sync_workers_enabled: bool,
    sync_event_workers: Mutex<Option<bridge::events::EventWorkerGroup>>,
}

#[derive(Clone)]
struct BridgeService {
    state: Arc<GrpcState>,
}

#[derive(Debug, Default)]
struct SyncLifecycleState {
    generation: u64,
    active_users: HashMap<String, u64>,
}

static SYNC_LIFECYCLE_BY_SERVICE: OnceLock<StdMutex<HashMap<usize, SyncLifecycleState>>> =
    OnceLock::new();

fn sync_lifecycle_registry() -> &'static StdMutex<HashMap<usize, SyncLifecycleState>> {
    SYNC_LIFECYCLE_BY_SERVICE.get_or_init(|| StdMutex::new(HashMap::new()))
}

impl Drop for BridgeService {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) != 1 {
            return;
        }
        let key = Arc::as_ptr(&self.state) as usize;
        if let Ok(mut registry) = sync_lifecycle_registry().lock() {
            registry.remove(&key);
        }
    }
}

fn os_keyring_helpers() -> &'static [&'static str] {
    match std::env::consts::OS {
        "macos" => &[KEYCHAIN_HELPER_MACOS],
        "windows" => &[KEYCHAIN_HELPER_WINDOWS],
        "linux" => &[
            KEYCHAIN_HELPER_SECRET_SERVICE_DBUS,
            KEYCHAIN_HELPER_SECRET_SERVICE,
        ],
        _ => &[vault::KEYCHAIN_BACKEND_KEYRING],
    }
}

fn os_pass_helpers() -> &'static [&'static str] {
    match std::env::consts::OS {
        "linux" => &[KEYCHAIN_HELPER_PASS_APP],
        _ => &[],
    }
}

fn keychain_helper_to_backend(helper: &str) -> Option<&'static str> {
    match helper.trim() {
        vault::KEYCHAIN_BACKEND_FILE => Some(vault::KEYCHAIN_BACKEND_FILE),
        vault::KEYCHAIN_BACKEND_KEYRING
        | KEYCHAIN_HELPER_MACOS
        | KEYCHAIN_HELPER_WINDOWS
        | KEYCHAIN_HELPER_SECRET_SERVICE_DBUS
        | KEYCHAIN_HELPER_SECRET_SERVICE => Some(vault::KEYCHAIN_BACKEND_KEYRING),
        KEYCHAIN_HELPER_PASS_APP => Some(vault::KEYCHAIN_BACKEND_PASS_APP),
        _ => None,
    }
}

fn available_keychain_helpers_with_backends(available_backends: &[String]) -> Vec<String> {
    let mut helpers = Vec::new();
    let keyring_available = available_backends
        .iter()
        .any(|backend| backend == vault::KEYCHAIN_BACKEND_KEYRING);
    let pass_available = available_backends
        .iter()
        .any(|backend| backend == vault::KEYCHAIN_BACKEND_PASS_APP);

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

    if pass_available {
        for helper in os_pass_helpers() {
            if !helpers.iter().any(|candidate| candidate == helper) {
                helpers.push((*helper).to_string());
            }
        }
        if !helpers
            .iter()
            .any(|candidate| candidate == vault::KEYCHAIN_BACKEND_PASS_APP)
        {
            helpers.push(vault::KEYCHAIN_BACKEND_PASS_APP.to_string());
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

include!("service.rs");
include!("rpc.rs");
include!("runtime.rs");

#[allow(dead_code)]
async fn maybe_start_grpc_sync_workers(
    runtime_paths: &RuntimePaths,
    service: &BridgeService,
    worker_generation: u64,
    _active_disk_cache_path: &Path,
) -> anyhow::Result<Option<bridge::events::EventWorkerGroup>> {
    let available_backends = vault::discover_available_keychains();
    let configured_helper = match vault::get_keychain_helper(runtime_paths.settings_dir()) {
        Ok(helper) => helper,
        Err(err) => {
            debug!(error = %err, "failed to load persisted keychain helper");
            None
        }
    };
    debug!(
        backends = ?available_backends,
        helper = configured_helper.as_deref().unwrap_or("<unset>"),
        "grpc sync worker keychain context"
    );

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
    repair_vault_user_ids_for_compatibility(runtime_paths.settings_dir(), &runtime_accounts).await;

    let runtime_snapshot = runtime_accounts.snapshot().await;
    if runtime_snapshot.is_empty() {
        return Ok(None);
    }

    let bootstrap_account_ids = runtime_snapshot
        .iter()
        .map(|account| account.account_id.0.clone())
        .collect::<Vec<_>>();
    let gluon_bootstrap =
        vault::load_gluon_store_bootstrap(runtime_paths.settings_dir(), &bootstrap_account_ids)
            .context("failed to resolve gluon vault bindings for grpc store bootstrap")?;
    let gluon_paths = runtime_paths.gluon_paths(Some(gluon_bootstrap.gluon_dir.as_str()));
    debug!(
        gluon_dir = %gluon_paths.root().display(),
        accounts = gluon_bootstrap.accounts.len(),
        "resolved grpc gluon store bootstrap context"
    );
    for account in &gluon_bootstrap.accounts {
        debug!(
            account_id = %account.account_id,
            storage_user_id = %account.storage_user_id,
            store_path = %gluon_paths.account_store_dir(&account.storage_user_id).display(),
            db_path = %gluon_paths.account_db_path(&account.storage_user_id).display(),
            "resolved grpc account-scoped gluon layout"
        );
    }

    let account_storage_ids = gluon_bootstrap
        .accounts
        .iter()
        .map(|account| (account.account_id.clone(), account.storage_user_id.clone()))
        .collect();
    let store: Arc<dyn crate::imap::store::MessageStore> =
        crate::imap::store::new_runtime_message_store(
            gluon_paths.root().to_path_buf(),
            account_storage_ids,
        )?;
    let checkpoint_store: bridge::events::SharedCheckpointStore = Arc::new(
        bridge::events::VaultCheckpointStore::new(runtime_paths.settings_dir().to_path_buf()),
    );

    let callback_service = service.clone();
    let sync_progress_callback: bridge::events::SyncProgressCallback =
        Arc::new(move |event| match event {
            bridge::events::SyncProgressUpdate::Started { user_id } => {
                callback_service.emit_sync_started_for_generation(&user_id, worker_generation);
            }
            bridge::events::SyncProgressUpdate::Progress {
                user_id,
                progress,
                elapsed_ms,
                remaining_ms,
            } => {
                callback_service.emit_sync_progress_for_generation(
                    &user_id,
                    progress,
                    elapsed_ms,
                    remaining_ms,
                    worker_generation,
                );
            }
            bridge::events::SyncProgressUpdate::Finished { user_id } => {
                callback_service.emit_sync_finished_for_generation(&user_id, worker_generation);
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

#[allow(dead_code)]
async fn repair_vault_user_ids_for_compatibility(
    settings_dir: &Path,
    runtime_accounts: &Arc<bridge::accounts::RuntimeAccountRegistry>,
) {
    let snapshot = runtime_accounts.snapshot().await;
    for account in snapshot {
        let session = match runtime_accounts
            .with_valid_access_token(&account.account_id)
            .await
        {
            Ok(session) => session,
            Err(err) => {
                debug!(
                    account_id = %account.account_id.0,
                    error = %err,
                    "skipping canonical user id repair: account token unavailable"
                );
                continue;
            }
        };

        if session.uid.trim().is_empty() || session.access_token.trim().is_empty() {
            continue;
        }

        let client = match ProtonClient::authenticated_with_mode(
            session.api_mode.base_url(),
            session.api_mode,
            &session.uid,
            &session.access_token,
        ) {
            Ok(client) => client,
            Err(err) => {
                debug!(
                    account_id = %account.account_id.0,
                    error = %err,
                    "skipping canonical user id repair: failed to create authenticated client"
                );
                continue;
            }
        };

        let user_resp = match api::users::get_user(&client).await {
            Ok(user_resp) => user_resp,
            Err(err) => {
                debug!(
                    account_id = %account.account_id.0,
                    error = %err,
                    "skipping canonical user id repair: failed to fetch user profile"
                );
                continue;
            }
        };

        if let Err(err) = vault::save_session_with_user_id(
            &session,
            Some(user_resp.user.id.as_str()),
            settings_dir,
        ) {
            warn!(
                account_id = %account.account_id.0,
                error = %err,
                "failed to persist canonical user id during grpc startup repair"
            );
        }
    }
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
        vault::VaultError::MissingGluonKey(account_id) => {
            Status::failed_precondition(format!("gluon key is missing for account: {account_id}"))
        }
        vault::VaultError::InvalidGluonKeyLength { account_id, length } => {
            Status::failed_precondition(format!(
                "invalid gluon key length {length} for account {account_id}; expected 32 bytes"
            ))
        }
        vault::VaultError::InvalidGluonIdBinding { account_id, reason } => {
            Status::failed_precondition(format!(
                "invalid gluon id binding for account {account_id}: {reason}"
            ))
        }
        vault::VaultError::MismatchedGluonIdBinding {
            address_id,
            expected,
            actual,
        } => Status::failed_precondition(format!(
            "mismatched gluon id binding for address {address_id}: expected {expected}, found {actual}"
        )),
        other => Status::internal(format!("vault error: {other}")),
    }
}

#[derive(Debug, Clone, Default)]
struct UserApiData {
    name: String,
    display_name: String,
    used_bytes: i64,
    total_bytes: i64,
    max_upload: i64,
    credit: i64,
    currency: String,
    calendar_used_bytes: i64,
    contact_used_bytes: i64,
    drive_used_bytes: i64,
    mail_used_bytes: i64,
    pass_used_bytes: i64,
}

impl From<api::types::User> for UserApiData {
    fn from(user: api::types::User) -> Self {
        Self {
            name: user.name,
            display_name: user.display_name,
            used_bytes: user.used_space,
            total_bytes: user.max_space,
            max_upload: user.max_upload,
            credit: user.credit,
            currency: user.currency,
            calendar_used_bytes: user.product_used_space.calendar,
            contact_used_bytes: user.product_used_space.contact,
            drive_used_bytes: user.product_used_space.drive,
            mail_used_bytes: user.product_used_space.mail,
            pass_used_bytes: user.product_used_space.pass,
        }
    }
}

fn session_to_user(
    session: &Session,
    split_mode: bool,
    api_data: Option<&UserApiData>,
) -> pb::User {
    let avatar_text = session
        .email
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "U".to_string());
    let api_data = api_data.cloned().unwrap_or_default();
    let display_name = if api_data.display_name.is_empty() {
        session.display_name.clone()
    } else {
        api_data.display_name
    };

    pb::User {
        id: session.uid.clone(),
        username: session.email.clone(),
        avatar_text,
        state: pb::UserState::Connected as i32,
        split_mode,
        used_bytes: api_data.used_bytes,
        total_bytes: api_data.total_bytes,
        password: session
            .bridge_password
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        addresses: vec![session.email.clone()],
        name: api_data.name,
        display_name,
        max_upload: api_data.max_upload,
        credit: api_data.credit,
        currency: api_data.currency,
        calendar_used_bytes: api_data.calendar_used_bytes,
        contact_used_bytes: api_data.contact_used_bytes,
        drive_used_bytes: api_data.drive_used_bytes,
        mail_used_bytes: api_data.mail_used_bytes,
        pass_used_bytes: api_data.pass_used_bytes,
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
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

async fn is_bind_port_free(bind_host: &str, port: u16) -> bool {
    std::net::TcpListener::bind((bind_host, port)).is_ok()
}

fn generate_server_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[cfg(unix)]
struct UnixSocketCleanup {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for UnixSocketCleanup {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to remove grpc unix socket file"
                );
            }
        }
    }
}

#[cfg(unix)]
fn compute_grpc_unix_socket_path() -> anyhow::Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    for _ in 0..1000 {
        let suffix = rand::thread_rng().gen_range(0..10_000);
        let candidate = temp_dir.join(format!("bridge{suffix:04}"));

        if candidate.exists() {
            match std::fs::remove_file(&candidate) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
        }

        return Ok(candidate);
    }

    anyhow::bail!("failed to allocate grpc unix socket path")
}

fn generate_bridge_password() -> String {
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    BASE64_URL_NO_PAD.encode(token)
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
    info!(
        path = %path.display(),
        "Successfully saved gRPC service config file"
    );
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

fn resolve_live_gluon_cache_root(runtime_paths: &RuntimePaths) -> Option<PathBuf> {
    let sessions = match vault::list_sessions(runtime_paths.settings_dir()) {
        Ok(sessions) => sessions,
        Err(err) => {
            warn!(
                error = %err,
                "failed to load sessions while resolving live gluon cache root"
            );
            return None;
        }
    };
    if sessions.is_empty() {
        return None;
    }

    let account_ids = sessions
        .iter()
        .map(|session| session.uid.clone())
        .collect::<Vec<_>>();
    let bootstrap =
        match vault::load_gluon_store_bootstrap(runtime_paths.settings_dir(), &account_ids) {
            Ok(bootstrap) => bootstrap,
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to load gluon bootstrap while resolving live cache root"
                );
                return None;
            }
        };

    Some(
        runtime_paths
            .gluon_paths(Some(bootstrap.gluon_dir.as_str()))
            .root()
            .to_path_buf(),
    )
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

async fn is_mail_tls_certificate_installed(vault_dir: &Path) -> anyhow::Result<bool> {
    let (cert_path, key_path) = mail_cert_paths(vault_dir);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(false);
    }

    crate::certs::is_certificate_installed(&cert_path)
}

async fn install_mail_tls_certificate(vault_dir: &Path) -> anyhow::Result<()> {
    ensure_mail_tls_certificate(vault_dir).await?;
    let (cert_path, _) = mail_cert_paths(vault_dir);
    crate::certs::install_certificate(&cert_path)
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
        include_bytes!("../../../tests/fixtures/proton_profile_golden/vault.enc");
    const PROTON_FIXTURE_VAULT_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/proton_profile_golden/vault.key");
    const PROTON_FIXTURE_DEFAULT_EMAIL: &str =
        include_str!("../../../tests/fixtures/proton_profile_golden/default_email");

    #[test]
    fn next_interrupt_action_transitions_after_first_signal() {
        assert_eq!(
            next_interrupt_action(false),
            InterruptAction::InitiateShutdown
        );
        assert_eq!(next_interrupt_action(true), InterruptAction::ForceExit);
    }

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
            runtime_supervisor: Arc::new(bridge::runtime_supervisor::RuntimeSupervisor::new(
                runtime_paths.clone(),
            )),
            runtime_paths,
            bind_host: "127.0.0.1".to_string(),
            active_disk_cache_path: Mutex::new(active_disk_cache_path),
            event_tx,
            event_backlog: std::sync::Mutex::new(VecDeque::new()),
            active_stream_stop: Mutex::new(None),
            pending_login: Mutex::new(None),
            pending_hv: Mutex::new(None),
            session_access_tokens: Mutex::new(HashMap::new()),
            shutdown_tx,
            mail_settings: Mutex::new(StoredMailSettings::default()),
            mail_runtime_transition_lock: Mutex::new(()),
            sync_workers_enabled: false,
            sync_event_workers: Mutex::new(None),
        });
        BridgeService::new(state)
    }

    fn build_test_service(vault_dir: PathBuf) -> BridgeService {
        let runtime_paths = RuntimePaths::resolve(Some(&vault_dir)).unwrap();
        build_test_service_with_paths(runtime_paths)
    }

    fn pim_test_calendar(id: &str, name: &str) -> crate::api::calendar::Calendar {
        crate::api::calendar::Calendar {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            color: "#00AAFF".to_string(),
            display: 1,
            calendar_type: 0,
            flags: 0,
        }
    }

    fn pim_test_contact(
        id: &str,
        name: &str,
        email: &str,
        modify_time: i64,
    ) -> crate::api::contacts::Contact {
        crate::api::contacts::Contact {
            metadata: crate::api::contacts::ContactMetadata {
                id: id.to_string(),
                name: name.to_string(),
                uid: format!("uid-{id}"),
                size: 10,
                create_time: modify_time - 1,
                modify_time,
                contact_emails: vec![crate::api::contacts::ContactEmail {
                    id: format!("email-{id}"),
                    email: email.to_string(),
                    name: name.to_string(),
                    kind: vec![],
                    defaults: None,
                    order: None,
                    contact_id: id.to_string(),
                    label_ids: vec![],
                    last_used_time: None,
                }],
                label_ids: vec![],
            },
            cards: vec![crate::api::contacts::ContactCard {
                card_type: 0,
                data: "BEGIN:VCARD".to_string(),
                signature: None,
            }],
        }
    }

    fn pim_test_calendar_event(
        id: &str,
        calendar_id: &str,
        start_time: i64,
        end_time: i64,
    ) -> crate::api::calendar::CalendarEvent {
        crate::api::calendar::CalendarEvent {
            id: id.to_string(),
            uid: format!("uid-{id}"),
            calendar_id: calendar_id.to_string(),
            shared_event_id: format!("shared-{id}"),
            create_time: start_time - 10,
            last_edit_time: start_time - 5,
            start_time,
            end_time,
            ..crate::api::calendar::CalendarEvent::default()
        }
    }

    fn pim_setup_account_store(
        service: &BridgeService,
        session: &Session,
    ) -> crate::pim::store::PimStore {
        vault::save_session(session, service.settings_dir()).unwrap();
        vault::set_gluon_key_by_account_id(service.settings_dir(), &session.uid, vec![9u8; 32])
            .unwrap();

        let bootstrap = vault::load_gluon_store_bootstrap(
            service.settings_dir(),
            std::slice::from_ref(&session.uid),
        )
        .unwrap();
        let account = bootstrap.accounts.first().unwrap();
        let db_path = service
            .state
            .runtime_paths
            .gluon_paths(Some(bootstrap.gluon_dir.as_str()))
            .account_db_path(&account.storage_user_id);
        crate::pim::store::PimStore::new(db_path).unwrap()
    }

    #[tokio::test]
    async fn startup_mail_runtime_port_conflict_emits_startup_error_event() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::resolve(Some(dir.path())).unwrap();
        let service = build_test_service_with_paths(runtime_paths);
        let mut events = service.state.event_tx.subscribe();

        let occupied = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        {
            let mut settings = service.state.mail_settings.lock().await;
            settings.imap_port = i32::from(occupied_port);
            settings.smtp_port = i32::from(occupied_port + 1);
        }

        service.start_mail_runtime_on_startup().await;

        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("startup event timeout")
            .expect("startup event");
        match event.event {
            Some(pb::stream_event::Event::MailServerSettings(pb::MailServerSettingsEvent {
                event: Some(pb::mail_server_settings_event::Event::Error(err)),
            })) => {
                assert_eq!(
                    err.r#type,
                    pb::MailServerSettingsErrorType::ImapPortStartupError as i32
                );
            }
            other => panic!("unexpected startup conflict event: {other:?}"),
        }
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
                api_mode: None,
                requested_scopes: Vec::new(),
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
            .contains("https://verify.proton.me/captcha?methods=captcha&token=token-123"));
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

    #[test]
    fn session_to_user_maps_api_metadata_fields() {
        let session = Session {
            uid: "uid-1".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-1".to_string(),
            email: "alice@example.com".to_string(),
            display_name: "Alice Session".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        let api_data = UserApiData {
            name: "alice".to_string(),
            display_name: "Alice API".to_string(),
            used_bytes: 128,
            total_bytes: 1024,
            max_upload: 32,
            credit: 7,
            currency: "CHF".to_string(),
            calendar_used_bytes: 1,
            contact_used_bytes: 2,
            drive_used_bytes: 3,
            mail_used_bytes: 4,
            pass_used_bytes: 5,
        };

        let user = session_to_user(&session, true, Some(&api_data));
        assert_eq!(user.id, "uid-1");
        assert_eq!(user.username, "alice@example.com");
        assert!(user.split_mode);
        assert_eq!(user.used_bytes, 128);
        assert_eq!(user.total_bytes, 1024);
        assert_eq!(user.max_upload, 32);
        assert_eq!(user.credit, 7);
        assert_eq!(user.currency, "CHF");
        assert_eq!(user.calendar_used_bytes, 1);
        assert_eq!(user.contact_used_bytes, 2);
        assert_eq!(user.drive_used_bytes, 3);
        assert_eq!(user.mail_used_bytes, 4);
        assert_eq!(user.pass_used_bytes, 5);
        assert_eq!(user.name, "alice");
        assert_eq!(user.display_name, "Alice API");
        assert_eq!(user.password, b"bridge-pass");
    }

    #[test]
    fn session_to_user_falls_back_to_session_display_name_without_api_metadata() {
        let session = Session {
            uid: "uid-2".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-2".to_string(),
            email: "bob@example.com".to_string(),
            display_name: "Bob Session".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };

        let user = session_to_user(&session, false, None);
        assert_eq!(user.display_name, "Bob Session");
        assert_eq!(user.used_bytes, 0);
        assert_eq!(user.total_bytes, 0);
        assert_eq!(user.password, b"");
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
            pim_reconcile_tick_secs: 600,
            pim_contacts_reconcile_secs: 86400,
            pim_calendar_reconcile_secs: 86400,
            pim_calendar_horizon_reconcile_secs: 43200,
        };
        save_mail_settings(&path, &settings).await.unwrap();
        let loaded = load_mail_settings(&path).await.unwrap();
        assert_eq!(loaded.imap_port, 1144);
        assert_eq!(loaded.smtp_port, 1026);
        assert!(loaded.use_ssl_for_imap);
        assert!(loaded.use_ssl_for_smtp);
        assert_eq!(loaded.pim_reconcile_tick_secs, 600);
        assert_eq!(loaded.pim_contacts_reconcile_secs, 86400);
        assert_eq!(loaded.pim_calendar_reconcile_secs, 86400);
        assert_eq!(loaded.pim_calendar_horizon_reconcile_secs, 43200);
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
    async fn pim_list_calendars_returns_rows_for_uid_and_email_selectors() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim@example.com".to_string(),
            display_name: "Pim User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        vault::save_session(&session, service.settings_dir()).unwrap();
        vault::set_gluon_key_by_account_id(service.settings_dir(), &session.uid, vec![9u8; 32])
            .unwrap();

        let bootstrap = vault::load_gluon_store_bootstrap(
            service.settings_dir(),
            std::slice::from_ref(&session.uid),
        )
        .unwrap();
        let account = bootstrap.accounts.first().unwrap();
        let db_path = service
            .state
            .runtime_paths
            .gluon_paths(Some(bootstrap.gluon_dir.as_str()))
            .account_db_path(&account.storage_user_id);
        let store = crate::pim::store::PimStore::new(db_path).unwrap();
        store
            .upsert_calendar(&pim_test_calendar("cal-1", "Primary"))
            .unwrap();

        let by_uid = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendars(
            &service,
            Request::new(pb::PimListCalendarsRequest {
                account_id: session.uid.clone(),
                include_deleted: false,
                page: Some(pb::PimPage {
                    limit: 20,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(by_uid.calendars.len(), 1);
        assert_eq!(by_uid.calendars[0].id, "cal-1");

        let by_email = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendars(
            &service,
            Request::new(pb::PimListCalendarsRequest {
                account_id: session.email.clone(),
                include_deleted: false,
                page: Some(pb::PimPage {
                    limit: 20,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(by_email.calendars.len(), 1);
        assert_eq!(by_email.calendars[0].name, "Primary");
    }

    #[tokio::test]
    async fn pim_list_calendars_returns_not_found_for_unknown_account() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let status = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendars(
            &service,
            Request::new(pb::PimListCalendarsRequest {
                account_id: "missing@example.com".to_string(),
                include_deleted: false,
                page: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn pim_contact_queries_support_listing_get_and_search() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-contact-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim-contacts@example.com".to_string(),
            display_name: "Pim Contacts User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let store = pim_setup_account_store(&service, &session);
        store
            .upsert_contact(&pim_test_contact(
                "contact-1",
                "Alice",
                "alice@proton.me",
                20,
            ))
            .unwrap();
        store
            .upsert_contact(&pim_test_contact("contact-2", "Bob", "bob@proton.me", 10))
            .unwrap();
        store.soft_delete_contact("contact-2").unwrap();

        let listed = <BridgeService as pb::bridge_server::Bridge>::pim_list_contacts(
            &service,
            Request::new(pb::PimListContactsRequest {
                account_id: session.uid.clone(),
                include_deleted: false,
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.contacts.len(), 1);
        assert_eq!(listed.contacts[0].id, "contact-1");

        let listed_with_deleted = <BridgeService as pb::bridge_server::Bridge>::pim_list_contacts(
            &service,
            Request::new(pb::PimListContactsRequest {
                account_id: session.uid.clone(),
                include_deleted: true,
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed_with_deleted.contacts.len(), 2);

        let hidden_deleted = <BridgeService as pb::bridge_server::Bridge>::pim_get_contact(
            &service,
            Request::new(pb::PimGetContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-2".to_string(),
                include_deleted: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(hidden_deleted.code(), tonic::Code::NotFound);

        let deleted_contact = <BridgeService as pb::bridge_server::Bridge>::pim_get_contact(
            &service,
            Request::new(pb::PimGetContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-2".to_string(),
                include_deleted: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(deleted_contact.id, "contact-2");
        assert!(deleted_contact.deleted);

        let searched = <BridgeService as pb::bridge_server::Bridge>::pim_search_contacts_by_email(
            &service,
            Request::new(pb::PimSearchContactsByEmailRequest {
                account_id: session.uid.clone(),
                email_like: "alice@".to_string(),
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(searched.contacts.len(), 1);
        assert_eq!(searched.contacts[0].id, "contact-1");
    }

    #[tokio::test]
    async fn pim_list_calendar_events_validates_and_filters_time_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-events-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim-events@example.com".to_string(),
            display_name: "Pim Events User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let store = pim_setup_account_store(&service, &session);
        store
            .upsert_calendar(&pim_test_calendar("cal-events-1", "Events"))
            .unwrap();
        store
            .upsert_calendar_event(&pim_test_calendar_event("evt-1", "cal-events-1", 100, 150))
            .unwrap();
        store
            .upsert_calendar_event(&pim_test_calendar_event("evt-2", "cal-events-1", 300, 350))
            .unwrap();
        store.soft_delete_calendar_event("evt-2").unwrap();

        let invalid_range = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendar_events(
            &service,
            Request::new(pb::PimListCalendarEventsRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-events-1".to_string(),
                include_deleted: false,
                start_time_from: Some(400),
                start_time_to: Some(200),
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(invalid_range.code(), tonic::Code::InvalidArgument);

        let filtered = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendar_events(
            &service,
            Request::new(pb::PimListCalendarEventsRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-events-1".to_string(),
                include_deleted: false,
                start_time_from: Some(50),
                start_time_to: Some(250),
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(filtered.events.len(), 1);
        assert_eq!(filtered.events[0].id, "evt-1");

        let with_deleted = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendar_events(
            &service,
            Request::new(pb::PimListCalendarEventsRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-events-1".to_string(),
                include_deleted: true,
                start_time_from: Some(50),
                start_time_to: Some(400),
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(with_deleted.events.len(), 2);
        assert_eq!(with_deleted.events[0].id, "evt-1");
        assert_eq!(with_deleted.events[1].id, "evt-2");
    }

    #[tokio::test]
    async fn pim_write_contact_roundtrip_supports_soft_and_hard_delete() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-write-contact-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim-write-contact@example.com".to_string(),
            display_name: "Pim Write Contact User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let _ = pim_setup_account_store(&service, &session);

        <BridgeService as pb::bridge_server::Bridge>::pim_upsert_contact(
            &service,
            Request::new(pb::PimUpsertContactRequest {
                account_id: session.uid.clone(),
                contact: Some(pb::PimContact {
                    id: "contact-write-1".to_string(),
                    uid: "uid-contact-write-1".to_string(),
                    name: "Alice Writable".to_string(),
                    size: 11,
                    create_time: 1000,
                    modify_time: 1001,
                    deleted: false,
                    updated_at_ms: 0,
                }),
                emails: vec![pb::PimContactEmail {
                    id: "email-write-1".to_string(),
                    email: "alice.writable@proton.me".to_string(),
                    name: "Alice Writable".to_string(),
                    kind: vec!["home".to_string()],
                    defaults: Some(1),
                    order: Some(1),
                    label_i_ds: vec![],
                    last_used_time: None,
                }],
                cards: vec![pb::PimContactCard {
                    card_type: 0,
                    data: "BEGIN:VCARD".to_string(),
                    signature: None,
                }],
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        let inserted = <BridgeService as pb::bridge_server::Bridge>::pim_get_contact(
            &service,
            Request::new(pb::PimGetContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-write-1".to_string(),
                include_deleted: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(inserted.name, "Alice Writable");

        <BridgeService as pb::bridge_server::Bridge>::pim_delete_contact(
            &service,
            Request::new(pb::PimDeleteContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-write-1".to_string(),
                hard_delete: false,
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        let soft_deleted = <BridgeService as pb::bridge_server::Bridge>::pim_get_contact(
            &service,
            Request::new(pb::PimGetContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-write-1".to_string(),
                include_deleted: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(soft_deleted.deleted);

        <BridgeService as pb::bridge_server::Bridge>::pim_delete_contact(
            &service,
            Request::new(pb::PimDeleteContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-write-1".to_string(),
                hard_delete: true,
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        let missing = <BridgeService as pb::bridge_server::Bridge>::pim_get_contact(
            &service,
            Request::new(pb::PimGetContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-write-1".to_string(),
                include_deleted: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn pim_write_calendar_and_event_roundtrip_supports_hard_delete() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-write-calendar-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim-write-calendar@example.com".to_string(),
            display_name: "Pim Write Calendar User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let _ = pim_setup_account_store(&service, &session);

        <BridgeService as pb::bridge_server::Bridge>::pim_upsert_calendar(
            &service,
            Request::new(pb::PimUpsertCalendarRequest {
                account_id: session.uid.clone(),
                calendar: Some(pb::PimCalendar {
                    id: "cal-write-1".to_string(),
                    name: "Writable".to_string(),
                    description: "".to_string(),
                    color: "#00AAFF".to_string(),
                    display: 1,
                    calendar_type: 0,
                    flags: 0,
                    deleted: false,
                    updated_at_ms: 0,
                }),
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        <BridgeService as pb::bridge_server::Bridge>::pim_upsert_calendar_event(
            &service,
            Request::new(pb::PimUpsertCalendarEventRequest {
                account_id: session.uid.clone(),
                event: Some(pb::PimCalendarEvent {
                    id: "evt-write-1".to_string(),
                    calendar_id: "cal-write-1".to_string(),
                    uid: "uid-evt-write-1".to_string(),
                    shared_event_id: "shared-evt-write-1".to_string(),
                    start_time: 500,
                    end_time: 550,
                    deleted: false,
                    updated_at_ms: 0,
                }),
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        let events = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendar_events(
            &service,
            Request::new(pb::PimListCalendarEventsRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-write-1".to_string(),
                include_deleted: false,
                start_time_from: None,
                start_time_to: None,
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.events[0].id, "evt-write-1");

        <BridgeService as pb::bridge_server::Bridge>::pim_delete_calendar_event(
            &service,
            Request::new(pb::PimDeleteCalendarEventRequest {
                account_id: session.uid.clone(),
                event_id: "evt-write-1".to_string(),
                hard_delete: true,
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        let post_delete_events =
            <BridgeService as pb::bridge_server::Bridge>::pim_list_calendar_events(
                &service,
                Request::new(pb::PimListCalendarEventsRequest {
                    account_id: session.uid.clone(),
                    calendar_id: "cal-write-1".to_string(),
                    include_deleted: true,
                    start_time_from: None,
                    start_time_to: None,
                    page: Some(pb::PimPage {
                        limit: 50,
                        offset: 0,
                    }),
                }),
            )
            .await
            .unwrap()
            .into_inner();
        assert!(post_delete_events.events.is_empty());

        <BridgeService as pb::bridge_server::Bridge>::pim_delete_calendar(
            &service,
            Request::new(pb::PimDeleteCalendarRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-write-1".to_string(),
                hard_delete: true,
                expected_updated_at_ms: None,
            }),
        )
        .await
        .unwrap();

        let missing_calendar = <BridgeService as pb::bridge_server::Bridge>::pim_get_calendar(
            &service,
            Request::new(pb::PimGetCalendarRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-write-1".to_string(),
                include_deleted: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing_calendar.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn pim_reconcile_metrics_returns_defaults_when_runtime_is_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());

        let metrics = <BridgeService as pb::bridge_server::Bridge>::pim_reconcile_metrics(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!metrics.runtime_running);
        assert_eq!(metrics.sweeps_total, 0);
        assert_eq!(metrics.contacts_success_total, 0);
        assert_eq!(metrics.calendar_full_success_total, 0);
    }

    #[tokio::test]
    async fn pim_reconcile_metrics_returns_non_zero_snapshot_when_runtime_running() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        service
            .state
            .runtime_supervisor
            .install_test_runtime_state(
                true,
                crate::bridge::mail_runtime::PimReconcileMetricsSnapshot {
                    sweeps_total: 3,
                    contacts_success_total: 4,
                    calendar_full_success_total: 5,
                    last_sweep_elapsed_ms: 123,
                    ..Default::default()
                },
            )
            .await;

        let metrics = <BridgeService as pb::bridge_server::Bridge>::pim_reconcile_metrics(
            &service,
            Request::new(()),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(metrics.runtime_running);
        assert_eq!(metrics.sweeps_total, 3);
        assert_eq!(metrics.contacts_success_total, 4);
        assert_eq!(metrics.calendar_full_success_total, 5);
        assert_eq!(metrics.last_sweep_elapsed_ms, 123);
    }

    #[tokio::test]
    async fn pim_upsert_contact_rejects_stale_expected_updated_at() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-stale-contact-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim-stale-contact@example.com".to_string(),
            display_name: "Pim Stale Contact User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let store = pim_setup_account_store(&service, &session);
        store
            .upsert_contact(&pim_test_contact(
                "contact-stale-1",
                "Alice",
                "alice@proton.me",
                100,
            ))
            .unwrap();

        let first = <BridgeService as pb::bridge_server::Bridge>::pim_get_contact(
            &service,
            Request::new(pb::PimGetContactRequest {
                account_id: session.uid.clone(),
                contact_id: "contact-stale-1".to_string(),
                include_deleted: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let initial_updated_at = first.updated_at_ms;
        assert!(initial_updated_at > 0);

        tokio::time::sleep(Duration::from_millis(2)).await;

        <BridgeService as pb::bridge_server::Bridge>::pim_upsert_contact(
            &service,
            Request::new(pb::PimUpsertContactRequest {
                account_id: session.uid.clone(),
                contact: Some(pb::PimContact {
                    id: "contact-stale-1".to_string(),
                    uid: "uid-contact-stale-1".to_string(),
                    name: "Alice v2".to_string(),
                    size: 10,
                    create_time: 100,
                    modify_time: 101,
                    deleted: false,
                    updated_at_ms: initial_updated_at,
                }),
                emails: vec![],
                cards: vec![],
                expected_updated_at_ms: Some(initial_updated_at),
            }),
        )
        .await
        .unwrap();

        let stale = <BridgeService as pb::bridge_server::Bridge>::pim_upsert_contact(
            &service,
            Request::new(pb::PimUpsertContactRequest {
                account_id: session.uid.clone(),
                contact: Some(pb::PimContact {
                    id: "contact-stale-1".to_string(),
                    uid: "uid-contact-stale-1".to_string(),
                    name: "Alice stale".to_string(),
                    size: 10,
                    create_time: 100,
                    modify_time: 102,
                    deleted: false,
                    updated_at_ms: initial_updated_at,
                }),
                emails: vec![],
                cards: vec![],
                expected_updated_at_ms: Some(initial_updated_at),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::Aborted);
    }

    #[tokio::test]
    async fn pim_delete_calendar_event_rejects_stale_expected_updated_at() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-pim-stale-event-1".to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: "pim-stale-event@example.com".to_string(),
            display_name: "Pim Stale Event User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let store = pim_setup_account_store(&service, &session);
        store
            .upsert_calendar(&pim_test_calendar("cal-stale-1", "Stale"))
            .unwrap();
        store
            .upsert_calendar_event(&pim_test_calendar_event(
                "evt-stale-1",
                "cal-stale-1",
                200,
                250,
            ))
            .unwrap();

        let first = <BridgeService as pb::bridge_server::Bridge>::pim_list_calendar_events(
            &service,
            Request::new(pb::PimListCalendarEventsRequest {
                account_id: session.uid.clone(),
                calendar_id: "cal-stale-1".to_string(),
                include_deleted: true,
                start_time_from: None,
                start_time_to: None,
                page: Some(pb::PimPage {
                    limit: 50,
                    offset: 0,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let initial_updated_at = first.events[0].updated_at_ms;
        assert!(initial_updated_at > 0);

        tokio::time::sleep(Duration::from_millis(2)).await;
        store
            .upsert_calendar_event(&pim_test_calendar_event(
                "evt-stale-1",
                "cal-stale-1",
                300,
                350,
            ))
            .unwrap();

        let stale_delete = <BridgeService as pb::bridge_server::Bridge>::pim_delete_calendar_event(
            &service,
            Request::new(pb::PimDeleteCalendarEventRequest {
                account_id: session.uid.clone(),
                event_id: "evt-stale-1".to_string(),
                hard_delete: true,
                expected_updated_at_ms: Some(initial_updated_at),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(stale_delete.code(), tonic::Code::Aborted);
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

        let current = <BridgeService as pb::bridge_server::Bridge>::current_email_client(
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
    async fn sync_generation_filters_stale_worker_callbacks() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let generation_1 = service.next_sync_worker_generation();
        service.emit_sync_started_for_generation("uid-1", generation_1);
        service.emit_sync_progress_for_generation("uid-1", 0.25, 25, 75, generation_1);

        let started = events.recv().await.unwrap();
        match started.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected started event: {other:?}"),
        }

        let progress = events.recv().await.unwrap();
        match progress.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
                assert!((event.progress - 0.25).abs() < f64::EPSILON);
            }
            other => panic!("unexpected progress event: {other:?}"),
        }

        let generation_2 = service.next_sync_worker_generation();
        service.emit_sync_progress_for_generation("uid-1", 0.75, 75, 25, generation_1);
        service.emit_sync_finished_for_generation("uid-1", generation_1);

        let stale = tokio::time::timeout(Duration::from_millis(150), events.recv()).await;
        assert!(
            stale.is_err(),
            "stale generation callbacks should be dropped"
        );

        service.emit_sync_started_for_generation("uid-1", generation_2);
        service.emit_sync_progress_for_generation("uid-1", 0.8, 80, 20, generation_2);
        service.emit_sync_finished_for_generation("uid-1", generation_2);

        let started_current = events.recv().await.unwrap();
        match started_current.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncStartedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected current started event: {other:?}"),
        }

        let progress_current = events.recv().await.unwrap();
        match progress_current.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncProgressEvent(event)),
            })) => {
                assert_eq!(event.user_id, "uid-1");
                assert!((event.progress - 0.8).abs() < f64::EPSILON);
            }
            other => panic!("unexpected current progress event: {other:?}"),
        }

        let finished_current = events.recv().await.unwrap();
        match finished_current.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected current finished event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn clear_active_syncing_users_emits_finished_once_per_user() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let generation = service.next_sync_worker_generation();
        service.emit_sync_started_for_generation("uid-b", generation);
        service.emit_sync_started_for_generation("uid-a", generation);
        service.emit_sync_started_for_generation("uid-a", generation);
        service.clear_active_syncing_users();

        let mut started_users = Vec::new();
        let mut finished_users = Vec::new();
        for _ in 0..4 {
            let event = events.recv().await.unwrap();
            match event.event {
                Some(pb::stream_event::Event::User(pb::UserEvent {
                    event: Some(pb::user_event::Event::SyncStartedEvent(started)),
                })) => started_users.push(started.user_id),
                Some(pb::stream_event::Event::User(pb::UserEvent {
                    event: Some(pb::user_event::Event::SyncFinishedEvent(finished)),
                })) => finished_users.push(finished.user_id),
                other => panic!("unexpected sync lifecycle event: {other:?}"),
            }
        }

        started_users.sort();
        finished_users.sort();
        assert_eq!(
            started_users,
            vec!["uid-a".to_string(), "uid-b".to_string()]
        );
        assert_eq!(
            finished_users,
            vec!["uid-a".to_string(), "uid-b".to_string()]
        );

        let extra = tokio::time::timeout(Duration::from_millis(150), events.recv()).await;
        assert!(
            extra.is_err(),
            "clear should not emit duplicate finish events"
        );
    }

    #[tokio::test]
    async fn clear_active_syncing_users_emits_sorted_finish_order() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        let generation = service.next_sync_worker_generation();
        service.emit_sync_started_for_generation("uid-b", generation);
        service.emit_sync_started_for_generation("uid-a", generation);
        let _ = events.recv().await.unwrap();
        let _ = events.recv().await.unwrap();

        service.clear_active_syncing_users();

        let first_finish = events.recv().await.unwrap();
        let second_finish = events.recv().await.unwrap();

        match first_finish.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-a"),
            other => panic!("unexpected first sorted finish event: {other:?}"),
        }
        match second_finish.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::SyncFinishedEvent(event)),
            })) => assert_eq!(event.user_id, "uid-b"),
            other => panic!("unexpected second sorted finish event: {other:?}"),
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
            api_mode: crate::api::types::ApiMode::Bridge,
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
            api_mode: crate::api::types::ApiMode::Bridge,
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
            api_mode: crate::api::types::ApiMode::Bridge,
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
            api_mode: crate::api::types::ApiMode::Bridge,
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
    async fn render_mutt_config_returns_stdout_equivalent_rendered_text() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-mutt-render-1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "mutt-render@proton.me".to_string(),
            display_name: "Mutt Render".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        {
            let mut settings = service.state.mail_settings.lock().await;
            settings.imap_port = 1143;
            settings.smtp_port = 1025;
            settings.use_ssl_for_imap = false;
            settings.use_ssl_for_smtp = false;
        }

        let response = <BridgeService as pb::bridge_server::Bridge>::render_mutt_config(
            &service,
            Request::new(pb::RenderMuttConfigRequest {
                account_selector: String::new(),
                address_override: String::new(),
                include_password: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let expected = client_config::render_mutt_config(
            &client_config::MuttConfigTemplate {
                account_address: session.email.clone(),
                display_name: session.display_name.clone(),
                hostname: "127.0.0.1".to_string(),
                imap_port: 1143,
                smtp_port: 1025,
                use_ssl_for_imap: false,
                use_ssl_for_smtp: false,
                bridge_password: session.bridge_password.clone(),
            },
            false,
        );
        assert_eq!(response.rendered_config, expected);
        assert!(response
            .rendered_config
            .contains("# set imap_pass = \"<bridge-password>\""));
    }

    #[tokio::test]
    async fn render_mutt_config_rejects_include_password_when_bridge_password_missing() {
        let dir = tempfile::tempdir().unwrap();
        let service = build_test_service(dir.path().to_path_buf());
        let session = Session {
            uid: "uid-mutt-render-2".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "mutt-missing@proton.me".to_string(),
            display_name: "Mutt Missing".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        vault::save_session(&session, service.settings_dir()).unwrap();

        let result = <BridgeService as pb::bridge_server::Bridge>::render_mutt_config(
            &service,
            Request::new(pb::RenderMuttConfigRequest {
                account_selector: session.uid.clone(),
                address_override: String::new(),
                include_password: true,
            }),
        )
        .await;

        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status
            .message()
            .contains("bridge password is missing for mutt-missing@proton.me"));
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
        assert!(response
            .keychains
            .iter()
            .all(|helper| keychain_helper_to_backend(helper).is_some()));
        let response_backends: Vec<String> = response
            .keychains
            .iter()
            .filter_map(|helper| keychain_helper_to_backend(helper).map(str::to_owned))
            .collect();
        let mapped = available_keychain_helpers_with_backends(&response_backends);
        assert!(response
            .keychains
            .iter()
            .all(|helper| mapped.iter().any(|candidate| candidate == helper)));
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
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, service.settings_dir()).unwrap();
        let checkpoint = vault::StoredEventCheckpoint {
            last_event_id: "event-123".to_string(),
            last_event_ts: Some(1_700_000_000),
            sync_state: Some("refresh_resync".to_string()),
        };
        vault::save_event_checkpoint_by_account_id(
            service.settings_dir(),
            &session.uid,
            &checkpoint,
        )
        .unwrap();
        assert!(
            vault::load_event_checkpoint_by_account_id(service.settings_dir(), &session.uid)
                .unwrap()
                .is_some()
        );

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
            api_mode: crate::api::types::ApiMode::Bridge,
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

        let old_payload = old_path
            .join("backend")
            .join("store")
            .join("uid-1")
            .join("00000001.msg");
        tokio::fs::create_dir_all(old_payload.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&old_payload, b"cache-payload")
            .await
            .unwrap();
        let old_db = old_path.join("backend").join("db").join("uid-1.db");
        tokio::fs::create_dir_all(old_db.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&old_db, b"cache-sqlite").await.unwrap();

        let new_path = root.path().join("moved-cache");
        <BridgeService as pb::bridge_server::Bridge>::set_disk_cache_path(
            &service,
            Request::new(new_path.display().to_string()),
        )
        .await
        .unwrap();

        let copied_payload = new_path
            .join("backend")
            .join("store")
            .join("uid-1")
            .join("00000001.msg");
        assert_eq!(
            tokio::fs::read(&copied_payload).await.unwrap(),
            b"cache-payload"
        );
        assert!(new_path
            .join("backend")
            .join("db")
            .join("uid-1.db")
            .exists());
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

        // Ensure the moved disk cache path is persisted and reloaded on service restart.
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

        let effective_after_restart =
            <BridgeService as pb::bridge_server::Bridge>::disk_cache_path(
                &restarted_service,
                Request::new(()),
            )
            .await
            .unwrap()
            .into_inner();
        assert_eq!(effective_after_restart, new_path.display().to_string());
        assert_eq!(
            tokio::fs::read(
                new_path
                    .join("backend")
                    .join("store")
                    .join("uid-1")
                    .join("00000001.msg")
            )
            .await
            .unwrap(),
            b"cache-payload"
        );
        assert!(new_path
            .join("backend")
            .join("db")
            .join("uid-1.db")
            .exists());
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
    async fn set_disk_cache_path_moves_live_gluon_store_and_updates_bootstrap_path() {
        let root = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::resolve(Some(root.path())).unwrap();
        let service = build_test_service_with_paths(runtime_paths.clone());

        let session = Session {
            uid: "uid-cache-switch".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "cache-switch@example.com".to_string(),
            display_name: "Cache Switch".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        vault::save_session(&session, service.settings_dir()).unwrap();
        vault::set_gluon_key_by_account_id(service.settings_dir(), &session.uid, vec![9u8; 32])
            .unwrap();

        let source_gluon_root = runtime_paths
            .gluon_paths(Some("gluon"))
            .root()
            .to_path_buf();
        let source_blob = source_gluon_root
            .join("backend")
            .join("store")
            .join("live-user")
            .join("00000001.msg");
        tokio::fs::create_dir_all(source_blob.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&source_blob, b"gluon-live-message")
            .await
            .unwrap();

        let target_gluon_root = root.path().join("gluon-cache-moved");
        <BridgeService as pb::bridge_server::Bridge>::set_disk_cache_path(
            &service,
            Request::new(target_gluon_root.display().to_string()),
        )
        .await
        .unwrap();

        let moved_blob = target_gluon_root
            .join("backend")
            .join("store")
            .join("live-user")
            .join("00000001.msg");
        assert_eq!(
            tokio::fs::read(&moved_blob).await.unwrap(),
            b"gluon-live-message"
        );
        assert!(!source_gluon_root.exists());

        let bootstrap = vault::load_gluon_store_bootstrap(
            service.settings_dir(),
            std::slice::from_ref(&session.uid),
        )
        .unwrap();
        assert_eq!(
            runtime_paths.gluon_paths(Some(&bootstrap.gluon_dir)).root(),
            target_gluon_root
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
            api_mode: crate::api::types::ApiMode::Bridge,
            required_scopes: Vec::new(),
            auth_granted_scopes: vec!["mail".to_string()],
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
            api_mode: crate::api::types::ApiMode::Bridge,
            required_scopes: Vec::new(),
            auth_granted_scopes: vec!["mail".to_string()],
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
            api_mode: crate::api::types::ApiMode::Bridge,
            required_scopes: Vec::new(),
            auth_granted_scopes: vec!["mail".to_string()],
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
            api_mode: crate::api::types::ApiMode::Bridge,
            required_scopes: Vec::new(),
            auth_granted_scopes: vec!["mail".to_string()],
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
    async fn integration_proton_fixture_reuse_survives_service_restart() {
        let dir = tempfile::tempdir().unwrap();
        write_proton_golden_fixture(dir.path());
        let runtime_paths = RuntimePaths::resolve(Some(dir.path())).unwrap();

        let service = build_test_service_with_paths(runtime_paths.clone());
        let users_before =
            <BridgeService as pb::bridge_server::Bridge>::get_user_list(&service, Request::new(()))
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
    async fn integration_login_then_logout_updates_user_list_and_emits_disconnect() {
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
            api_mode: crate::api::types::ApiMode::Bridge,
            required_scopes: Vec::new(),
            auth_granted_scopes: vec!["mail".to_string()],
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

        let users =
            <BridgeService as pb::bridge_server::Bridge>::get_user_list(&service, Request::new(()))
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

        let users_after =
            <BridgeService as pb::bridge_server::Bridge>::get_user_list(&service, Request::new(()))
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
    async fn integration_restart_and_quit_signal_shutdown() {
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
