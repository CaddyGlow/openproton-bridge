use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::api::client::ProtonClient;
use crate::api::error::{is_auth_error, ApiError};
use crate::api::events as api_events;
use crate::api::messages;
use crate::api::types::{
    ApiMode, MessageFilter, MessageMetadata, Session, LABEL_TYPE_FOLDER, LABEL_TYPE_LABEL,
};
use crate::api::users;
use crate::bridge::auth_router::AuthRouter;
use crate::imap::mailbox;
use crate::imap::store::MessageStore;
use crate::pim::incremental as pim_incremental;
use crate::pim::store::PimStore;

use super::accounts::{
    AccountHealth, AccountRuntimeError, RuntimeAccountInfo, RuntimeAccountRegistry,
};
use super::types::{AccountId, EventCheckpoint, EventCheckpointStore};

#[derive(Debug, Default)]
pub struct InMemoryCheckpointStore {
    checkpoints: RwLock<HashMap<AccountId, EventCheckpoint>>,
}

impl InMemoryCheckpointStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventCheckpointStore for InMemoryCheckpointStore {
    type Error = ();

    fn load_checkpoint(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<Option<EventCheckpoint>, Self::Error> {
        let checkpoints = self.checkpoints.read().map_err(|_| ())?;
        Ok(checkpoints.get(account_id).cloned())
    }

    fn save_checkpoint(
        &self,
        account_id: &AccountId,
        checkpoint: &EventCheckpoint,
    ) -> std::result::Result<(), Self::Error> {
        let mut checkpoints = self.checkpoints.write().map_err(|_| ())?;
        checkpoints.insert(account_id.clone(), checkpoint.clone());
        Ok(())
    }
}

#[derive(Debug)]
pub struct FileCheckpointStore {
    path: PathBuf,
    checkpoints: RwLock<HashMap<AccountId, EventCheckpoint>>,
}

impl FileCheckpointStore {
    pub fn new(path: PathBuf) -> Self {
        let checkpoints = match Self::read_from_disk(&path) {
            Ok(checkpoints) => checkpoints,
            Err(()) => {
                warn!(
                    path = %path.display(),
                    "failed to load persisted event checkpoints, starting with empty state"
                );
                HashMap::new()
            }
        };
        Self {
            path,
            checkpoints: RwLock::new(checkpoints),
        }
    }

    fn read_from_disk(path: &Path) -> std::result::Result<HashMap<AccountId, EventCheckpoint>, ()> {
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let bytes = std::fs::read(path).map_err(|_| ())?;
        let decoded: HashMap<String, EventCheckpoint> =
            serde_json::from_slice(&bytes).map_err(|_| ())?;
        Ok(decoded
            .into_iter()
            .map(|(account_id, checkpoint)| (AccountId(account_id), checkpoint))
            .collect())
    }

    fn write_to_disk(
        path: &Path,
        checkpoints: &HashMap<AccountId, EventCheckpoint>,
    ) -> std::result::Result<(), ()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| ())?;
        }

        let encoded: HashMap<String, EventCheckpoint> = checkpoints
            .iter()
            .map(|(account_id, checkpoint)| (account_id.0.clone(), checkpoint.clone()))
            .collect();

        let payload = serde_json::to_vec_pretty(&encoded).map_err(|_| ())?;
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, payload).map_err(|_| ())?;
        std::fs::rename(&tmp_path, path).map_err(|_| ())?;
        Ok(())
    }
}

impl EventCheckpointStore for FileCheckpointStore {
    type Error = ();

    fn load_checkpoint(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<Option<EventCheckpoint>, Self::Error> {
        let checkpoints = self.checkpoints.read().map_err(|_| ())?;
        Ok(checkpoints.get(account_id).cloned())
    }

    fn save_checkpoint(
        &self,
        account_id: &AccountId,
        checkpoint: &EventCheckpoint,
    ) -> std::result::Result<(), Self::Error> {
        let snapshot = {
            let mut checkpoints = self.checkpoints.write().map_err(|_| ())?;
            checkpoints.insert(account_id.clone(), checkpoint.clone());
            checkpoints.clone()
        };
        Self::write_to_disk(&self.path, &snapshot)
    }
}

#[derive(Debug, Clone)]
pub struct VaultCheckpointStore {
    vault_dir: PathBuf,
}

impl VaultCheckpointStore {
    pub fn new(vault_dir: PathBuf) -> Self {
        Self { vault_dir }
    }
}

impl EventCheckpointStore for VaultCheckpointStore {
    type Error = ();

    fn load_checkpoint(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<Option<EventCheckpoint>, Self::Error> {
        let loaded =
            crate::vault::load_event_checkpoint_by_account_id(&self.vault_dir, &account_id.0)
                .map_err(|_| ())?;
        Ok(loaded.map(|checkpoint| EventCheckpoint {
            last_event_id: checkpoint.last_event_id,
            last_event_ts: checkpoint.last_event_ts,
            sync_state: checkpoint.sync_state,
        }))
    }

    fn save_checkpoint(
        &self,
        account_id: &AccountId,
        checkpoint: &EventCheckpoint,
    ) -> std::result::Result<(), Self::Error> {
        crate::vault::save_event_checkpoint_by_account_id(
            &self.vault_dir,
            &account_id.0,
            &crate::vault::StoredEventCheckpoint {
                last_event_id: checkpoint.last_event_id.clone(),
                last_event_ts: checkpoint.last_event_ts,
                sync_state: checkpoint.sync_state.clone(),
            },
        )
        .map_err(|_| ())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventWorkerError {
    #[error("runtime account error: {0}")]
    Account(#[from] AccountRuntimeError),
    #[error("api error: {0}")]
    Api(#[from] ApiError),
    #[error("checkpoint store error")]
    Checkpoint,
    #[error("event payload error: {0}")]
    Payload(String),
}

pub type SharedCheckpointStore = Arc<dyn EventCheckpointStore<Error = ()> + Send + Sync>;
const RESYNC_PAGE_SIZE: i32 = 150;
const MAX_EVENT_PAGES_PER_POLL: usize = 50;
const REFRESH_MAIL_FLAG: i32 = 1;
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(300);
const WORKER_STATS_LOG_EVERY_ATTEMPTS: u64 = 20;
const MAX_INITIAL_POLL_STAGGER_MS: u64 = 2_000;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncProgressUpdate {
    Started {
        user_id: String,
    },
    Progress {
        user_id: String,
        progress: f64,
        elapsed_ms: i64,
        remaining_ms: i64,
    },
    Finished {
        user_id: String,
    },
}

pub type SyncProgressCallback = Arc<dyn Fn(SyncProgressUpdate) + Send + Sync>;

pub struct EventWorkerGroup {
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
}

impl EventWorkerGroup {
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let shutdown_deadline = Instant::now() + Duration::from_secs(2);
        let handles = self.handles;

        while Instant::now() < shutdown_deadline {
            if handles.iter().all(|handle| handle.is_finished()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        for handle in &handles {
            if !handle.is_finished() {
                handle.abort();
            }
        }

        for handle in handles {
            let _ = handle.await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerFailureClass {
    Auth,
    Transient,
    Permanent,
}

#[derive(Debug, Default)]
struct EventWorkerStats {
    poll_attempts: u64,
    successful_polls: u64,
    failed_polls: u64,
    auth_failures: u64,
    transient_failures: u64,
    permanent_failures: u64,
    last_success_ts: Option<i64>,
    last_failure_ts: Option<i64>,
}

impl EventWorkerStats {
    fn record_success(&mut self, ts: i64) {
        self.poll_attempts = self.poll_attempts.saturating_add(1);
        self.successful_polls = self.successful_polls.saturating_add(1);
        self.last_success_ts = Some(ts);
    }

    fn record_failure(&mut self, class: WorkerFailureClass, ts: i64) {
        self.poll_attempts = self.poll_attempts.saturating_add(1);
        self.failed_polls = self.failed_polls.saturating_add(1);
        self.last_failure_ts = Some(ts);
        match class {
            WorkerFailureClass::Auth => {
                self.auth_failures = self.auth_failures.saturating_add(1);
            }
            WorkerFailureClass::Transient => {
                self.transient_failures = self.transient_failures.saturating_add(1);
            }
            WorkerFailureClass::Permanent => {
                self.permanent_failures = self.permanent_failures.saturating_add(1);
            }
        }
    }
}

fn classify_worker_failure_class(error: &EventWorkerError) -> WorkerFailureClass {
    match error {
        EventWorkerError::Account(AccountRuntimeError::AccountUnavailable(_)) => {
            WorkerFailureClass::Auth
        }
        EventWorkerError::Account(AccountRuntimeError::Api(err)) if is_auth_error(err) => {
            WorkerFailureClass::Auth
        }
        EventWorkerError::Api(err) if is_auth_error(err) => WorkerFailureClass::Auth,
        EventWorkerError::Account(AccountRuntimeError::AccountNotFound(_)) => {
            WorkerFailureClass::Permanent
        }
        EventWorkerError::Account(AccountRuntimeError::Vault(_))
        | EventWorkerError::Checkpoint
        | EventWorkerError::Payload(_) => WorkerFailureClass::Permanent,
        _ => WorkerFailureClass::Transient,
    }
}

fn classify_worker_health(error: &EventWorkerError) -> Option<AccountHealth> {
    match classify_worker_failure_class(error) {
        WorkerFailureClass::Auth => Some(AccountHealth::Unavailable),
        WorkerFailureClass::Permanent => match error {
            EventWorkerError::Account(AccountRuntimeError::AccountNotFound(_)) => None,
            _ => Some(AccountHealth::Degraded),
        },
        WorkerFailureClass::Transient => Some(AccountHealth::Degraded),
    }
}

fn compute_failure_delay(
    poll_interval: Duration,
    consecutive_failures: u32,
    jitter_ms: u64,
) -> Duration {
    let exp = consecutive_failures.saturating_sub(1).min(4);
    let factor = 1u32 << exp;
    let base_delay = poll_interval
        .saturating_mul(factor)
        .min(MAX_FAILURE_BACKOFF);
    base_delay + Duration::from_millis(jitter_ms.min(500))
}

fn compute_initial_poll_stagger(account_id: &AccountId, poll_interval: Duration) -> Duration {
    if poll_interval.is_zero() {
        return Duration::ZERO;
    }

    let max_stagger_ms = (poll_interval
        .as_millis()
        .min(MAX_INITIAL_POLL_STAGGER_MS as u128)) as u64;
    if max_stagger_ms == 0 {
        return Duration::ZERO;
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    account_id.0.hash(&mut hasher);
    let stagger_ms = hasher.finish() % (max_stagger_ms + 1);
    Duration::from_millis(stagger_ms)
}

#[derive(Clone)]
pub struct EventWorkerConfig {
    pub account_id: AccountId,
    pub account_email: String,
    pub api_base_url: String,
    pub runtime_accounts: Arc<RuntimeAccountRegistry>,
    pub auth_router: AuthRouter,
    pub store: Arc<dyn MessageStore>,
    pub pim_store: Option<Arc<PimStore>>,
    pub checkpoint_store: SharedCheckpointStore,
    pub sync_progress_callback: Option<SyncProgressCallback>,
}

impl EventWorkerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        account_email: String,
        api_base_url: String,
        runtime_accounts: Arc<RuntimeAccountRegistry>,
        auth_router: AuthRouter,
        store: Arc<dyn MessageStore>,
        checkpoint_store: SharedCheckpointStore,
    ) -> Self {
        Self {
            account_id,
            account_email,
            api_base_url,
            runtime_accounts,
            auth_router,
            store,
            pim_store: None,
            checkpoint_store,
            sync_progress_callback: None,
        }
    }

    pub fn with_pim_store(mut self, store: Arc<PimStore>) -> Self {
        self.pim_store = Some(store);
        self
    }

    pub fn with_sync_progress_callback(mut self, callback: SyncProgressCallback) -> Self {
        self.sync_progress_callback = Some(callback);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventDelta {
    MessageUpsert(String),
    MessageDelete(String),
    LabelsChanged,
    AddressesChanged,
}

const EVENT_ACTION_DELETE: i64 = 0;

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn scoped_mailbox_name(account_id: &AccountId, mailbox_name: &str) -> String {
    format!("{}::{}", account_id.0, mailbox_name)
}

fn redacted_subject_for_log(subject: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    subject.hash(&mut hasher);
    format!("******** ({:08x})", (hasher.finish() & 0xffff_ffff) as u32)
}

fn has_mail_refresh_flag(refresh: i32) -> bool {
    refresh & REFRESH_MAIL_FLAG != 0
}

fn format_ids_for_update(ids: &[String]) -> String {
    ids.join(" ")
}

fn format_flags_for_update(metadata: &MessageMetadata) -> String {
    mailbox::message_flags(metadata).join(" ")
}

async fn message_exists_in_store(
    config: &EventWorkerConfig,
    message_id: &str,
    expected_generation: u64,
) -> Result<bool, EventWorkerError> {
    for mb in mailbox::system_mailboxes() {
        if !mb.selectable {
            continue;
        }
        ensure_account_generation(config, expected_generation, "message_exists_in_store").await?;
        let scoped = scoped_mailbox_name(&config.account_id, mb.name);
        let uid = config
            .store
            .get_uid(&scoped, message_id)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        if uid.is_some() {
            return Ok(true);
        }
    }

    Ok(false)
}

fn extract_message_id(value: &serde_json::Value, fallback_key: Option<&str>) -> Option<String> {
    if let Some(id) = value.get("ID").and_then(|v| v.as_str()) {
        return Some(id.to_string());
    }
    if fallback_key.is_none() {
        if let Some(id) = value.as_str() {
            return Some(id.to_string());
        }
    }
    fallback_key.map(str::to_string)
}

fn is_delete_action(
    value: &serde_json::Value,
    fallback_action_source: Option<&serde_json::Value>,
) -> bool {
    if let Some(code) = value.as_i64() {
        return code == EVENT_ACTION_DELETE;
    }
    if let Some(name) = value.as_str() {
        if name.trim() == "0" {
            return true;
        }
        let name = name.to_ascii_lowercase();
        if name.contains("delete") || name.contains("remove") {
            return true;
        }
    }

    if value
        .get("Deleted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return true;
    }
    if value
        .get("Delete")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(action) = value
        .get("Action")
        .or_else(|| fallback_action_source.and_then(|v| v.get("Action")))
    {
        if let Some(code) = action.as_i64() {
            return code == EVENT_ACTION_DELETE;
        }
        if let Some(name) = action.as_str() {
            if name.trim() == "0" {
                return true;
            }
            let name = name.to_ascii_lowercase();
            return name.contains("delete") || name.contains("remove");
        }
    }
    false
}

fn push_typed_message_delta(
    item: &crate::api::types::TypedEventItem,
    fallback_id: Option<&str>,
    payload: &serde_json::Value,
    out: &mut Vec<EventDelta>,
) {
    let message_id = if item.id.is_empty() {
        fallback_id.unwrap_or_default().to_string()
    } else {
        item.id.clone()
    };
    if message_id.is_empty() {
        return;
    }

    let mut entry_fields = serde_json::Map::new();
    entry_fields.insert(
        "ID".to_string(),
        serde_json::Value::String(message_id.clone()),
    );
    if let Some(action) = item.action.clone() {
        entry_fields.insert("Action".to_string(), action);
    }
    for (key, value) in &item.extra {
        entry_fields.insert(key.clone(), value.clone());
    }
    let entry = serde_json::Value::Object(entry_fields);

    if is_delete_action(&entry, Some(payload)) {
        out.push(EventDelta::MessageDelete(message_id));
    } else {
        out.push(EventDelta::MessageUpsert(message_id));
    }
}

fn parse_typed_event_deltas(payload: &serde_json::Value) -> Option<Vec<EventDelta>> {
    let typed = api_events::parse_typed_event_payload(payload)?;
    if !typed.has_recognized_event_fields() {
        return None;
    }

    let mut out = Vec::new();

    if let Some(messages) = typed.messages.as_ref() {
        for item in messages {
            push_typed_message_delta(item, None, payload, &mut out);
        }
    }

    if let Some(message) = typed.message.as_ref() {
        let fallback_id = payload.get("ID").and_then(|value| value.as_str());
        push_typed_message_delta(message, fallback_id, payload, &mut out);
    }

    if typed.labels.is_some() || typed.label.is_some() {
        out.push(EventDelta::LabelsChanged);
    }

    if typed.addresses.is_some() || typed.address.is_some() {
        out.push(EventDelta::AddressesChanged);
    }

    Some(out)
}

fn parse_message_deltas_heuristic(payload: &serde_json::Value, out: &mut Vec<EventDelta>) {
    let mut push_message_delta =
        |entry: &serde_json::Value,
         fallback_key: Option<&str>,
         fallback_action_source: Option<&serde_json::Value>| {
            let Some(message_id) = extract_message_id(entry, fallback_key) else {
                return;
            };
            if fallback_key.is_some() && entry.is_null() {
                out.push(EventDelta::MessageDelete(message_id));
                return;
            }
            if is_delete_action(entry, fallback_action_source) {
                out.push(EventDelta::MessageDelete(message_id));
            } else {
                out.push(EventDelta::MessageUpsert(message_id));
            }
        };

    if let Some(messages) = payload.get("Messages") {
        if let Some(array) = messages.as_array() {
            for entry in array {
                push_message_delta(entry, None, Some(payload));
            }
        } else if let Some(object) = messages.as_object() {
            for (message_id, entry) in object {
                push_message_delta(entry, Some(message_id), Some(payload));
            }
        }
    }

    if let Some(message) = payload.get("Message") {
        if message.is_object() {
            let fallback_id = payload.get("ID").and_then(|v| v.as_str());
            push_message_delta(message, fallback_id, Some(payload));
        }
    }
}

fn parse_event_deltas_heuristic(payload: &serde_json::Value) -> Vec<EventDelta> {
    let mut out = Vec::new();
    parse_message_deltas_heuristic(payload, &mut out);

    if payload.get("Labels").is_some() || payload.get("Label").is_some() {
        out.push(EventDelta::LabelsChanged);
    }

    if payload.get("Addresses").is_some() || payload.get("Address").is_some() {
        out.push(EventDelta::AddressesChanged);
    }

    out
}

fn parse_event_deltas(payload: &serde_json::Value) -> Vec<EventDelta> {
    if let Some(deltas) = parse_typed_event_deltas(payload) {
        return deltas;
    }
    parse_event_deltas_heuristic(payload)
}

fn is_invalid_event_cursor_error(error: &ApiError) -> bool {
    let ApiError::Api { message, .. } = error else {
        return false;
    };

    let normalized = message.to_ascii_lowercase();
    normalized.contains("event")
        && normalized.contains("id")
        && (normalized.contains("invalid")
            || normalized.contains("not found")
            || normalized.contains("unknown")
            || normalized.contains("gone")
            || normalized.contains("expired"))
}

fn resolve_api_base_url_for_mode(configured_base_url: &str, api_mode: ApiMode) -> String {
    if matches!(api_mode, ApiMode::Webmail) && configured_base_url == ApiMode::Bridge.base_url() {
        ApiMode::Webmail.base_url().to_string()
    } else {
        configured_base_url.to_string()
    }
}

async fn ensure_account_generation(
    config: &EventWorkerConfig,
    expected_generation: u64,
    stage: &'static str,
) -> Result<(), EventWorkerError> {
    let generation_is_current = config
        .runtime_accounts
        .is_runtime_generation_current(&config.account_id, expected_generation)
        .await?;
    match config
        .runtime_accounts
        .ensure_runtime_generation(&config.account_id, expected_generation)
        .await
    {
        Ok(()) => Ok(()),
        Err(AccountRuntimeError::AccountUnavailable(_)) => {
            if !generation_is_current {
                let current_generation = config
                    .runtime_accounts
                    .runtime_generation(&config.account_id)
                    .await
                    .unwrap_or(expected_generation);
                info!(
                    account_id = %config.account_id.0,
                    account_email = %config.account_email,
                    stage,
                    expected_generation,
                    current_generation,
                    "ignored stale account worker success due to runtime generation mismatch"
                );
            } else {
                info!(
                    account_id = %config.account_id.0,
                    account_email = %config.account_email,
                    stage,
                    expected_generation,
                    "account runtime became unavailable; canceling account-scoped work"
                );
            }
            Err(EventWorkerError::Account(
                AccountRuntimeError::AccountUnavailable(config.account_id.0.clone()),
            ))
        }
        Err(err) => Err(EventWorkerError::Account(err)),
    }
}

async fn build_client_with_retry(
    config: &EventWorkerConfig,
    session: &mut Session,
    stale_access_token: Option<&str>,
) -> Result<ProtonClient, EventWorkerError> {
    *session = config
        .runtime_accounts
        .refresh_session_if_stale(&config.account_id, stale_access_token)
        .await?;
    let base_url = resolve_api_base_url_for_mode(&config.api_base_url, session.api_mode);
    Ok(ProtonClient::authenticated_with_mode(
        &base_url,
        session.api_mode,
        &session.uid,
        &session.access_token,
    )?)
}

async fn fetch_events_with_retry(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
    event_id: &str,
) -> Result<crate::api::types::EventsResponse, EventWorkerError> {
    match api_events::get_events(client, event_id).await {
        Ok(resp) => Ok(resp),
        Err(err) if is_auth_error(&err) => {
            let stale_token = session.access_token.clone();
            *client = build_client_with_retry(config, session, Some(&stale_token)).await?;
            Ok(api_events::get_events(client, event_id).await?)
        }
        Err(err) => Err(err.into()),
    }
}

async fn fetch_message_metadata_with_retry(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
    message_id: &str,
) -> Result<MessageMetadata, EventWorkerError> {
    match messages::get_message(client, message_id).await {
        Ok(resp) => Ok(resp.message.metadata),
        Err(err) if is_auth_error(&err) => {
            let stale_token = session.access_token.clone();
            *client = build_client_with_retry(config, session, Some(&stale_token)).await?;
            Ok(messages::get_message(client, message_id)
                .await?
                .message
                .metadata)
        }
        Err(err) => Err(err.into()),
    }
}

async fn fetch_message_metadata_page_with_retry(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
    filter: &MessageFilter,
    page: i32,
    page_size: i32,
) -> Result<Vec<MessageMetadata>, EventWorkerError> {
    match messages::get_message_metadata(client, filter, page, page_size).await {
        Ok(resp) => Ok(resp.messages),
        Err(err) if is_auth_error(&err) => {
            let stale_token = session.access_token.clone();
            *client = build_client_with_retry(config, session, Some(&stale_token)).await?;
            Ok(
                messages::get_message_metadata(client, filter, page, page_size)
                    .await?
                    .messages,
            )
        }
        Err(err) => Err(err.into()),
    }
}

async fn refresh_address_index_with_retry(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "refresh_address_index_fetch").await?;
    let addresses = match users::get_addresses(client).await {
        Ok(resp) => resp,
        Err(err) if is_auth_error(&err) => {
            let stale_token = session.access_token.clone();
            *client = build_client_with_retry(config, session, Some(&stale_token)).await?;
            users::get_addresses(client).await?
        }
        Err(err) => return Err(err.into()),
    };

    let emails: Vec<String> = addresses
        .addresses
        .into_iter()
        .filter(|addr| addr.status == 1)
        .map(|addr| addr.email)
        .collect();

    ensure_account_generation(config, expected_generation, "refresh_address_index_commit").await?;
    let _ = config
        .auth_router
        .set_account_addresses(&config.account_id, emails);
    Ok(())
}

async fn apply_message_upsert(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
    message_id: &str,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    let already_present = message_exists_in_store(config, message_id, expected_generation).await?;
    let metadata = fetch_message_metadata_with_retry(config, session, client, message_id).await?;
    let subject = redacted_subject_for_log(&metadata.subject);
    let mailbox_ids = format_ids_for_update(&metadata.label_ids);
    let flags = format_flags_for_update(&metadata);

    if already_present {
        info!(
            service = "imap",
            user = %config.account_id.0,
            messageID = %metadata.id,
            subject = %subject,
            msg = "Handling message updated event",
            "Handling message updated event"
        );
        debug!(
            pkg = "gluon/user",
            userID = %config.account_id.0,
            update = format!(
                "MessageMailboxesUpdated: MessageID = {}, MailboxIDs = [{}], Flags = [{}]",
                metadata.id, mailbox_ids, flags
            ),
            msg = "Applying update",
            "Applying update"
        );
    } else {
        info!(
            date = metadata.time,
            service = "imap",
            user = %config.account_id.0,
            messageID = %metadata.id,
            subject = %subject,
            msg = "Handling message created event",
            "Handling message created event"
        );
        debug!(
            pkg = "gluon/user",
            userID = %config.account_id.0,
            update = format!(
                "MessagesCreated: MessageCount=1 Messages=[ID:{} Mailboxes:[{}] Flags:[{}]]",
                metadata.id, mailbox_ids, flags
            ),
            msg = "Applying update",
            "Applying update"
        );
    }

    apply_metadata_to_store(config, &metadata, expected_generation).await
}

async fn apply_metadata_to_store(
    config: &EventWorkerConfig,
    metadata: &MessageMetadata,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "apply_metadata_to_store").await?;
    for mb in mailbox::system_mailboxes() {
        if !mb.selectable {
            continue;
        }
        ensure_account_generation(config, expected_generation, "apply_metadata_to_store").await?;
        let scoped = scoped_mailbox_name(&config.account_id, mb.name);
        let in_mailbox = metadata.label_ids.iter().any(|label| label == mb.label_id);
        if in_mailbox {
            config
                .store
                .store_metadata(&scoped, &metadata.id, metadata.clone())
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        } else if let Some(uid) = config
            .store
            .get_uid(&scoped, &metadata.id)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        {
            config
                .store
                .remove_message(&scoped, uid)
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        }
    }

    let user_labels = config.runtime_accounts.get_user_labels(&config.account_id);
    for ul in &user_labels {
        let scoped = scoped_mailbox_name(&config.account_id, &ul.name);
        let in_mailbox = metadata.label_ids.iter().any(|label| label == &ul.label_id);
        if in_mailbox {
            config
                .store
                .store_metadata(&scoped, &metadata.id, metadata.clone())
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        } else if let Some(uid) = config
            .store
            .get_uid(&scoped, &metadata.id)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        {
            config
                .store
                .remove_message(&scoped, uid)
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        }
    }

    Ok(())
}

async fn migrate_label_mailbox_data(
    config: &EventWorkerConfig,
    from_mailbox: &str,
    to_mailbox: &str,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "migrate_label_mailbox_data").await?;

    if from_mailbox.eq_ignore_ascii_case(to_mailbox) {
        return Ok(());
    }

    let from_scoped = scoped_mailbox_name(&config.account_id, from_mailbox);
    let to_scoped = scoped_mailbox_name(&config.account_id, to_mailbox);
    let uids = config
        .store
        .list_uids(&from_scoped)
        .await
        .map_err(|e| EventWorkerError::Payload(e.to_string()))?;

    for uid in &uids {
        let Some(proton_id) = config
            .store
            .get_proton_id(&from_scoped, *uid)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        else {
            continue;
        };
        let Some(metadata) = config
            .store
            .get_metadata(&from_scoped, *uid)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        else {
            continue;
        };

        let new_uid = config
            .store
            .store_metadata(&to_scoped, &proton_id, metadata)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        let flags = config
            .store
            .get_flags(&from_scoped, *uid)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        config
            .store
            .set_flags(&to_scoped, new_uid, flags)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        if let Some(rfc822) = config
            .store
            .get_rfc822(&from_scoped, *uid)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        {
            config
                .store
                .store_rfc822(&to_scoped, new_uid, rfc822)
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        }
    }

    for uid in uids {
        config
            .store
            .remove_message(&from_scoped, uid)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
    }

    Ok(())
}

async fn clear_label_mailbox_data(
    config: &EventWorkerConfig,
    mailbox_name: &str,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "clear_label_mailbox_data").await?;
    let scoped = scoped_mailbox_name(&config.account_id, mailbox_name);
    let uids = config
        .store
        .list_uids(&scoped)
        .await
        .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
    for uid in uids {
        config
            .store
            .remove_message(&scoped, uid)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
    }
    Ok(())
}

async fn reconcile_user_label_topology(
    config: &EventWorkerConfig,
    previous_labels: &[mailbox::ResolvedMailbox],
    next_labels: &[mailbox::ResolvedMailbox],
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    let previous_by_id: HashMap<&str, &mailbox::ResolvedMailbox> = previous_labels
        .iter()
        .map(|label| (label.label_id.as_str(), label))
        .collect();
    let next_by_id: HashMap<&str, &mailbox::ResolvedMailbox> = next_labels
        .iter()
        .map(|label| (label.label_id.as_str(), label))
        .collect();

    for (label_id, previous) in &previous_by_id {
        if let Some(next) = next_by_id.get(label_id) {
            if !previous.name.eq_ignore_ascii_case(&next.name) {
                migrate_label_mailbox_data(config, &previous.name, &next.name, expected_generation)
                    .await?;
            }
        } else {
            clear_label_mailbox_data(config, &previous.name, expected_generation).await?;
        }
    }

    Ok(())
}

async fn fetch_and_update_user_labels(
    config: &EventWorkerConfig,
    client: &ProtonClient,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    let resp = messages::get_labels(client, &[LABEL_TYPE_LABEL, LABEL_TYPE_FOLDER]).await?;
    let resolved = mailbox::labels_to_mailboxes(&resp.labels);
    let previous = config.runtime_accounts.get_user_labels(&config.account_id);
    reconcile_user_label_topology(config, &previous, &resolved, expected_generation).await?;
    info!(
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        user_labels = resolved.len(),
        "refreshed user labels for event sync"
    );
    config
        .runtime_accounts
        .set_user_labels(&config.account_id, resolved);
    Ok(())
}

struct SyncProgressRunGuard<'a> {
    callback: Option<&'a SyncProgressCallback>,
    user_id: String,
    finished_emitted: bool,
}

impl<'a> SyncProgressRunGuard<'a> {
    fn new(callback: Option<&'a SyncProgressCallback>, user_id: String) -> Self {
        if let Some(callback) = callback {
            callback(SyncProgressUpdate::Started {
                user_id: user_id.clone(),
            });
        }
        Self {
            callback,
            user_id,
            finished_emitted: false,
        }
    }

    fn finish(&mut self) {
        if self.finished_emitted {
            return;
        }
        if let Some(callback) = self.callback {
            callback(SyncProgressUpdate::Finished {
                user_id: self.user_id.clone(),
            });
        }
        self.finished_emitted = true;
    }
}

impl Drop for SyncProgressRunGuard<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
async fn bounded_resync_account(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
) -> Result<(), EventWorkerError> {
    let expected_generation = config
        .runtime_accounts
        .runtime_generation(&config.account_id)
        .await?;
    bounded_resync_account_for_generation(config, session, client, expected_generation).await
}

async fn bounded_resync_account_for_generation(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "bounded_resync_start").await?;
    let resync_started_at = Instant::now();
    let sync_start = unix_now();

    let duration = resync_started_at.elapsed();
    info!(
        service = "imap",
        user = %config.account_id.0,
        user_id = %config.account_id.0,
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        start = sync_start,
        start_unix = sync_start,
        duration = ?duration,
        duration_ms = duration.as_millis() as u64,
        msg = "Sync triggered",
        "Sync triggered"
    );
    let duration = resync_started_at.elapsed();
    info!(
        service = "imap",
        user = %config.account_id.0,
        user_id = %config.account_id.0,
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        start = sync_start,
        start_unix = sync_start,
        duration = ?duration,
        duration_ms = duration.as_millis() as u64,
        msg = "Beginning user sync",
        "Beginning user sync"
    );
    let mut progress_guard = SyncProgressRunGuard::new(
        config.sync_progress_callback.as_ref(),
        config.account_id.0.clone(),
    );

    let duration = resync_started_at.elapsed();
    info!(
        service = "imap",
        user = %config.account_id.0,
        user_id = %config.account_id.0,
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        start = sync_start,
        start_unix = sync_start,
        duration = ?duration,
        duration_ms = duration.as_millis() as u64,
        msg = "Syncing labels",
        "Syncing labels"
    );
    let duration = resync_started_at.elapsed();
    info!(
        service = "imap",
        user = %config.account_id.0,
        user_id = %config.account_id.0,
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        start = sync_start,
        start_unix = sync_start,
        duration = ?duration,
        duration_ms = duration.as_millis() as u64,
        msg = "Synced labels",
        "Synced labels"
    );
    let duration = resync_started_at.elapsed();
    info!(
        service = "imap",
        user = %config.account_id.0,
        user_id = %config.account_id.0,
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        start = sync_start,
        start_unix = sync_start,
        duration = ?duration,
        duration_ms = duration.as_millis() as u64,
        msg = "Syncing messages",
        "Syncing messages"
    );

    let mut total_steps = mailbox::system_mailboxes()
        .iter()
        .filter(|mb| mb.selectable)
        .count()
        .max(1);
    let mut completed_steps = 0usize;
    let mut synced_message_ids = HashSet::new();
    let mut total_applied = 0usize;

    for mb in mailbox::system_mailboxes() {
        if !mb.selectable {
            continue;
        }
        ensure_account_generation(config, expected_generation, "bounded_resync_mailbox").await?;

        let mut end_id: Option<String> = None;
        loop {
            ensure_account_generation(config, expected_generation, "bounded_resync_page").await?;
            let request_phase = if end_id.is_some() {
                "continuation"
            } else {
                "mailbox_start"
            };
            info!(
                account_id = %config.account_id.0,
                account_email = %config.account_email,
                mailbox = %mb.name,
                label_id = %mb.label_id,
                phase = request_phase,
                end_id = end_id.as_deref().unwrap_or_default(),
                page_size = RESYNC_PAGE_SIZE,
                "resync mailbox metadata request"
            );
            let filter = MessageFilter {
                label_id: Some(mb.label_id.to_string()),
                end_id: end_id.clone(),
                desc: 1,
                ..Default::default()
            };
            let messages = fetch_message_metadata_page_with_retry(
                config,
                session,
                client,
                &filter,
                0,
                RESYNC_PAGE_SIZE,
            )
            .await?;

            completed_steps = completed_steps.saturating_add(1);
            let page_count = messages.len() as i32;
            let next_end_id = messages.last().map(|metadata| metadata.id.as_str());
            info!(
                account_id = %config.account_id.0,
                account_email = %config.account_email,
                mailbox = %mb.name,
                label_id = %mb.label_id,
                phase = request_phase,
                end_id = end_id.as_deref().unwrap_or_default(),
                messages_count = messages.len(),
                first_message_id = ?messages.first().map(|metadata| metadata.id.as_str()),
                last_message_id = ?next_end_id,
                "resync mailbox metadata page"
            );
            if page_count == RESYNC_PAGE_SIZE {
                total_steps = total_steps.saturating_add(1);
            }
            emit_sync_progress(
                config,
                completed_steps,
                total_steps,
                resync_started_at.elapsed(),
            );

            if messages.is_empty() {
                break;
            }

            end_id = next_end_id.map(str::to_string);

            for metadata in messages {
                if synced_message_ids.insert(metadata.id.clone()) {
                    apply_metadata_to_store(config, &metadata, expected_generation).await?;
                    total_applied += 1;
                }
            }

            if page_count < RESYNC_PAGE_SIZE {
                break;
            }

            if end_id.is_none() {
                warn!(
                    account_id = %config.account_id.0,
                    account_email = %config.account_email,
                    label_id = %mb.label_id,
                    "resync page was full but did not contain a terminal message id; stopping mailbox pagination"
                );
                break;
            }
        }
    }

    debug!(
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        total_applied,
        "completed refresh resync"
    );

    emit_sync_progress(
        config,
        total_steps,
        total_steps,
        resync_started_at.elapsed(),
    );
    progress_guard.finish();

    let duration = resync_started_at.elapsed();
    if total_applied == 0 {
        info!(
            service = "imap",
            user = %config.account_id.0,
            user_id = %config.account_id.0,
            account_id = %config.account_id.0,
            account_email = %config.account_email,
            start = sync_start,
            start_unix = sync_start,
            duration = ?duration,
            duration_ms = duration.as_millis() as u64,
            msg = "Messages are already synced, skipping",
            "Messages are already synced, skipping"
        );
    } else {
        info!(
            service = "imap",
            user = %config.account_id.0,
            user_id = %config.account_id.0,
            account_id = %config.account_id.0,
            account_email = %config.account_email,
            start = sync_start,
            start_unix = sync_start,
            duration = ?duration,
            duration_ms = duration.as_millis() as u64,
            msg = "Synced messages",
            "Synced messages"
        );
    }

    let duration = resync_started_at.elapsed();
    info!(
        service = "imap",
        user = %config.account_id.0,
        user_id = %config.account_id.0,
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        start = sync_start,
        start_unix = sync_start,
        duration = ?duration,
        duration_ms = duration.as_millis() as u64,
        msg = "Finished user sync",
        "Finished user sync"
    );

    Ok(())
}

fn emit_sync_progress(
    config: &EventWorkerConfig,
    completed_steps: usize,
    total_steps: usize,
    elapsed: Duration,
) {
    let Some(callback) = config.sync_progress_callback.as_ref() else {
        return;
    };

    let total = total_steps.max(1) as f64;
    let progress = (completed_steps as f64 / total).clamp(0.0, 1.0);
    let elapsed_ms = elapsed.as_millis().min(i64::MAX as u128) as i64;
    let remaining_ms = if progress > 0.0 && progress < 1.0 {
        ((elapsed_ms as f64) * ((1.0 - progress) / progress))
            .round()
            .clamp(0.0, i64::MAX as f64) as i64
    } else {
        0
    };

    callback(SyncProgressUpdate::Progress {
        user_id: config.account_id.0.clone(),
        progress,
        elapsed_ms,
        remaining_ms,
    });
}

async fn apply_message_delete(
    config: &EventWorkerConfig,
    message_id: &str,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "apply_message_delete").await?;
    for mb in mailbox::system_mailboxes() {
        let scoped = scoped_mailbox_name(&config.account_id, mb.name);
        if let Some(uid) = config
            .store
            .get_uid(&scoped, message_id)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        {
            config
                .store
                .remove_message(&scoped, uid)
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        }
    }
    for label_mailbox in config.runtime_accounts.get_user_labels(&config.account_id) {
        let scoped = scoped_mailbox_name(&config.account_id, &label_mailbox.name);
        if let Some(uid) = config
            .store
            .get_uid(&scoped, message_id)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
        {
            config
                .store
                .remove_message(&scoped, uid)
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
        }
    }
    Ok(())
}

async fn run_startup_resync_for_generation(
    config: &EventWorkerConfig,
    expected_generation: u64,
) -> Result<(), EventWorkerError> {
    ensure_account_generation(config, expected_generation, "startup_resync_init").await?;
    let mut session = config
        .runtime_accounts
        .with_valid_access_token(&config.account_id)
        .await?;

    let base_url = resolve_api_base_url_for_mode(&config.api_base_url, session.api_mode);
    let mut client = ProtonClient::authenticated_with_mode(
        &base_url,
        session.api_mode,
        &session.uid,
        &session.access_token,
    )?;

    info!(
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        "running startup bounded resync"
    );
    bounded_resync_account_for_generation(config, &mut session, &mut client, expected_generation)
        .await
}

async fn cached_message_count_for_generation(
    config: &EventWorkerConfig,
    expected_generation: u64,
) -> Result<u64, EventWorkerError> {
    ensure_account_generation(config, expected_generation, "cached_message_count").await?;
    let mut total = 0u64;

    for mb in mailbox::system_mailboxes() {
        if !mb.selectable {
            continue;
        }

        let scoped = scoped_mailbox_name(&config.account_id, mb.name);
        let count = config
            .store
            .list_uids(&scoped)
            .await
            .map_err(|e| EventWorkerError::Payload(e.to_string()))?
            .len() as u64;
        total = total.saturating_add(count);

        if total > 0 {
            break;
        }
    }

    Ok(total)
}

async fn bootstrap_latest_event_cursor_for_generation(
    config: &EventWorkerConfig,
    expected_generation: u64,
) -> Result<String, EventWorkerError> {
    ensure_account_generation(config, expected_generation, "startup_cursor_init").await?;
    let mut session = config
        .runtime_accounts
        .with_valid_access_token(&config.account_id)
        .await?;

    let base_url = resolve_api_base_url_for_mode(&config.api_base_url, session.api_mode);
    let mut client = ProtonClient::authenticated_with_mode(
        &base_url,
        session.api_mode,
        &session.uid,
        &session.access_token,
    )?;

    info!(
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        "bootstrapping baseline event cursor from cached message store"
    );
    let response = fetch_events_with_retry(config, &mut session, &mut client, "").await?;
    let event_id = response.event_id.trim().to_string();
    if event_id.is_empty() {
        return Err(EventWorkerError::Payload(
            "latest event cursor bootstrap returned empty event id".to_string(),
        ));
    }

    ensure_account_generation(config, expected_generation, "startup_cursor_commit").await?;
    let checkpoint = EventCheckpoint {
        last_event_id: event_id.clone(),
        last_event_ts: Some(unix_now()),
        sync_state: Some("baseline_cursor".to_string()),
    };
    config
        .checkpoint_store
        .save_checkpoint(&config.account_id, &checkpoint)
        .map_err(|_| EventWorkerError::Checkpoint)?;

    Ok(event_id)
}

pub async fn poll_account_once(
    config: &EventWorkerConfig,
    last_event_id: &str,
) -> Result<String, EventWorkerError> {
    let expected_generation = config
        .runtime_accounts
        .runtime_generation(&config.account_id)
        .await?;
    poll_account_once_for_generation(config, last_event_id, expected_generation).await
}

async fn poll_account_once_for_generation(
    config: &EventWorkerConfig,
    last_event_id: &str,
    expected_generation: u64,
) -> Result<String, EventWorkerError> {
    ensure_account_generation(config, expected_generation, "poll_init").await?;
    let mut session = config
        .runtime_accounts
        .with_valid_access_token(&config.account_id)
        .await?;

    let base_url = resolve_api_base_url_for_mode(&config.api_base_url, session.api_mode);
    let mut client = ProtonClient::authenticated_with_mode(
        &base_url,
        session.api_mode,
        &session.uid,
        &session.access_token,
    )?;

    let mut cursor = last_event_id.to_string();
    let mut pages = 0usize;

    loop {
        ensure_account_generation(config, expected_generation, "poll_loop").await?;
        pages += 1;
        if pages > MAX_EVENT_PAGES_PER_POLL {
            warn!(
                account_id = %config.account_id.0,
                account_email = %config.account_email,
                "event poll reached page safety limit"
            );
            break;
        }

        let mut forced_sync_state: Option<&str> = None;
        let response =
            match fetch_events_with_retry(config, &mut session, &mut client, &cursor).await {
                Ok(response) => response,
                Err(EventWorkerError::Api(error))
                    if !cursor.trim().is_empty() && is_invalid_event_cursor_error(&error) =>
                {
                    let reset_event_id = cursor.clone();
                    warn!(
                        account_id = %config.account_id.0,
                        account_email = %config.account_email,
                        cursor = %cursor,
                        error = %error,
                        "detected stale event cursor; resetting to baseline after bounded resync"
                    );
                    info!(
                        service = "user-events",
                        user = %config.account_id.0,
                        account_id = %config.account_id.0,
                        account_email = %config.account_email,
                        event_id = %reset_event_id,
                        msg = "Event loop reset",
                        "Event loop reset"
                    );
                    bounded_resync_account_for_generation(
                        config,
                        &mut session,
                        &mut client,
                        expected_generation,
                    )
                    .await?;
                    forced_sync_state = Some("cursor_reset_resync");
                    cursor.clear();
                    fetch_events_with_retry(config, &mut session, &mut client, &cursor).await?
                }
                Err(error) => return Err(error),
            };
        ensure_account_generation(config, expected_generation, "poll_after_fetch").await?;

        let refresh_requires_resync = has_mail_refresh_flag(response.refresh);
        let mut address_changed = refresh_requires_resync;
        let mut resync_state: Option<&str> = None;
        if refresh_requires_resync && forced_sync_state.is_none() {
            info!(
                service = "user-events",
                user = %config.account_id.0,
                account_id = %config.account_id.0,
                account_email = %config.account_email,
                refresh = response.refresh,
                msg = "Received refresh event",
                "Received refresh event"
            );
            bounded_resync_account_for_generation(
                config,
                &mut session,
                &mut client,
                expected_generation,
            )
            .await?;
            resync_state = Some("refresh_resync");
        }
        for event in &response.events {
            ensure_account_generation(config, expected_generation, "poll_event_delta").await?;
            for delta in parse_event_deltas(event) {
                match delta {
                    EventDelta::MessageUpsert(id) => {
                        apply_message_upsert(
                            config,
                            &mut session,
                            &mut client,
                            &id,
                            expected_generation,
                        )
                        .await?;
                    }
                    EventDelta::MessageDelete(id) => {
                        apply_message_delete(config, &id, expected_generation).await?;
                    }
                    EventDelta::LabelsChanged => {
                        if let Err(err) =
                            fetch_and_update_user_labels(config, &client, expected_generation).await
                        {
                            warn!(
                                account_id = %config.account_id.0,
                                account_email = %config.account_email,
                                error = %err,
                                "failed to refresh/reconcile user labels during event sync"
                            );
                        }
                    }
                    EventDelta::AddressesChanged => {
                        address_changed = true;
                    }
                }
            }

            if let Some(pim_store) = config.pim_store.as_ref() {
                ensure_account_generation(config, expected_generation, "poll_event_pim_delta")
                    .await?;
                let pim_summary =
                    pim_incremental::apply_incremental_event(&client, pim_store, event)
                        .await
                        .map_err(|err| {
                            EventWorkerError::Payload(format!(
                                "pim incremental apply failed: {err}"
                            ))
                        })?;
                if pim_summary != pim_incremental::IncrementalPimSummary::default() {
                    debug!(
                        account_id = %config.account_id.0,
                        account_email = %config.account_email,
                        contacts_refreshed = pim_summary.contacts_refreshed,
                        contacts_deleted = pim_summary.contacts_deleted,
                        calendars_refreshed = pim_summary.calendars_refreshed,
                        calendars_deleted = pim_summary.calendars_deleted,
                        calendar_events_upserted = pim_summary.calendar_events_upserted,
                        calendar_events_deleted = pim_summary.calendar_events_deleted,
                        "applied pim incremental event changes"
                    );
                }
            }
        }

        if address_changed {
            ensure_account_generation(config, expected_generation, "poll_refresh_address_index")
                .await?;
            refresh_address_index_with_retry(
                config,
                &mut session,
                &mut client,
                expected_generation,
            )
            .await?;
        }

        let next_event_id = if response.event_id.is_empty() {
            cursor.clone()
        } else {
            response.event_id.clone()
        };

        if next_event_id != cursor || !response.events.is_empty() {
            info!(
                account_id = %config.account_id.0,
                account_email = %config.account_email,
                old_event_id = %cursor,
                new_event_id = %next_event_id,
                events = response.events.len(),
                "Received new API event"
            );
        }

        if next_event_id != cursor || !response.events.is_empty() {
            ensure_account_generation(config, expected_generation, "poll_checkpoint_commit")
                .await?;
            let checkpoint = EventCheckpoint {
                last_event_id: next_event_id.clone(),
                last_event_ts: Some(unix_now()),
                sync_state: Some(if let Some(state) = forced_sync_state {
                    state.to_string()
                } else if let Some(state) = resync_state {
                    state.to_string()
                } else if refresh_requires_resync {
                    "refresh".to_string()
                } else if response.more != 0 {
                    "more".to_string()
                } else {
                    "ok".to_string()
                }),
            };
            config
                .checkpoint_store
                .save_checkpoint(&config.account_id, &checkpoint)
                .map_err(|_| EventWorkerError::Checkpoint)?;
        }

        debug!(
            account_id = %config.account_id.0,
            account_email = %config.account_email,
            event_id = %next_event_id,
            events = response.events.len(),
            more = response.more,
            refresh = response.refresh,
            "polled account events"
        );

        cursor = next_event_id;
        if response.more == 0 {
            break;
        }
    }

    Ok(cursor)
}

async fn run_event_worker_with_shutdown(
    config: EventWorkerConfig,
    poll_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut last_event_id = config
        .checkpoint_store
        .load_checkpoint(&config.account_id)
        .ok()
        .flatten()
        .map(|cp| cp.last_event_id)
        .unwrap_or_default();
    let mut startup_resync_pending = true;
    let mut consecutive_failures = 0u32;
    let mut next_delay = compute_initial_poll_stagger(&config.account_id, poll_interval);
    let mut stats = EventWorkerStats::default();
    if !next_delay.is_zero() {
        debug!(
            account_id = %config.account_id.0,
            account_email = %config.account_email,
            initial_delay_ms = next_delay.as_millis() as u64,
            "event worker applying initial poll stagger"
        );
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(next_delay) => {
                let expected_generation = match config
                    .runtime_accounts
                    .runtime_generation(&config.account_id)
                    .await
                {
                    Ok(generation) => generation,
                    Err(err) => {
                        warn!(
                            account_id = %config.account_id.0,
                            account_email = %config.account_email,
                            error = %err,
                            "failed to read account runtime generation; stopping worker"
                        );
                        break;
                    }
                };
                if startup_resync_pending {
                    match cached_message_count_for_generation(&config, expected_generation).await {
                        Ok(cached_count) if cached_count > 0 => {
                            if last_event_id.trim().is_empty() {
                                match bootstrap_latest_event_cursor_for_generation(
                                    &config,
                                    expected_generation,
                                )
                                .await
                                {
                                    Ok(event_id) => {
                                        info!(
                                            service = "user-events",
                                            user = %config.account_id.0,
                                            account_id = %config.account_id.0,
                                            account_email = %config.account_email,
                                            count = cached_count,
                                            event_id = %event_id,
                                            msg = "Bootstrapped latest event cursor from cached messages",
                                            "Bootstrapped latest event cursor from cached messages"
                                        );
                                        last_event_id = event_id;
                                        startup_resync_pending = false;
                                        next_delay = Duration::ZERO;
                                        continue;
                                    }
                                    Err(err) => {
                                        let now = unix_now();
                                        let failure_class = classify_worker_failure_class(&err);
                                        stats.record_failure(failure_class, now);
                                        consecutive_failures =
                                            consecutive_failures.saturating_add(1);
                                        if let Some(next_health) = classify_worker_health(&err) {
                                            let _ = config
                                                .runtime_accounts
                                                .set_health(&config.account_id, next_health)
                                                .await;
                                        }
                                        let jitter_ms = rand::thread_rng().gen_range(0..=500_u64);
                                        next_delay = compute_failure_delay(
                                            poll_interval,
                                            consecutive_failures,
                                            jitter_ms,
                                        );
                                        warn!(
                                            account_id = %config.account_id.0,
                                            account_email = %config.account_email,
                                            error = %err,
                                            failure_class = ?failure_class,
                                            consecutive_failures,
                                            retry_delay_ms = next_delay.as_millis() as u64,
                                            poll_attempts = stats.poll_attempts,
                                            failed_polls = stats.failed_polls,
                                            auth_failures = stats.auth_failures,
                                            transient_failures = stats.transient_failures,
                                            permanent_failures = stats.permanent_failures,
                                            "event worker startup cursor bootstrap failed"
                                        );
                                        if stats.poll_attempts % WORKER_STATS_LOG_EVERY_ATTEMPTS == 0 {
                                            warn!(
                                                account_id = %config.account_id.0,
                                                account_email = %config.account_email,
                                                poll_attempts = stats.poll_attempts,
                                                successful_polls = stats.successful_polls,
                                                failed_polls = stats.failed_polls,
                                                auth_failures = stats.auth_failures,
                                                transient_failures = stats.transient_failures,
                                                permanent_failures = stats.permanent_failures,
                                                "event worker stats"
                                            );
                                        }
                                        continue;
                                    }
                                }
                            } else {
                                info!(
                                    service = "imap",
                                    user = %config.account_id.0,
                                    user_id = %config.account_id.0,
                                    account_id = %config.account_id.0,
                                    account_email = %config.account_email,
                                    count = cached_count,
                                    msg = "Messages are already synced, skipping",
                                    "Messages are already synced, skipping"
                                );
                                startup_resync_pending = false;
                                next_delay = Duration::ZERO;
                                continue;
                            }
                        }
                        Ok(_) => {}
                        Err(err) => {
                            warn!(
                                account_id = %config.account_id.0,
                                account_email = %config.account_email,
                                error = %err,
                                "failed to inspect cached message state before startup resync"
                            );
                        }
                    }
                    let startup_result = match run_startup_resync_for_generation(
                        &config,
                        expected_generation,
                    )
                    .await
                    {
                        Ok(()) => ensure_account_generation(
                            &config,
                            expected_generation,
                            "startup_resync_success_commit",
                        )
                        .await
                        .map(|_| ()),
                        Err(err) => Err(err),
                    };
                    match startup_result {
                        Ok(()) => {
                            let now = unix_now();
                            let failures_before_recovery = consecutive_failures;
                            stats.record_success(now);
                            startup_resync_pending = false;
                            consecutive_failures = 0;
                            next_delay = Duration::ZERO;
                            let _ = config
                                .runtime_accounts
                                .set_health(&config.account_id, AccountHealth::Healthy)
                                .await;
                            if failures_before_recovery > 0 {
                                info!(
                                    account_id = %config.account_id.0,
                                    account_email = %config.account_email,
                                    recovered_after_failures = failures_before_recovery,
                                    poll_attempts = stats.poll_attempts,
                                    successful_polls = stats.successful_polls,
                                    failed_polls = stats.failed_polls,
                                    auth_failures = stats.auth_failures,
                                    transient_failures = stats.transient_failures,
                                    permanent_failures = stats.permanent_failures,
                                    "event worker startup resync recovered"
                                );
                            }
                        }
                        Err(err) => {
                            let now = unix_now();
                            let failure_class = classify_worker_failure_class(&err);
                            stats.record_failure(failure_class, now);
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            if let Some(next_health) = classify_worker_health(&err) {
                                let _ = config
                                    .runtime_accounts
                                    .set_health(&config.account_id, next_health)
                                    .await;
                            }
                            let jitter_ms = rand::thread_rng().gen_range(0..=500_u64);
                            next_delay =
                                compute_failure_delay(poll_interval, consecutive_failures, jitter_ms);
                            warn!(
                                account_id = %config.account_id.0,
                                account_email = %config.account_email,
                                error = %err,
                                failure_class = ?failure_class,
                                consecutive_failures,
                                retry_delay_ms = next_delay.as_millis() as u64,
                                poll_attempts = stats.poll_attempts,
                                failed_polls = stats.failed_polls,
                                auth_failures = stats.auth_failures,
                                transient_failures = stats.transient_failures,
                                permanent_failures = stats.permanent_failures,
                                "event worker startup resync failed"
                            );
                            if stats.poll_attempts % WORKER_STATS_LOG_EVERY_ATTEMPTS == 0 {
                                warn!(
                                    account_id = %config.account_id.0,
                                    account_email = %config.account_email,
                                    poll_attempts = stats.poll_attempts,
                                    successful_polls = stats.successful_polls,
                                    failed_polls = stats.failed_polls,
                                    auth_failures = stats.auth_failures,
                                    transient_failures = stats.transient_failures,
                                    permanent_failures = stats.permanent_failures,
                                    "event worker stats"
                                );
                            }
                        }
                    }
                    continue;
                }

                let poll_result = match poll_account_once_for_generation(
                    &config,
                    &last_event_id,
                    expected_generation,
                )
                .await
                {
                    Ok(next_event_id) => ensure_account_generation(
                        &config,
                        expected_generation,
                        "poll_success_commit",
                    )
                    .await
                    .map(|_| next_event_id),
                    Err(err) => Err(err),
                };
                match poll_result {
                    Ok(next_event_id) => {
                        let now = unix_now();
                        let failures_before_recovery = consecutive_failures;
                        stats.record_success(now);
                        last_event_id = next_event_id;
                        consecutive_failures = 0;
                        next_delay = poll_interval;
                        let _ = config
                            .runtime_accounts
                            .set_health(&config.account_id, AccountHealth::Healthy)
                            .await;
                        if failures_before_recovery > 0 {
                            info!(
                                account_id = %config.account_id.0,
                                account_email = %config.account_email,
                                recovered_after_failures = failures_before_recovery,
                                poll_attempts = stats.poll_attempts,
                                successful_polls = stats.successful_polls,
                                failed_polls = stats.failed_polls,
                                auth_failures = stats.auth_failures,
                                transient_failures = stats.transient_failures,
                                permanent_failures = stats.permanent_failures,
                                "event worker recovered"
                            );
                        } else if stats.poll_attempts % WORKER_STATS_LOG_EVERY_ATTEMPTS == 0 {
                            info!(
                                account_id = %config.account_id.0,
                                account_email = %config.account_email,
                                poll_attempts = stats.poll_attempts,
                                successful_polls = stats.successful_polls,
                                failed_polls = stats.failed_polls,
                                auth_failures = stats.auth_failures,
                                transient_failures = stats.transient_failures,
                                permanent_failures = stats.permanent_failures,
                                "event worker stats"
                            );
                        }
                    }
                    Err(err) => {
                        let now = unix_now();
                        let failure_class = classify_worker_failure_class(&err);
                        stats.record_failure(failure_class, now);
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if let Some(next_health) = classify_worker_health(&err) {
                            let _ = config
                                .runtime_accounts
                                .set_health(&config.account_id, next_health)
                                .await;
                        }
                        let jitter_ms = rand::thread_rng().gen_range(0..=500_u64);
                        next_delay =
                            compute_failure_delay(poll_interval, consecutive_failures, jitter_ms);
                        warn!(
                            account_id = %config.account_id.0,
                            account_email = %config.account_email,
                            error = %err,
                            failure_class = ?failure_class,
                            consecutive_failures,
                            retry_delay_ms = next_delay.as_millis() as u64,
                            poll_attempts = stats.poll_attempts,
                            failed_polls = stats.failed_polls,
                            auth_failures = stats.auth_failures,
                            transient_failures = stats.transient_failures,
                            permanent_failures = stats.permanent_failures,
                            "event worker poll failed"
                        );
                        if stats.poll_attempts % WORKER_STATS_LOG_EVERY_ATTEMPTS == 0 {
                            warn!(
                                account_id = %config.account_id.0,
                                account_email = %config.account_email,
                                poll_attempts = stats.poll_attempts,
                                successful_polls = stats.successful_polls,
                                failed_polls = stats.failed_polls,
                                auth_failures = stats.auth_failures,
                                transient_failures = stats.transient_failures,
                                permanent_failures = stats.permanent_failures,
                                "event worker stats"
                            );
                        }
                    }
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    debug!(
                        account_id = %config.account_id.0,
                        account_email = %config.account_email,
                        "event worker received shutdown"
                    );
                    break;
                }
            }
        }
    }
}

pub async fn run_event_worker(config: EventWorkerConfig, poll_interval: Duration) {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_event_worker_with_shutdown(config, poll_interval, shutdown_rx).await;
}

#[allow(clippy::too_many_arguments)]
pub fn start_event_worker_group(
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    accounts: Vec<RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: AuthRouter,
    store: Arc<dyn MessageStore>,
    checkpoint_store: SharedCheckpointStore,
    poll_interval: Duration,
) -> EventWorkerGroup {
    start_event_worker_group_with_sync_progress(
        runtime_accounts,
        accounts,
        api_base_url,
        auth_router,
        store,
        checkpoint_store,
        None,
        poll_interval,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn start_event_worker_group_with_sync_progress(
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    accounts: Vec<RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: AuthRouter,
    store: Arc<dyn MessageStore>,
    checkpoint_store: SharedCheckpointStore,
    sync_progress_callback: Option<SyncProgressCallback>,
    poll_interval: Duration,
) -> EventWorkerGroup {
    start_event_worker_group_with_sync_progress_and_pim(
        runtime_accounts,
        accounts,
        api_base_url,
        auth_router,
        store,
        checkpoint_store,
        HashMap::new(),
        sync_progress_callback,
        poll_interval,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn start_event_worker_group_with_sync_progress_and_pim(
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    accounts: Vec<RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: AuthRouter,
    store: Arc<dyn MessageStore>,
    checkpoint_store: SharedCheckpointStore,
    pim_stores: HashMap<String, Arc<PimStore>>,
    sync_progress_callback: Option<SyncProgressCallback>,
    poll_interval: Duration,
) -> EventWorkerGroup {
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let handles = accounts
        .into_iter()
        .map(|account| {
            let account_base_url = resolve_api_base_url_for_mode(&api_base_url, account.api_mode);
            let account_id_key = account.account_id.0.clone();
            let mut config = EventWorkerConfig::new(
                account.account_id,
                account.email,
                account_base_url,
                runtime_accounts.clone(),
                auth_router.clone(),
                store.clone(),
                checkpoint_store.clone(),
            );
            if let Some(pim_store) = pim_stores.get(&account_id_key) {
                config = config.with_pim_store(pim_store.clone());
            }
            if let Some(callback) = sync_progress_callback.as_ref() {
                config = config.with_sync_progress_callback(callback.clone());
            }
            let shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(run_event_worker_with_shutdown(
                config,
                poll_interval,
                shutdown_rx,
            ))
        })
        .collect();

    EventWorkerGroup {
        shutdown_tx,
        handles,
    }
}

pub fn start_event_workers(
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    accounts: Vec<RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: AuthRouter,
    store: Arc<dyn MessageStore>,
    checkpoint_store: SharedCheckpointStore,
    poll_interval: Duration,
) -> Vec<JoinHandle<()>> {
    start_event_workers_with_sync_progress(
        runtime_accounts,
        accounts,
        api_base_url,
        auth_router,
        store,
        checkpoint_store,
        None,
        poll_interval,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn start_event_workers_with_sync_progress(
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    accounts: Vec<RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: AuthRouter,
    store: Arc<dyn MessageStore>,
    checkpoint_store: SharedCheckpointStore,
    sync_progress_callback: Option<SyncProgressCallback>,
    poll_interval: Duration,
) -> Vec<JoinHandle<()>> {
    start_event_workers_with_sync_progress_and_pim(
        runtime_accounts,
        accounts,
        api_base_url,
        auth_router,
        store,
        checkpoint_store,
        HashMap::new(),
        sync_progress_callback,
        poll_interval,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn start_event_workers_with_sync_progress_and_pim(
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    accounts: Vec<RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: AuthRouter,
    store: Arc<dyn MessageStore>,
    checkpoint_store: SharedCheckpointStore,
    pim_stores: HashMap<String, Arc<PimStore>>,
    sync_progress_callback: Option<SyncProgressCallback>,
    poll_interval: Duration,
) -> Vec<JoinHandle<()>> {
    accounts
        .into_iter()
        .map(|account| {
            let account_base_url = resolve_api_base_url_for_mode(&api_base_url, account.api_mode);
            let account_id_key = account.account_id.0.clone();
            let mut config = EventWorkerConfig::new(
                account.account_id,
                account.email,
                account_base_url,
                runtime_accounts.clone(),
                auth_router.clone(),
                store.clone(),
                checkpoint_store.clone(),
            );
            if let Some(pim_store) = pim_stores.get(&account_id_key) {
                config = config.with_pim_store(pim_store.clone());
            }
            if let Some(callback) = sync_progress_callback.as_ref() {
                config = config.with_sync_progress_callback(callback.clone());
            }
            tokio::spawn(run_event_worker(config, poll_interval))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::api::types::Session;
    use crate::bridge::accounts::AccountHealth;
    use crate::bridge::accounts::AccountRegistry;
    use crate::imap::store::InMemoryStore;
    use crate::pim::store::PimStore;
    use rusqlite::Connection;
    use serde::Deserialize;
    use tempfile::tempdir;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_session(uid: &str, email: &str, bridge_password: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: format!("access-{uid}"),
            refresh_token: format!("refresh-{uid}"),
            email: email.to_string(),
            display_name: email.to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some(bridge_password.to_string()),
        }
    }

    fn message_json(message_id: &str, label_ids: &[&str], unread: i32) -> serde_json::Value {
        serde_json::json!({
            "Code": 1000,
            "Message": {
                "ID": message_id,
                "AddressID": "addr-1",
                "LabelIDs": label_ids,
                "Subject": "Event Subject",
                "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                "ToList": [],
                "CCList": [],
                "BCCList": [],
                "Time": 1700000000,
                "Size": 100,
                "Unread": unread,
                "NumAttachments": 0,
                "Header": "From: alice@proton.me\r\n",
                "Body": "body",
                "MIMEType": "text/plain",
                "Attachments": []
            }
        })
    }

    fn event_worker_config(
        server_uri: &str,
        runtime: Arc<RuntimeAccountRegistry>,
        auth_router: AuthRouter,
        store: Arc<dyn MessageStore>,
        checkpoints: SharedCheckpointStore,
    ) -> EventWorkerConfig {
        EventWorkerConfig::new(
            AccountId("uid-1".to_string()),
            "alice@proton.me".to_string(),
            server_uri.to_string(),
            runtime,
            auth_router,
            store,
            checkpoints,
        )
    }

    fn setup_pim_store() -> Arc<PimStore> {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("account.db");
        Box::leak(Box::new(tmp));
        Arc::new(PimStore::new(db_path).unwrap())
    }

    #[derive(Debug, Deserialize)]
    struct EventDeltaMatrixFixture {
        cases: Vec<EventDeltaMatrixCase>,
    }

    #[derive(Debug, Deserialize)]
    struct EventDeltaMatrixCase {
        name: String,
        payload: serde_json::Value,
        expected: EventDeltaMatrixExpected,
    }

    #[derive(Debug, Deserialize)]
    struct EventDeltaMatrixExpected {
        message_upserts: Vec<String>,
        message_deletes: Vec<String>,
        labels_changed: bool,
        addresses_changed: bool,
    }

    fn read_event_delta_matrix_fixture() -> EventDeltaMatrixFixture {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/parity/fixtures/events_delta_matrix.json");
        let bytes = std::fs::read(&path).expect("event delta matrix fixture should be readable");
        serde_json::from_slice(&bytes).expect("event delta matrix fixture should parse")
    }

    #[test]
    fn checkpoint_roundtrip() {
        let store = InMemoryCheckpointStore::new();
        let account_id = AccountId("uid-1".to_string());
        let checkpoint = EventCheckpoint {
            last_event_id: "event-42".to_string(),
            last_event_ts: Some(42),
            sync_state: Some("ok".to_string()),
        };

        store.save_checkpoint(&account_id, &checkpoint).unwrap();
        let loaded = store.load_checkpoint(&account_id).unwrap().unwrap();

        assert_eq!(loaded, checkpoint);
    }

    #[test]
    fn compute_failure_delay_scales_and_caps() {
        let base = Duration::from_secs(30);
        assert_eq!(compute_failure_delay(base, 1, 0), Duration::from_secs(30));
        assert_eq!(compute_failure_delay(base, 2, 0), Duration::from_secs(60));
        assert_eq!(compute_failure_delay(base, 3, 0), Duration::from_secs(120));
        assert_eq!(compute_failure_delay(base, 4, 0), Duration::from_secs(240));
        assert_eq!(compute_failure_delay(base, 5, 0), Duration::from_secs(300));
        assert_eq!(compute_failure_delay(base, 9, 0), Duration::from_secs(300));
    }

    #[test]
    fn compute_initial_poll_stagger_is_bounded_and_stable() {
        let account_a = AccountId("uid-a".to_string());
        let account_b = AccountId("uid-b".to_string());

        let poll = Duration::from_secs(30);
        let stagger_a_1 = compute_initial_poll_stagger(&account_a, poll);
        let stagger_a_2 = compute_initial_poll_stagger(&account_a, poll);
        let stagger_b = compute_initial_poll_stagger(&account_b, poll);

        assert_eq!(stagger_a_1, stagger_a_2);
        assert!(stagger_a_1 <= Duration::from_millis(MAX_INITIAL_POLL_STAGGER_MS));
        assert!(stagger_b <= Duration::from_millis(MAX_INITIAL_POLL_STAGGER_MS));
        assert_eq!(
            compute_initial_poll_stagger(&account_a, Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn compute_initial_poll_stagger_spreads_high_account_counts() {
        let mut bucket_counts: HashMap<u64, usize> = HashMap::new();
        let poll = Duration::from_secs(30);

        for i in 0..500 {
            let account_id = AccountId(format!("uid-{i}"));
            let bucket = compute_initial_poll_stagger(&account_id, poll).as_millis() as u64;
            *bucket_counts.entry(bucket).or_insert(0) += 1;
        }

        let unique_buckets = bucket_counts.len();
        let max_bucket_load = bucket_counts.values().copied().max().unwrap_or(0);

        assert!(
            unique_buckets >= 380,
            "expected broad startup spread, got only {unique_buckets} unique buckets"
        );
        assert!(
            max_bucket_load <= 4,
            "expected low bucket concentration, got {max_bucket_load}"
        );
    }

    #[test]
    fn classify_worker_error_health_mapping() {
        let auth_error = EventWorkerError::Api(ApiError::SessionExpired);
        assert_eq!(
            classify_worker_health(&auth_error),
            Some(AccountHealth::Unavailable)
        );
        assert_eq!(
            classify_worker_failure_class(&auth_error),
            WorkerFailureClass::Auth
        );

        let transient = EventWorkerError::Api(ApiError::Io(io::Error::other("network")));
        assert_eq!(
            classify_worker_health(&transient),
            Some(AccountHealth::Degraded)
        );
        assert_eq!(
            classify_worker_failure_class(&transient),
            WorkerFailureClass::Transient
        );

        let permanent = EventWorkerError::Payload("bad event".to_string());
        assert_eq!(
            classify_worker_failure_class(&permanent),
            WorkerFailureClass::Permanent
        );
        assert_eq!(
            classify_worker_health(&permanent),
            Some(AccountHealth::Degraded)
        );
    }

    #[test]
    fn worker_stats_counts_failure_classes() {
        let mut stats = EventWorkerStats::default();
        stats.record_failure(WorkerFailureClass::Auth, 10);
        stats.record_failure(WorkerFailureClass::Transient, 20);
        stats.record_failure(WorkerFailureClass::Permanent, 30);
        stats.record_success(40);

        assert_eq!(stats.poll_attempts, 4);
        assert_eq!(stats.failed_polls, 3);
        assert_eq!(stats.successful_polls, 1);
        assert_eq!(stats.auth_failures, 1);
        assert_eq!(stats.transient_failures, 1);
        assert_eq!(stats.permanent_failures, 1);
        assert_eq!(stats.last_failure_ts, Some(30));
        assert_eq!(stats.last_success_ts, Some(40));
    }

    #[test]
    fn parse_event_deltas_respects_proton_numeric_actions() {
        let payload = serde_json::json!({
            "Messages": [
                {"ID": "msg-delete", "Action": 0},
                {"ID": "msg-create", "Action": 1},
                {"ID": "msg-update", "Action": 2},
                {"ID": "msg-update-flags", "Action": 3}
            ]
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(
            deltas,
            vec![
                EventDelta::MessageDelete("msg-delete".to_string()),
                EventDelta::MessageUpsert("msg-create".to_string()),
                EventDelta::MessageUpsert("msg-update".to_string()),
                EventDelta::MessageUpsert("msg-update-flags".to_string()),
            ]
        );
    }

    #[test]
    fn parse_event_deltas_message_uses_parent_id_and_action_fallback() {
        let payload = serde_json::json!({
            "ID": "msg-parent",
            "Action": 0,
            "Message": {
                "Subject": "hello"
            }
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(
            deltas,
            vec![EventDelta::MessageDelete("msg-parent".to_string())]
        );
    }

    #[test]
    fn parse_event_deltas_accepts_string_numeric_delete_action() {
        let payload = serde_json::json!({
            "Messages": [{"ID": "msg-delete", "Action": "0"}]
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(
            deltas,
            vec![EventDelta::MessageDelete("msg-delete".to_string())]
        );
    }

    #[test]
    fn parse_event_deltas_supports_scalar_map_message_actions() {
        let payload = serde_json::json!({
            "Messages": {
                "msg-del": 0,
                "msg-upsert-a": 2,
                "msg-upsert-b": "update"
            }
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(deltas.len(), 3);
        assert!(deltas.contains(&EventDelta::MessageDelete("msg-del".to_string())));
        assert!(deltas.contains(&EventDelta::MessageUpsert("msg-upsert-a".to_string())));
        assert!(deltas.contains(&EventDelta::MessageUpsert("msg-upsert-b".to_string())));
    }

    #[test]
    fn parse_event_deltas_treats_null_map_message_entry_as_delete() {
        let payload = serde_json::json!({
            "Messages": {
                "msg-null": serde_json::Value::Null
            }
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(
            deltas,
            vec![EventDelta::MessageDelete("msg-null".to_string())]
        );
    }

    #[test]
    fn parse_event_deltas_includes_label_change_marker() {
        let payload = serde_json::json!({
            "Labels": [{"ID": "label-1", "Action": 2}]
        });

        let deltas = parse_event_deltas(&payload);
        assert!(deltas.contains(&EventDelta::LabelsChanged));
    }

    #[test]
    fn parse_event_deltas_supports_scalar_array_messages_with_parent_action() {
        let payload = serde_json::json!({
            "Action": 0,
            "Messages": ["msg-a", "msg-b"]
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(
            deltas,
            vec![
                EventDelta::MessageDelete("msg-a".to_string()),
                EventDelta::MessageDelete("msg-b".to_string()),
            ]
        );
    }

    #[test]
    fn parse_event_deltas_supports_scalar_array_messages_with_remove_action_name() {
        let payload = serde_json::json!({
            "Action": "remove",
            "Messages": ["msg-a"]
        });

        let deltas = parse_event_deltas(&payload);
        assert_eq!(
            deltas,
            vec![EventDelta::MessageDelete("msg-a".to_string()),]
        );
    }

    #[test]
    fn parse_event_deltas_matches_fixture_matrix_cases() {
        let fixture = read_event_delta_matrix_fixture();
        assert!(
            !fixture.cases.is_empty(),
            "fixture matrix should not be empty"
        );

        for case in fixture.cases {
            let deltas = parse_event_deltas(&case.payload);
            let mut upserts = Vec::new();
            let mut deletes = Vec::new();
            let mut labels_changed = false;
            let mut addresses_changed = false;

            for delta in deltas {
                match delta {
                    EventDelta::MessageUpsert(id) => upserts.push(id),
                    EventDelta::MessageDelete(id) => deletes.push(id),
                    EventDelta::LabelsChanged => labels_changed = true,
                    EventDelta::AddressesChanged => addresses_changed = true,
                }
            }

            assert_eq!(
                upserts, case.expected.message_upserts,
                "fixture case {} upserts mismatch",
                case.name
            );
            assert_eq!(
                deletes, case.expected.message_deletes,
                "fixture case {} deletes mismatch",
                case.name
            );
            assert_eq!(
                labels_changed, case.expected.labels_changed,
                "fixture case {} labels_changed mismatch",
                case.name
            );
            assert_eq!(
                addresses_changed, case.expected.addresses_changed,
                "fixture case {} addresses_changed mismatch",
                case.name
            );
        }
    }

    #[test]
    fn invalid_event_cursor_error_detection_uses_message_shape() {
        let invalid = ApiError::Api {
            code: 9999,
            message: "Invalid event ID".to_string(),
            details: None,
        };
        assert!(is_invalid_event_cursor_error(&invalid));

        let not_found = ApiError::Api {
            code: 9999,
            message: "Event ID not found".to_string(),
            details: None,
        };
        assert!(is_invalid_event_cursor_error(&not_found));

        let unrelated = ApiError::Api {
            code: 8002,
            message: "Invalid credentials".to_string(),
            details: None,
        };
        assert!(!is_invalid_event_cursor_error(&unrelated));
    }

    #[test]
    fn file_checkpoint_store_roundtrip() {
        let tmp = tempdir().unwrap();
        let checkpoint_path = tmp.path().join("event_checkpoints.json");

        let store = FileCheckpointStore::new(checkpoint_path.clone());
        let account_id = AccountId("uid-1".to_string());
        let checkpoint = EventCheckpoint {
            last_event_id: "event-88".to_string(),
            last_event_ts: Some(88),
            sync_state: Some("ok".to_string()),
        };
        store.save_checkpoint(&account_id, &checkpoint).unwrap();

        let restored = FileCheckpointStore::new(checkpoint_path);
        let loaded = restored.load_checkpoint(&account_id).unwrap().unwrap();
        assert_eq!(loaded, checkpoint);
    }

    #[test]
    fn vault_checkpoint_store_roundtrip() {
        let tmp = tempdir().unwrap();
        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let store = VaultCheckpointStore::new(tmp.path().to_path_buf());
        let account_id = AccountId("uid-1".to_string());
        let checkpoint = EventCheckpoint {
            last_event_id: "event-44".to_string(),
            last_event_ts: Some(44),
            sync_state: Some("ok".to_string()),
        };
        store.save_checkpoint(&account_id, &checkpoint).unwrap();

        let loaded = store.load_checkpoint(&account_id).unwrap().unwrap();
        assert_eq!(loaded, checkpoint);
    }

    #[tokio::test]
    async fn poll_account_once_updates_checkpoint_and_store() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{"Messages": [{"ID": "msg-1", "Action": 1}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/mail/v4/messages/msg-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(message_json(
                "msg-1",
                &["0"],
                1,
            )))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");

        let uid = store.get_uid("uid-1::INBOX", "msg-1").await.unwrap();
        assert_eq!(uid, Some(1));

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.last_event_id, "event-1");
        assert!(checkpoint.last_event_ts.is_some());
        assert_eq!(checkpoint.sync_state.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn poll_account_once_with_pim_contact_delta_updates_cache_and_checkpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Contacts": [{"Action": 2, "Contact": {"ID": "contact-1"}}]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/contacts/v4/contact-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Contact": {
                    "ID": "contact-1",
                    "Name": "Alice",
                    "UID": "uid-contact-1",
                    "Size": 10,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "ContactEmails": [{
                        "ID": "email-1",
                        "Email": "alice@proton.me",
                        "Name": "Alice",
                        "ContactID": "contact-1",
                        "Kind": []
                    }],
                    "Cards": [{
                        "Type": 0,
                        "Data": "BEGIN:VCARD"
                    }]
                }
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let pim_store = setup_pim_store();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store,
            checkpoints.clone(),
        )
        .with_pim_store(pim_store.clone());

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.last_event_id, "event-1");

        let conn = Connection::open(pim_store.db_path()).unwrap();
        let deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_contacts WHERE id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn poll_account_once_pim_failure_does_not_commit_checkpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Contacts": [{"Action": 2, "Contact": {"ID": "contact-1"}}]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/contacts/v4/contact-1"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "Code": 5000,
                "Error": "boom"
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let pim_store = setup_pim_store();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store,
            checkpoints.clone(),
        )
        .with_pim_store(pim_store.clone());

        let err = poll_account_once(&config, "event-0").await.unwrap_err();
        assert!(
            matches!(err, EventWorkerError::Payload(message) if message.contains("pim incremental apply failed"))
        );

        assert!(checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .is_none());

        let conn = Connection::open(pim_store.db_path()).unwrap();
        let contacts_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_contacts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(contacts_count, 0);
    }

    #[tokio::test]
    async fn poll_account_once_handles_delete_delta() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{"Messages": [{"ID": "msg-1", "Action": 0}]}]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let _ = store
            .store_metadata(
                "uid-1::INBOX",
                "msg-1",
                crate::api::types::MessageMetadata {
                    id: "msg-1".to_string(),
                    address_id: "addr-1".to_string(),
                    label_ids: vec!["0".to_string()],
                    external_id: None,
                    subject: "x".to_string(),
                    sender: crate::api::types::EmailAddress {
                        name: "A".to_string(),
                        address: "a@b.com".to_string(),
                    },
                    to_list: vec![],
                    cc_list: vec![],
                    bcc_list: vec![],
                    reply_tos: vec![],
                    flags: 0,
                    time: 0,
                    size: 1,
                    unread: 1,
                    is_replied: 0,
                    is_replied_all: 0,
                    is_forwarded: 0,
                    num_attachments: 0,
                },
            )
            .await
            .unwrap();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints,
        );

        let _ = poll_account_once(&config, "event-0").await.unwrap();
        assert!(store
            .get_uid("uid-1::INBOX", "msg-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn poll_account_once_refreshes_address_index_on_address_event() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{"Addresses": [{"ID": "addr-2"}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-2",
                    "Email": "alias@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Alias",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let _ = auth_router.set_account_split_mode(&AccountId("uid-1".to_string()), true);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router.clone(),
            store,
            checkpoints,
        );

        let _ = poll_account_once(&config, "event-0").await.unwrap();
        assert!(auth_router
            .resolve_login("alias@proton.me", "pass-a")
            .is_some());
    }

    #[tokio::test]
    async fn poll_account_once_refresh_uses_bounded_resync() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 1,
                "Events": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-refresh-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Recovered message",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-1",
                    "Email": "alice@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Alice",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");
        assert_eq!(
            store
                .get_uid("uid-1::INBOX", "msg-refresh-1")
                .await
                .unwrap(),
            Some(1)
        );

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sync_state.as_deref(), Some("refresh_resync"));
    }

    #[tokio::test]
    async fn poll_account_once_non_mail_refresh_bit_does_not_trigger_resync() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 2,
                "Events": []
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");
        assert_eq!(
            store.list_uids("uid-1::INBOX").await.unwrap(),
            Vec::<u32>::new()
        );

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sync_state.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn poll_account_once_more_chain_honors_upstream_page_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-0",
                "More": 1,
                "Refresh": 0,
                "Events": []
            })))
            .expect(MAX_EVENT_PAGES_PER_POLL as u64)
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(&server.uri(), runtime, auth_router, store, checkpoints);

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-0");
    }

    #[tokio::test]
    async fn poll_account_once_refresh_paginates_until_end_id_exhausted() {
        let server = MockServer::start().await;
        let selectable_mailboxes = mailbox::system_mailboxes()
            .iter()
            .filter(|mb| mb.selectable)
            .count();

        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 1,
                "Events": []
            })))
            .mount(&server)
            .await;

        let first_page_messages: Vec<serde_json::Value> = (0..RESYNC_PAGE_SIZE)
            .map(|idx| {
                let id = format!("msg-page1-{idx}");
                serde_json::json!({
                    "ID": id,
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": format!("Recovered message {idx}"),
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000 + idx as i64,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                })
            })
            .collect();

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .and(body_partial_json(serde_json::json!({
                "EndID": serde_json::Value::Null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": RESYNC_PAGE_SIZE,
                "Messages": first_page_messages
            })))
            .expect(selectable_mailboxes as u64)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .and(body_partial_json(serde_json::json!({
                "EndID": format!("msg-page1-{}", RESYNC_PAGE_SIZE - 1)
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-page2-0",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Recovered page two message",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700001000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .expect(selectable_mailboxes as u64)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-1",
                    "Email": "alice@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Alice",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");
        assert!(store
            .get_uid("uid-1::INBOX", "msg-page2-0")
            .await
            .unwrap()
            .is_some());

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sync_state.as_deref(), Some("refresh_resync"));
    }

    #[tokio::test]
    async fn poll_account_once_refresh_emits_sync_lifecycle_progress_events() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 1,
                "Events": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-refresh-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Recovered message",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-1",
                    "Email": "alice@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Alice",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let progress_events = Arc::new(StdMutex::new(Vec::new()));
        let progress_events_sink = progress_events.clone();
        let callback: SyncProgressCallback = Arc::new(move |event| {
            progress_events_sink.lock().unwrap().push(event);
        });

        let config = event_worker_config(&server.uri(), runtime, auth_router, store, checkpoints)
            .with_sync_progress_callback(callback);

        let _ = poll_account_once(&config, "event-0").await.unwrap();

        let events = progress_events.lock().unwrap().clone();
        assert!(matches!(
            events.first(),
            Some(SyncProgressUpdate::Started { user_id }) if user_id == "uid-1"
        ));
        assert!(matches!(
            events.last(),
            Some(SyncProgressUpdate::Finished { user_id }) if user_id == "uid-1"
        ));

        let progress_values: Vec<(f64, i64, i64)> = events
            .iter()
            .filter_map(|event| match event {
                SyncProgressUpdate::Progress {
                    progress,
                    elapsed_ms,
                    remaining_ms,
                    ..
                } => Some((*progress, *elapsed_ms, *remaining_ms)),
                _ => None,
            })
            .collect();
        assert!(
            !progress_values.is_empty(),
            "expected at least one progress event"
        );
        for (progress, elapsed_ms, remaining_ms) in &progress_values {
            assert!((*progress >= 0.0) && (*progress <= 1.0));
            assert!(*elapsed_ms >= 0);
            assert!(*remaining_ms >= 0);
        }
        for pair in progress_values.windows(2) {
            assert!(
                pair[1].0 >= pair[0].0,
                "expected non-decreasing progress, got {:?} -> {:?}",
                pair[0],
                pair[1]
            );
        }
        let last_progress = progress_values.last().unwrap().0;
        assert_eq!(last_progress, 1.0);
    }

    #[tokio::test]
    async fn poll_account_once_invalid_cursor_resets_to_baseline_and_resyncs() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/stale-event"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2011,
                "Error": "Invalid event ID"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-resync-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Recovered from stale cursor",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-2",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "stale-event").await.unwrap();
        assert_eq!(next, "event-2");
        assert_eq!(
            store.get_uid("uid-1::INBOX", "msg-resync-1").await.unwrap(),
            Some(1)
        );

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.last_event_id, "event-2");
        assert_eq!(
            checkpoint.sync_state.as_deref(),
            Some("cursor_reset_resync")
        );
    }

    #[tokio::test]
    async fn poll_account_once_label_event_does_not_trigger_resync() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Labels": [{
                        "ID": "label-custom-1",
                        "Action": 2,
                        "Label": {
                            "ID": "label-custom-1",
                            "Name": "Projects"
                        }
                    }]
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");
        assert_eq!(
            store.list_uids("uid-1::INBOX").await.unwrap(),
            Vec::<u32>::new()
        );

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sync_state.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn poll_account_once_label_event_reconciles_renamed_mailbox_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Labels": [{
                        "ID": "label-custom-1",
                        "Action": 2
                    }]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/labels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Labels": [{
                    "ID": "label-custom-1",
                    "Name": "New Projects",
                    "Path": "New Projects",
                    "Type": 1
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        runtime.set_user_labels(
            &AccountId("uid-1".to_string()),
            vec![crate::imap::mailbox::ResolvedMailbox {
                name: "Labels/Old Projects".to_string(),
                label_id: "label-custom-1".to_string(),
                special_use: None,
                selectable: true,
            }],
        );
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        store
            .store_metadata(
                "uid-1::Labels/Old Projects",
                "msg-label-1",
                MessageMetadata {
                    id: "msg-label-1".to_string(),
                    address_id: "addr-1".to_string(),
                    label_ids: vec!["label-custom-1".to_string()],
                    external_id: None,
                    subject: "Project note".to_string(),
                    sender: crate::api::types::EmailAddress {
                        name: "Alice".to_string(),
                        address: "alice@proton.me".to_string(),
                    },
                    to_list: Vec::new(),
                    cc_list: Vec::new(),
                    bcc_list: Vec::new(),
                    reply_tos: Vec::new(),
                    flags: 0,
                    time: 1_700_000_000,
                    size: 120,
                    unread: 1,
                    is_replied: 0,
                    is_replied_all: 0,
                    is_forwarded: 0,
                    num_attachments: 0,
                },
            )
            .await
            .unwrap();

        let config = event_worker_config(
            &server.uri(),
            runtime.clone(),
            auth_router,
            store.clone(),
            checkpoints,
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");

        let labels = runtime.get_user_labels(&AccountId("uid-1".to_string()));
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].name, "Labels/New Projects");
        assert_eq!(labels[0].label_id, "label-custom-1");

        assert_eq!(
            store
                .get_uid("uid-1::Labels/New Projects", "msg-label-1")
                .await
                .unwrap(),
            Some(1)
        );
        assert!(store
            .list_uids("uid-1::Labels/Old Projects")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn poll_account_once_label_event_clears_deleted_mailbox_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Labels": [{
                        "ID": "label-custom-1",
                        "Action": 0
                    }]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/labels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Labels": []
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        runtime.set_user_labels(
            &AccountId("uid-1".to_string()),
            vec![crate::imap::mailbox::ResolvedMailbox {
                name: "Labels/Obsolete".to_string(),
                label_id: "label-custom-1".to_string(),
                special_use: None,
                selectable: true,
            }],
        );
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        store
            .store_metadata(
                "uid-1::Labels/Obsolete",
                "msg-obsolete-1",
                MessageMetadata {
                    id: "msg-obsolete-1".to_string(),
                    address_id: "addr-1".to_string(),
                    label_ids: vec!["label-custom-1".to_string()],
                    external_id: None,
                    subject: "Obsolete note".to_string(),
                    sender: crate::api::types::EmailAddress {
                        name: "Alice".to_string(),
                        address: "alice@proton.me".to_string(),
                    },
                    to_list: Vec::new(),
                    cc_list: Vec::new(),
                    bcc_list: Vec::new(),
                    reply_tos: Vec::new(),
                    flags: 0,
                    time: 1_700_000_000,
                    size: 64,
                    unread: 1,
                    is_replied: 0,
                    is_replied_all: 0,
                    is_forwarded: 0,
                    num_attachments: 0,
                },
            )
            .await
            .unwrap();

        let config = event_worker_config(
            &server.uri(),
            runtime.clone(),
            auth_router,
            store.clone(),
            checkpoints,
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");

        assert!(runtime
            .get_user_labels(&AccountId("uid-1".to_string()))
            .is_empty());
        assert!(store
            .list_uids("uid-1::Labels/Obsolete")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn poll_account_once_refresh_and_label_event_resyncs_once() {
        let server = MockServer::start().await;
        let selectable_mailboxes = mailbox::system_mailboxes()
            .iter()
            .filter(|mb| mb.selectable)
            .count();

        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 1,
                "Events": [{
                    "Labels": [{
                        "ID": "label-custom-1",
                        "Action": 2
                    }]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-refresh-label-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Recovered message",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .expect(selectable_mailboxes as u64)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-1",
                    "Email": "alice@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Alice",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");
        assert_eq!(
            store
                .get_uid("uid-1::INBOX", "msg-refresh-label-1")
                .await
                .unwrap(),
            Some(1)
        );

        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sync_state.as_deref(), Some("refresh_resync"));
    }

    #[tokio::test]
    async fn poll_account_once_message_and_label_batch_stays_incremental() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Messages": [{"ID": "msg-1", "Action": 1}],
                    "Labels": [{"ID": "label-custom-1", "Action": 2}]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/mail/v4/messages/msg-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(message_json(
                "msg-1",
                &["0"],
                1,
            )))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let registry = AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        ));
        let auth_router = AuthRouter::new(registry);
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();

        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store.clone(),
            checkpoints.clone(),
        );

        let next = poll_account_once(&config, "event-0").await.unwrap();
        assert_eq!(next, "event-1");
        assert_eq!(
            store.get_uid("uid-1::INBOX", "msg-1").await.unwrap(),
            Some(1)
        );
        let checkpoint = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sync_state.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn start_event_workers_starts_one_task_per_account() {
        let accounts = vec![
            RuntimeAccountInfo {
                account_id: AccountId("uid-1".to_string()),
                email: "a@proton.me".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                health: AccountHealth::Healthy,
            },
            RuntimeAccountInfo {
                account_id: AccountId("uid-2".to_string()),
                email: "b@proton.me".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                health: AccountHealth::Healthy,
            },
        ];
        let sessions = vec![
            sample_session("uid-1", "a@proton.me", "p1"),
            sample_session("uid-2", "b@proton.me", "p2"),
        ];

        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(sessions));
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let auth_router = AuthRouter::new(AccountRegistry::from_sessions(vec![
            sample_session("uid-1", "a@proton.me", "p1"),
            sample_session("uid-2", "b@proton.me", "p2"),
        ]));

        let handles = start_event_workers(
            runtime,
            accounts,
            "http://127.0.0.1:1".to_string(),
            auth_router,
            store,
            checkpoints,
            Duration::from_secs(3600),
        );
        assert_eq!(handles.len(), 2);
        for handle in handles {
            handle.abort();
        }
    }

    #[tokio::test]
    async fn start_event_worker_group_shuts_down_cleanly() {
        let accounts = vec![
            RuntimeAccountInfo {
                account_id: AccountId("uid-1".to_string()),
                email: "a@proton.me".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                health: AccountHealth::Healthy,
            },
            RuntimeAccountInfo {
                account_id: AccountId("uid-2".to_string()),
                email: "b@proton.me".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                health: AccountHealth::Healthy,
            },
        ];
        let sessions = vec![
            sample_session("uid-1", "a@proton.me", "p1"),
            sample_session("uid-2", "b@proton.me", "p2"),
        ];

        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(sessions));
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let auth_router = AuthRouter::new(AccountRegistry::from_sessions(vec![
            sample_session("uid-1", "a@proton.me", "p1"),
            sample_session("uid-2", "b@proton.me", "p2"),
        ]));

        let group = start_event_worker_group(
            runtime,
            accounts,
            "http://127.0.0.1:1".to_string(),
            auth_router,
            store,
            checkpoints,
            Duration::from_secs(3600),
        );
        assert_eq!(group.len(), 2);
        group.shutdown().await;
    }

    #[tokio::test]
    async fn worker_group_isolates_unavailable_account_from_healthy_account() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 0,
                "Messages": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .and(header("x-pm-uid", "uid-2"))
            .and(header("Authorization", "Bearer access-uid-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-b-1",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-b-1"))
            .and(header("x-pm-uid", "uid-2"))
            .and(header("Authorization", "Bearer access-uid-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-b-1",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;

        let sessions = vec![
            sample_session("uid-1", "a@proton.me", "p1"),
            sample_session("uid-2", "b@proton.me", "p2"),
        ];
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(sessions));
        runtime
            .set_health(&AccountId("uid-1".to_string()), AccountHealth::Unavailable)
            .await
            .unwrap();

        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let auth_router = AuthRouter::new(AccountRegistry::from_sessions(vec![
            sample_session("uid-1", "a@proton.me", "p1"),
            sample_session("uid-2", "b@proton.me", "p2"),
        ]));
        let accounts = vec![
            RuntimeAccountInfo {
                account_id: AccountId("uid-1".to_string()),
                email: "a@proton.me".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                health: AccountHealth::Unavailable,
            },
            RuntimeAccountInfo {
                account_id: AccountId("uid-2".to_string()),
                email: "b@proton.me".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                health: AccountHealth::Healthy,
            },
        ];

        let group = start_event_worker_group(
            runtime.clone(),
            accounts,
            server.uri(),
            auth_router,
            store,
            checkpoints.clone(),
            Duration::from_millis(50),
        );

        tokio::time::sleep(Duration::from_millis(200)).await;

        let account_a_cp = checkpoints
            .load_checkpoint(&AccountId("uid-1".to_string()))
            .unwrap();
        let account_b_cp = checkpoints
            .load_checkpoint(&AccountId("uid-2".to_string()))
            .unwrap();
        assert!(account_a_cp.is_none());
        assert_eq!(account_b_cp.unwrap().last_event_id, "event-b-1".to_string());

        assert_eq!(
            runtime
                .get_health(&AccountId("uid-1".to_string()))
                .await
                .unwrap(),
            AccountHealth::Unavailable
        );
        assert_eq!(
            runtime
                .get_health(&AccountId("uid-2".to_string()))
                .await
                .unwrap(),
            AccountHealth::Healthy
        );

        group.shutdown().await;
    }

    #[tokio::test]
    async fn stale_in_flight_poll_does_not_commit_after_unavailable_transition() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(250))
                    .set_body_json(serde_json::json!({
                        "Code": 1000,
                        "EventID": "event-1",
                        "More": 0,
                        "Refresh": 0,
                        "Events": []
                    })),
            )
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let auth_router = AuthRouter::new(AccountRegistry::from_single_session(sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        )));
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let config = event_worker_config(
            &server.uri(),
            runtime.clone(),
            auth_router,
            store,
            checkpoints.clone(),
        );
        let account_id = AccountId("uid-1".to_string());
        let expected_generation = runtime.runtime_generation(&account_id).await.unwrap();

        let poll = tokio::spawn({
            let config = config.clone();
            async move {
                poll_account_once_for_generation(&config, "event-0", expected_generation).await
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        runtime
            .set_health(&account_id, AccountHealth::Unavailable)
            .await
            .unwrap();

        let err = poll.await.unwrap().unwrap_err();
        assert!(matches!(
            err,
            EventWorkerError::Account(AccountRuntimeError::AccountUnavailable(_))
        ));
        assert_eq!(
            runtime.get_health(&account_id).await.unwrap(),
            AccountHealth::Unavailable
        );
        assert!(checkpoints.load_checkpoint(&account_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn worker_group_sync_progress_callback_is_propagated() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 1,
                "Events": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-1"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-cb-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Callback propagation",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-1",
                    "Email": "alice@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Alice",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let sessions = vec![sample_session("uid-1", "alice@proton.me", "pass-a")];
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(sessions));
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());
        let store = InMemoryStore::new();
        let auth_router = AuthRouter::new(AccountRegistry::from_sessions(vec![sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        )]));
        let accounts = vec![RuntimeAccountInfo {
            account_id: AccountId("uid-1".to_string()),
            email: "alice@proton.me".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            health: AccountHealth::Healthy,
        }];
        let progress_events = Arc::new(StdMutex::new(Vec::new()));
        let progress_events_sink = progress_events.clone();
        let callback: SyncProgressCallback = Arc::new(move |event| {
            progress_events_sink.lock().unwrap().push(event);
        });

        let group = start_event_worker_group_with_sync_progress(
            runtime,
            accounts,
            server.uri(),
            auth_router,
            store,
            checkpoints,
            Some(callback),
            Duration::from_millis(50),
        );

        let start = tokio::time::Instant::now();
        loop {
            let snapshot = progress_events.lock().unwrap().clone();
            let saw_started = snapshot
                .iter()
                .any(|event| matches!(event, SyncProgressUpdate::Started { user_id } if user_id == "uid-1"));
            let saw_finished = snapshot
                .iter()
                .any(|event| matches!(event, SyncProgressUpdate::Finished { user_id } if user_id == "uid-1"));
            let saw_progress = snapshot
                .iter()
                .any(|event| matches!(event, SyncProgressUpdate::Progress { user_id, .. } if user_id == "uid-1"));
            if saw_started && saw_progress && saw_finished {
                break;
            }
            if start.elapsed() >= Duration::from_secs(4) {
                panic!("timed out waiting for sync progress callback events");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        group.shutdown().await;
    }

    #[tokio::test]
    async fn bounded_resync_failure_still_emits_finished_callback() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "Code": 5000,
                "Error": "boom"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        )]));
        let auth_router = AuthRouter::new(AccountRegistry::from_sessions(vec![sample_session(
            "uid-1",
            "alice@proton.me",
            "pass-a",
        )]));
        let store = InMemoryStore::new();
        let checkpoints: SharedCheckpointStore = Arc::new(InMemoryCheckpointStore::new());

        let observed = Arc::new(StdMutex::new(Vec::new()));
        let observed_sink = observed.clone();
        let callback: SyncProgressCallback = Arc::new(move |event| {
            observed_sink.lock().unwrap().push(event);
        });
        let config = event_worker_config(&server.uri(), runtime, auth_router, store, checkpoints)
            .with_sync_progress_callback(callback);

        let mut session = sample_session("uid-1", "alice@proton.me", "pass-a");
        let mut client = ProtonClient::authenticated_with_mode(
            &server.uri(),
            session.api_mode,
            &session.uid,
            &session.access_token,
        )
        .unwrap();

        let err = bounded_resync_account(&config, &mut session, &mut client)
            .await
            .unwrap_err();
        assert!(matches!(err, EventWorkerError::Api(_)));

        let snapshot = observed.lock().unwrap().clone();
        assert_eq!(snapshot.len(), 2, "expected started+finished only");
        assert!(matches!(
            &snapshot[0],
            SyncProgressUpdate::Started { user_id } if user_id == "uid-1"
        ));
        assert!(matches!(
            &snapshot[1],
            SyncProgressUpdate::Finished { user_id } if user_id == "uid-1"
        ));
    }

    #[tokio::test]
    async fn vault_checkpoint_restart_continuity_resumes_cursor() {
        let tmp = tempdir().unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 0,
                "Messages": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session.clone()]));
        let auth_router = AuthRouter::new(AccountRegistry::from_single_session(session.clone()));
        let store = InMemoryStore::new();
        let checkpoints: SharedCheckpointStore =
            Arc::new(VaultCheckpointStore::new(tmp.path().to_path_buf()));
        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store,
            checkpoints.clone(),
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_event_worker_with_shutdown(
            config,
            Duration::from_secs(3600),
            shutdown_rx,
        ));
        let checkpoint = wait_for_checkpoint(
            checkpoints.as_ref(),
            &AccountId("uid-1".to_string()),
            Duration::from_secs(8),
        )
        .await
        .expect("first run should persist a checkpoint");
        let _ = shutdown_tx.send(true);
        let _ = handle.await;

        assert_eq!(checkpoint.last_event_id, "event-1");

        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-1"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-2",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;

        // Simulate restart with fresh runtime + store + checkpoint store.
        let runtime_after_restart = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let auth_router_after_restart = AuthRouter::new(AccountRegistry::from_single_session(
            sample_session("uid-1", "alice@proton.me", "pass-a"),
        ));
        let store_after_restart = InMemoryStore::new();
        let checkpoints_after_restart: SharedCheckpointStore =
            Arc::new(VaultCheckpointStore::new(tmp.path().to_path_buf()));
        let config_after_restart = event_worker_config(
            &server.uri(),
            runtime_after_restart,
            auth_router_after_restart,
            store_after_restart,
            checkpoints_after_restart.clone(),
        );

        let (shutdown_tx_2, shutdown_rx_2) = watch::channel(false);
        let handle_2 = tokio::spawn(run_event_worker_with_shutdown(
            config_after_restart,
            Duration::from_secs(3600),
            shutdown_rx_2,
        ));
        let checkpoint_after_restart = wait_for_checkpoint_event_id(
            checkpoints_after_restart.as_ref(),
            &AccountId("uid-1".to_string()),
            "event-2",
            Duration::from_secs(8),
        )
        .await
        .expect("second run should advance checkpoint");
        let _ = shutdown_tx_2.send(true);
        let _ = handle_2.await;

        assert_eq!(checkpoint_after_restart.last_event_id, "event-2");
    }

    #[tokio::test]
    async fn startup_with_cached_mail_and_missing_cursor_bootstraps_latest_event_id() {
        let tmp = tempdir().unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-1"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let store_root = tmp.path().join("gluon");
        let mut account_storage_ids = HashMap::new();
        account_storage_ids.insert("uid-1".to_string(), "storage-uid-1".to_string());
        let store = crate::imap::store::new_runtime_message_store(
            store_root.clone(),
            account_storage_ids.clone(),
        )
        .unwrap();
        store
            .store_metadata(
                "uid-1::INBOX",
                "msg-1",
                MessageMetadata {
                    id: "msg-1".to_string(),
                    address_id: "addr-1".to_string(),
                    label_ids: vec!["0".to_string()],
                    external_id: None,
                    subject: "Cached message".to_string(),
                    sender: crate::api::types::EmailAddress {
                        name: "Alice".to_string(),
                        address: "alice@proton.me".to_string(),
                    },
                    to_list: vec![],
                    cc_list: vec![],
                    bcc_list: vec![],
                    reply_tos: vec![],
                    flags: 0,
                    time: 1700000000,
                    size: 100,
                    unread: 1,
                    is_replied: 0,
                    is_replied_all: 0,
                    is_forwarded: 0,
                    num_attachments: 0,
                },
            )
            .await
            .unwrap();
        drop(store);

        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session.clone()]));
        let auth_router = AuthRouter::new(AccountRegistry::from_single_session(session));
        let store_after_restart =
            crate::imap::store::new_runtime_message_store(store_root, account_storage_ids).unwrap();
        let checkpoints: SharedCheckpointStore =
            Arc::new(VaultCheckpointStore::new(tmp.path().to_path_buf()));
        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store_after_restart.clone(),
            checkpoints.clone(),
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_event_worker_with_shutdown(
            config,
            Duration::from_secs(3600),
            shutdown_rx,
        ));
        let checkpoint = wait_for_checkpoint_event_id(
            checkpoints.as_ref(),
            &AccountId("uid-1".to_string()),
            "event-1",
            Duration::from_secs(8),
        )
        .await
        .expect("cached restart should bootstrap a latest event cursor");
        let _ = shutdown_tx.send(true);
        let _ = handle.await;

        assert_eq!(checkpoint.sync_state.as_deref(), Some("baseline_cursor"));
        assert_eq!(
            store_after_restart
                .get_uid("uid-1::INBOX", "msg-1")
                .await
                .unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn vault_checkpoint_restart_recovers_from_stale_cursor() {
        let tmp = tempdir().unwrap();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/stale-event"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2011,
                "Error": "Invalid event ID"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Messages": [{
                    "ID": "msg-stale-recovery-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Recovered from stale cursor",
                    "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 100,
                    "Unread": 1,
                    "NumAttachments": 0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-uid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-2",
                "More": 0,
                "Refresh": 0,
                "Events": []
            })))
            .mount(&server)
            .await;

        let session = sample_session("uid-1", "alice@proton.me", "pass-a");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let checkpoint_store = VaultCheckpointStore::new(tmp.path().to_path_buf());
        checkpoint_store
            .save_checkpoint(
                &AccountId("uid-1".to_string()),
                &EventCheckpoint {
                    last_event_id: "stale-event".to_string(),
                    last_event_ts: Some(unix_now()),
                    sync_state: Some("ok".to_string()),
                },
            )
            .unwrap();

        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![session.clone()]));
        let auth_router = AuthRouter::new(AccountRegistry::from_single_session(session));
        let store = InMemoryStore::new();
        let checkpoints: SharedCheckpointStore =
            Arc::new(VaultCheckpointStore::new(tmp.path().to_path_buf()));
        let config = event_worker_config(
            &server.uri(),
            runtime,
            auth_router,
            store,
            checkpoints.clone(),
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_event_worker_with_shutdown(
            config,
            Duration::from_secs(3600),
            shutdown_rx,
        ));
        let checkpoint_after_recovery = wait_for_checkpoint_event_id(
            checkpoints.as_ref(),
            &AccountId("uid-1".to_string()),
            "event-2",
            Duration::from_secs(6),
        )
        .await
        .expect("stale cursor recovery should converge to fresh event id");
        let _ = shutdown_tx.send(true);
        let _ = handle.await;

        assert_eq!(checkpoint_after_recovery.last_event_id, "event-2");
        assert_eq!(
            checkpoint_after_recovery.sync_state.as_deref(),
            Some("cursor_reset_resync")
        );
    }

    async fn wait_for_checkpoint(
        checkpoints: &dyn EventCheckpointStore<Error = ()>,
        account_id: &AccountId,
        timeout: Duration,
    ) -> Option<EventCheckpoint> {
        let start = tokio::time::Instant::now();
        loop {
            if let Ok(Some(cp)) = checkpoints.load_checkpoint(account_id) {
                return Some(cp);
            }
            if start.elapsed() >= timeout {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_for_checkpoint_event_id(
        checkpoints: &dyn EventCheckpointStore<Error = ()>,
        account_id: &AccountId,
        expected_event_id: &str,
        timeout: Duration,
    ) -> Option<EventCheckpoint> {
        let start = tokio::time::Instant::now();
        loop {
            if let Ok(Some(cp)) = checkpoints.load_checkpoint(account_id) {
                if cp.last_event_id == expected_event_id {
                    return Some(cp);
                }
            }
            if start.elapsed() >= timeout {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
