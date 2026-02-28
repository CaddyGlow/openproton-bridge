use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::api::client::ProtonClient;
use crate::api::error::{is_auth_error, ApiError};
use crate::api::events as api_events;
use crate::api::messages;
use crate::api::types::{MessageFilter, MessageMetadata, Session};
use crate::api::users;
use crate::bridge::auth_router::AuthRouter;
use crate::imap::mailbox;
use crate::imap::store::MessageStore;

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
const RESYNC_MAX_PAGES_PER_MAILBOX: usize = 4;
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(300);
const WORKER_STATS_LOG_EVERY_ATTEMPTS: u64 = 20;

pub struct EventWorkerGroup {
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
}

impl EventWorkerGroup {
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        for mut handle in self.handles {
            tokio::select! {
                _ = &mut handle => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    handle.abort();
                    let _ = handle.await;
                }
            }
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

#[derive(Clone)]
pub struct EventWorkerConfig {
    pub account_id: AccountId,
    pub account_email: String,
    pub api_base_url: String,
    pub runtime_accounts: Arc<RuntimeAccountRegistry>,
    pub auth_router: AuthRouter,
    pub store: Arc<dyn MessageStore>,
    pub checkpoint_store: SharedCheckpointStore,
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
            checkpoint_store,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventDelta {
    MessageUpsert(String),
    MessageDelete(String),
    AddressesChanged,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn scoped_mailbox_name(account_id: &AccountId, mailbox_name: &str) -> String {
    format!("{}::{}", account_id.0, mailbox_name)
}

fn extract_message_id(value: &serde_json::Value, fallback_key: Option<&str>) -> Option<String> {
    if let Some(id) = value.get("ID").and_then(|v| v.as_str()) {
        return Some(id.to_string());
    }
    fallback_key.map(str::to_string)
}

fn is_delete_action(value: &serde_json::Value) -> bool {
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
    if let Some(action) = value.get("Action") {
        if let Some(code) = action.as_i64() {
            return code == 2 || code == 3;
        }
        if let Some(name) = action.as_str() {
            let name = name.to_ascii_lowercase();
            return name.contains("delete") || name.contains("remove");
        }
    }
    false
}

fn parse_message_deltas(payload: &serde_json::Value, out: &mut Vec<EventDelta>) {
    let mut push_message_delta = |entry: &serde_json::Value, fallback_key: Option<&str>| {
        let Some(message_id) = extract_message_id(entry, fallback_key) else {
            return;
        };
        if is_delete_action(entry) {
            out.push(EventDelta::MessageDelete(message_id));
        } else {
            out.push(EventDelta::MessageUpsert(message_id));
        }
    };

    if let Some(messages) = payload.get("Messages") {
        if let Some(array) = messages.as_array() {
            for entry in array {
                push_message_delta(entry, None);
            }
        } else if let Some(object) = messages.as_object() {
            for (message_id, entry) in object {
                push_message_delta(entry, Some(message_id));
            }
        }
    }

    if let Some(message) = payload.get("Message") {
        if message.is_object() {
            push_message_delta(message, None);
        }
    }
}

fn parse_event_deltas(payload: &serde_json::Value) -> Vec<EventDelta> {
    let mut out = Vec::new();
    parse_message_deltas(payload, &mut out);

    if payload.get("Addresses").is_some() || payload.get("Address").is_some() {
        out.push(EventDelta::AddressesChanged);
    }

    out
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
    Ok(ProtonClient::authenticated(
        &config.api_base_url,
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
) -> Result<(), EventWorkerError> {
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
) -> Result<(), EventWorkerError> {
    let metadata = fetch_message_metadata_with_retry(config, session, client, message_id).await?;

    apply_metadata_to_store(config, &metadata).await
}

async fn apply_metadata_to_store(
    config: &EventWorkerConfig,
    metadata: &MessageMetadata,
) -> Result<(), EventWorkerError> {
    for mb in mailbox::system_mailboxes() {
        if !mb.selectable {
            continue;
        }
        let scoped = scoped_mailbox_name(&config.account_id, mb.name);
        let in_mailbox = metadata.label_ids.iter().any(|label| label == mb.label_id);
        if in_mailbox {
            let uid = config
                .store
                .store_metadata(&scoped, &metadata.id, metadata.clone())
                .await
                .map_err(|e| EventWorkerError::Payload(e.to_string()))?;
            let flags = mailbox::message_flags(&metadata)
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>();
            config
                .store
                .set_flags(&scoped, uid, flags)
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

async fn bounded_resync_account(
    config: &EventWorkerConfig,
    session: &mut Session,
    client: &mut ProtonClient,
) -> Result<(), EventWorkerError> {
    let mut synced_message_ids = HashSet::new();
    let mut total_applied = 0usize;

    for mb in mailbox::system_mailboxes() {
        if !mb.selectable {
            continue;
        }

        let mut page = 0i32;
        for _ in 0..RESYNC_MAX_PAGES_PER_MAILBOX {
            let filter = MessageFilter {
                label_id: Some(mb.label_id.to_string()),
                desc: 1,
                ..Default::default()
            };
            let messages = fetch_message_metadata_page_with_retry(
                config,
                session,
                client,
                &filter,
                page,
                RESYNC_PAGE_SIZE,
            )
            .await?;
            if messages.is_empty() {
                break;
            }

            let page_count = messages.len() as i32;
            for metadata in messages {
                if synced_message_ids.insert(metadata.id.clone()) {
                    apply_metadata_to_store(config, &metadata).await?;
                    total_applied += 1;
                }
            }

            if page_count < RESYNC_PAGE_SIZE {
                break;
            }
            page += 1;
        }
    }

    debug!(
        account_id = %config.account_id.0,
        account_email = %config.account_email,
        total_applied,
        "completed bounded refresh resync"
    );

    Ok(())
}

async fn apply_message_delete(
    config: &EventWorkerConfig,
    message_id: &str,
) -> Result<(), EventWorkerError> {
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
    Ok(())
}

pub async fn poll_account_once(
    config: &EventWorkerConfig,
    last_event_id: &str,
) -> Result<String, EventWorkerError> {
    let mut session = config
        .runtime_accounts
        .with_valid_access_token(&config.account_id)
        .await?;

    let mut client =
        ProtonClient::authenticated(&config.api_base_url, &session.uid, &session.access_token)?;

    let mut cursor = last_event_id.to_string();
    let mut pages = 0usize;

    loop {
        pages += 1;
        if pages > 32 {
            warn!(
                account_id = %config.account_id.0,
                account_email = %config.account_email,
                "event poll reached page safety limit"
            );
            break;
        }

        let response = fetch_events_with_retry(config, &mut session, &mut client, &cursor).await?;

        let mut address_changed = response.refresh != 0;
        let mut used_refresh_resync = false;
        if response.refresh != 0 {
            bounded_resync_account(config, &mut session, &mut client).await?;
            used_refresh_resync = true;
        }
        for event in &response.events {
            for delta in parse_event_deltas(event) {
                match delta {
                    EventDelta::MessageUpsert(id) => {
                        apply_message_upsert(config, &mut session, &mut client, &id).await?;
                    }
                    EventDelta::MessageDelete(id) => {
                        apply_message_delete(config, &id).await?;
                    }
                    EventDelta::AddressesChanged => {
                        address_changed = true;
                    }
                }
            }
        }

        if address_changed {
            refresh_address_index_with_retry(config, &mut session, &mut client).await?;
        }

        let next_event_id = if response.event_id.is_empty() {
            cursor.clone()
        } else {
            response.event_id.clone()
        };

        if next_event_id != cursor || !response.events.is_empty() {
            let checkpoint = EventCheckpoint {
                last_event_id: next_event_id.clone(),
                last_event_ts: Some(unix_now()),
                sync_state: Some(if used_refresh_resync {
                    "refresh_resync".to_string()
                } else if response.refresh != 0 {
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
    let mut consecutive_failures = 0u32;
    let mut next_delay = Duration::ZERO;
    let mut stats = EventWorkerStats::default();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(next_delay) => {
                match poll_account_once(&config, &last_event_id).await {
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
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let handles = accounts
        .into_iter()
        .map(|account| {
            let config = EventWorkerConfig::new(
                account.account_id,
                account.email,
                api_base_url.clone(),
                runtime_accounts.clone(),
                auth_router.clone(),
                store.clone(),
                checkpoint_store.clone(),
            );
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
    accounts
        .into_iter()
        .map(|account| {
            let config = EventWorkerConfig::new(
                account.account_id,
                account.email,
                api_base_url.clone(),
                runtime_accounts.clone(),
                auth_router.clone(),
                store.clone(),
                checkpoint_store.clone(),
            );
            tokio::spawn(run_event_worker(config, poll_interval))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::api::types::Session;
    use crate::bridge::accounts::AccountHealth;
    use crate::bridge::accounts::AccountRegistry;
    use crate::imap::store::InMemoryStore;
    use tempfile::tempdir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_session(uid: &str, email: &str, bridge_password: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: format!("access-{uid}"),
            refresh_token: format!("refresh-{uid}"),
            email: email.to_string(),
            display_name: email.to_string(),
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
    async fn poll_account_once_handles_delete_delta() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "More": 0,
                "Refresh": 0,
                "Events": [{"Messages": [{"ID": "msg-1", "Action": 2}]}]
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
                    subject: "x".to_string(),
                    sender: crate::api::types::EmailAddress {
                        name: "A".to_string(),
                        address: "a@b.com".to_string(),
                    },
                    to_list: vec![],
                    cc_list: vec![],
                    bcc_list: vec![],
                    time: 0,
                    size: 1,
                    unread: 1,
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
    async fn start_event_workers_starts_one_task_per_account() {
        let accounts = vec![
            RuntimeAccountInfo {
                account_id: AccountId("uid-1".to_string()),
                email: "a@proton.me".to_string(),
                health: AccountHealth::Healthy,
            },
            RuntimeAccountInfo {
                account_id: AccountId("uid-2".to_string()),
                email: "b@proton.me".to_string(),
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
                health: AccountHealth::Healthy,
            },
            RuntimeAccountInfo {
                account_id: AccountId("uid-2".to_string()),
                email: "b@proton.me".to_string(),
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
        Mock::given(method("GET"))
            .and(path("/core/v4/events"))
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
                health: AccountHealth::Unavailable,
            },
            RuntimeAccountInfo {
                account_id: AccountId("uid-2".to_string()),
                email: "b@proton.me".to_string(),
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
}
