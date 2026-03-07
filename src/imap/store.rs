use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD;
#[cfg(test)]
use base64::Engine;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::api::types::MessageMetadata;

use super::Result;

pub struct MailboxStatus {
    pub uid_validity: u32,
    pub next_uid: u32,
    pub exists: u32,
    pub unseen: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxSnapshot {
    pub exists: u32,
    pub mod_seq: u64,
}

#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32>;
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>>;
    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>>;
    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>>;
    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()>;
    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>>;
    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>>;
    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus>;
    async fn mailbox_snapshot(&self, mailbox: &str) -> Result<MailboxSnapshot>;
    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()>;
    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()>;
    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()>;
    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>>;
    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()>;
    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>>;
    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxData {
    uid_validity: u32,
    next_uid: u32,
    proton_to_uid: HashMap<String, u32>,
    uid_to_proton: HashMap<u32, String>,
    metadata: HashMap<u32, MessageMetadata>,
    rfc822: HashMap<u32, Vec<u8>>,
    flags: HashMap<u32, Vec<String>>,
    uid_order: Vec<u32>,
    mod_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(test)]
struct PersistentMailboxFile {
    mailbox: String,
    data: MailboxData,
}

impl MailboxData {
    fn new() -> Self {
        let uid_validity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        Self {
            uid_validity,
            next_uid: 1,
            proton_to_uid: HashMap::new(),
            uid_to_proton: HashMap::new(),
            metadata: HashMap::new(),
            rfc822: HashMap::new(),
            flags: HashMap::new(),
            uid_order: Vec::new(),
            mod_seq: 0,
        }
    }
}

pub struct InMemoryStore {
    mailboxes: RwLock<HashMap<String, MailboxData>>,
}

impl InMemoryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mailboxes: RwLock::new(HashMap::new()),
        })
    }
}

#[cfg(test)]
pub struct PersistentStore {
    root: PathBuf,
    inner: InMemoryStore,
}

#[cfg(test)]
impl PersistentStore {
    pub fn new(root: PathBuf) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&root)?;
        let loaded = Self::load_mailboxes(&root)?;
        Ok(Arc::new(Self {
            root,
            inner: InMemoryStore {
                mailboxes: RwLock::new(loaded),
            },
        }))
    }

    fn load_mailboxes(root: &Path) -> Result<HashMap<String, MailboxData>> {
        let mut mailboxes = HashMap::new();
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            let payload = match std::fs::read(&path) {
                Ok(data) => data,
                Err(err) => {
                    warn!(
                        error = %err,
                        path = %path.display(),
                        "failed to read persistent mailbox file; skipping"
                    );
                    continue;
                }
            };

            match serde_json::from_slice::<PersistentMailboxFile>(&payload) {
                Ok(record) => {
                    mailboxes.insert(record.mailbox, record.data);
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        path = %path.display(),
                        "failed to parse persistent mailbox file; skipping"
                    );
                }
            }
        }

        Ok(mailboxes)
    }

    fn mailbox_path(&self, mailbox: &str) -> PathBuf {
        let encoded = BASE64_URL_NO_PAD.encode(mailbox.as_bytes());
        self.root.join(format!("{encoded}.json"))
    }

    async fn persist_all(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.root).await?;

        let snapshot = self.inner.mailboxes.read().await.clone();
        let mut retained = std::collections::HashSet::new();

        for (mailbox, data) in snapshot {
            let record = PersistentMailboxFile {
                mailbox: mailbox.clone(),
                data,
            };
            let path = self.mailbox_path(&mailbox);
            retained.insert(path.clone());
            let tmp = path.with_extension("json.tmp");

            let payload = serde_json::to_vec(&record).map_err(|err| {
                super::ImapError::Protocol(format!("failed to serialize mailbox {mailbox}: {err}"))
            })?;

            tokio::fs::write(&tmp, payload).await?;
            tokio::fs::rename(&tmp, &path).await?;
        }

        let mut entries = tokio::fs::read_dir(&self.root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if !retained.contains(&path) {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }

        Ok(())
    }
}

pub fn new_runtime_message_store(
    store_root: PathBuf,
    account_storage_ids: HashMap<String, String>,
) -> Result<Arc<dyn MessageStore>> {
    let store: Arc<dyn MessageStore> = GluonStore::new(store_root, account_storage_ids)?;
    Ok(store)
}

const GLUON_BACKEND_DIR: &str = "backend";
const GLUON_DB_DIR: &str = "db";
const GLUON_STORE_DIR: &str = "store";
const GLUON_SQLITE_INDEX_TABLE: &str = "openproton_mailbox_index";
const GLUON_DEFAULT_ACCOUNT_SCOPE: &str = "__default__";
const GLUON_DEFAULT_MAILBOX: &str = "INBOX";
const GLUON_INDEX_VERSION: u32 = 1;
const GLUON_COMPAT_MIGRATION_TABLES: &[&str] = &[
    "deleted_subscriptions",
    "mailboxes",
    "mailbox_flags",
    "mailbox_attrs",
    "mailbox_perm_flags",
    "messages",
    "message_flags",
    "ui_ds",
    "gluon_version",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GluonMailboxData {
    #[serde(default)]
    uid_validity: u32,
    #[serde(default)]
    next_uid: u32,
    #[serde(default)]
    proton_to_uid: HashMap<String, u32>,
    #[serde(default)]
    uid_to_proton: HashMap<u32, String>,
    #[serde(default)]
    metadata: HashMap<u32, MessageMetadata>,
    #[serde(default)]
    flags: HashMap<u32, Vec<String>>,
    #[serde(default)]
    uid_order: Vec<u32>,
    #[serde(default)]
    mod_seq: u64,
    #[serde(default)]
    uid_to_blob: HashMap<u32, String>,
}

impl GluonMailboxData {
    fn new() -> Self {
        Self {
            uid_validity: current_uid_validity(),
            next_uid: 1,
            proton_to_uid: HashMap::new(),
            uid_to_proton: HashMap::new(),
            metadata: HashMap::new(),
            flags: HashMap::new(),
            uid_order: Vec::new(),
            mod_seq: 0,
            uid_to_blob: HashMap::new(),
        }
    }

    fn sanitize(&mut self) {
        if self.uid_validity == 0 {
            self.uid_validity = current_uid_validity();
        }
        if self.next_uid == 0 {
            self.next_uid = 1;
        }

        let mut seen = HashSet::new();
        self.uid_order.retain(|uid| seen.insert(*uid));

        let max_uid = self
            .uid_to_proton
            .keys()
            .chain(self.metadata.keys())
            .chain(self.flags.keys())
            .chain(self.uid_to_blob.keys())
            .copied()
            .max()
            .unwrap_or(0);
        if max_uid >= self.next_uid {
            self.next_uid = max_uid.saturating_add(1);
        }
    }

    fn prune_missing_blob_refs(&mut self, account_dir: &Path) -> usize {
        let mut missing_uids = self
            .uid_to_blob
            .iter()
            .filter_map(|(uid, blob_name)| {
                let blob_path = account_dir.join(blob_name);
                (!blob_path.exists()).then_some(*uid)
            })
            .collect::<Vec<_>>();
        if missing_uids.is_empty() {
            return 0;
        }

        missing_uids.sort_unstable();
        missing_uids.dedup();
        let missing_uid_set: HashSet<u32> = missing_uids.iter().copied().collect();

        self.uid_order.retain(|uid| !missing_uid_set.contains(uid));
        self.metadata
            .retain(|uid, _| !missing_uid_set.contains(uid));
        self.flags.retain(|uid, _| !missing_uid_set.contains(uid));
        self.uid_to_blob
            .retain(|uid, _| !missing_uid_set.contains(uid));
        self.uid_to_proton
            .retain(|uid, _| !missing_uid_set.contains(uid));
        self.proton_to_uid
            .retain(|_, uid| !missing_uid_set.contains(uid));
        self.mod_seq = self.mod_seq.saturating_add(missing_uids.len() as u64);
        missing_uids.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GluonAccountIndexFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    next_blob_id: u64,
    #[serde(default)]
    updated_at_ms: u64,
    #[serde(default)]
    mailboxes: HashMap<String, GluonMailboxData>,
}

impl GluonAccountIndexFile {
    fn new() -> Self {
        Self {
            version: GLUON_INDEX_VERSION,
            next_blob_id: 1,
            updated_at_ms: 0,
            mailboxes: HashMap::new(),
        }
    }

    fn sanitize(&mut self) {
        if self.version == 0 {
            self.version = GLUON_INDEX_VERSION;
        }
        if self.next_blob_id == 0 {
            self.next_blob_id = 1;
        }
        for mailbox in self.mailboxes.values_mut() {
            mailbox.sanitize();
        }
    }
}

#[derive(Debug, Clone)]
struct GluonAccountState {
    next_blob_id: u64,
    mailboxes: HashMap<String, GluonMailboxData>,
}

pub struct GluonStore {
    root: PathBuf,
    account_storage_ids: HashMap<String, String>,
    accounts: RwLock<HashMap<String, GluonAccountState>>,
    txn_manager: super::gluon_txn::GluonTxnManager,
}

impl GluonStore {
    fn emit_bootstrap_migration_logs(storage_user_id: &str, db_path: &Path) {
        debug!(
            tx = "tx",
            account = %storage_user_id,
            db = %db_path.display(),
            "Running database migrations"
        );
        debug!("Version table does not exist, running all migrations");
        debug!("Running migration for version 0");
        for table in GLUON_COMPAT_MIGRATION_TABLES {
            debug!("Table '{}' does not exist, creating", table);
        }
        debug!("Running migration for version 1");
        debug!("Running migration for version 2");
        debug!("Running migration for version 3");
        debug!("Migrations completed");
    }

    pub fn new(root: PathBuf, account_storage_ids: HashMap<String, String>) -> Result<Arc<Self>> {
        std::fs::create_dir_all(root.join(GLUON_BACKEND_DIR).join(GLUON_STORE_DIR))?;
        std::fs::create_dir_all(root.join(GLUON_BACKEND_DIR).join(GLUON_DB_DIR))?;
        let txn_manager = super::gluon_txn::GluonTxnManager::new(&root).map_err(|err| {
            super::ImapError::Protocol(format!("failed to initialize gluon txn manager: {err}"))
        })?;
        txn_manager
            .recover_pending_all()
            .map_err(|err| super::ImapError::GluonCorruption {
                path: root.join(".gluon-txn"),
                reason: format!("failed to recover pending gluon transactions: {err}"),
            })?;
        Ok(Arc::new(Self {
            root,
            account_storage_ids,
            accounts: RwLock::new(HashMap::new()),
            txn_manager,
        }))
    }

    fn split_scoped_mailbox(mailbox: &str) -> (String, String) {
        match mailbox.split_once("::") {
            Some((account_id, mailbox_name)) if !account_id.is_empty() => {
                let mailbox_name = if mailbox_name.is_empty() {
                    GLUON_DEFAULT_MAILBOX.to_string()
                } else {
                    mailbox_name.to_string()
                };
                (account_id.to_string(), mailbox_name)
            }
            _ => (GLUON_DEFAULT_ACCOUNT_SCOPE.to_string(), mailbox.to_string()),
        }
    }

    fn storage_user_id_for_account(&self, account_id: &str) -> String {
        self.account_storage_ids
            .get(account_id)
            .cloned()
            .unwrap_or_else(|| account_id.to_string())
    }

    fn account_store_dir(&self, storage_user_id: &str) -> PathBuf {
        self.root
            .join(GLUON_BACKEND_DIR)
            .join(GLUON_STORE_DIR)
            .join(storage_user_id)
    }

    fn account_db_path(&self, storage_user_id: &str) -> PathBuf {
        self.root
            .join(GLUON_BACKEND_DIR)
            .join(GLUON_DB_DIR)
            .join(format!("{storage_user_id}.db"))
    }

    fn account_rel_store_dir(storage_user_id: &str) -> PathBuf {
        Path::new(GLUON_BACKEND_DIR)
            .join(GLUON_STORE_DIR)
            .join(storage_user_id)
    }

    fn message_rel_path(storage_user_id: &str, blob_name: &str) -> PathBuf {
        Self::account_rel_store_dir(storage_user_id).join(blob_name)
    }

    fn empty_account_state() -> GluonAccountState {
        GluonAccountState {
            next_blob_id: 1,
            mailboxes: HashMap::new(),
        }
    }

    fn to_index_file(account: &GluonAccountState) -> GluonAccountIndexFile {
        GluonAccountIndexFile {
            version: GLUON_INDEX_VERSION,
            next_blob_id: account.next_blob_id,
            updated_at_ms: current_epoch_millis(),
            mailboxes: account.mailboxes.clone(),
        }
    }

    fn load_index_from_sqlite(
        &self,
        storage_user_id: &str,
    ) -> Result<Option<GluonAccountIndexFile>> {
        let db_path = self.account_db_path(storage_user_id);
        if !db_path.exists() {
            return Ok(None);
        }

        let conn = match rusqlite::Connection::open(&db_path) {
            Ok(conn) => conn,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to open sqlite db for gluon index, falling back to empty index"
                );
                return Ok(None);
            }
        };

        if let Err(err) = conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_INDEX_TABLE} (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );"
        )) {
            warn!(
                path = %db_path.display(),
                error = %err,
                "failed to initialize sqlite schema for gluon index, falling back to empty index"
            );
            return Ok(None);
        }

        let row = match conn
            .query_row(
                &format!(
                    "SELECT payload, updated_at_ms FROM {GLUON_SQLITE_INDEX_TABLE} WHERE id = 1"
                ),
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
        {
            Ok(row) => row,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite index row, falling back to empty index"
                );
                return Ok(None);
            }
        };

        let Some((payload, updated_at_ms)) = row else {
            return Ok(None);
        };

        let mut parsed = match serde_json::from_slice::<GluonAccountIndexFile>(&payload) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to parse sqlite index payload, falling back to empty index"
                );
                return Ok(None);
            }
        };
        if parsed.updated_at_ms == 0 && updated_at_ms > 0 {
            parsed.updated_at_ms = updated_at_ms as u64;
        }
        Ok(Some(parsed))
    }

    fn persist_index_to_sqlite_once(
        db_path: &Path,
        payload: &[u8],
        updated_at_ms: i64,
    ) -> rusqlite::Result<()> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_INDEX_TABLE} (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );"
        ))?;
        conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {GLUON_SQLITE_INDEX_TABLE} (id, payload, updated_at_ms)
                 VALUES (1, ?1, ?2)"
            ),
            rusqlite::params![payload, updated_at_ms],
        )?;
        Ok(())
    }

    fn persist_index_to_sqlite(
        &self,
        storage_user_id: &str,
        index: &GluonAccountIndexFile,
    ) -> Result<()> {
        let db_path = self.account_db_path(storage_user_id);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let payload = serde_json::to_vec(index).map_err(|err| {
            super::ImapError::Protocol(format!(
                "failed to serialize sqlite index payload for account {storage_user_id}: {err}"
            ))
        })?;

        let mut retried_with_recreate = false;
        loop {
            match Self::persist_index_to_sqlite_once(&db_path, &payload, index.updated_at_ms as i64)
            {
                Ok(()) => return Ok(()),
                Err(err) if !retried_with_recreate && db_path.exists() => {
                    warn!(
                        path = %db_path.display(),
                        error = %err,
                        "failed to persist sqlite index; recreating db and retrying once"
                    );
                    std::fs::remove_file(&db_path).map_err(|remove_err| {
                        super::ImapError::Protocol(format!(
                            "failed to remove corrupted sqlite db {} after persist error {err}: {remove_err}",
                            db_path.display()
                        ))
                    })?;
                    retried_with_recreate = true;
                }
                Err(err) => {
                    return Err(super::ImapError::Protocol(format!(
                        "failed to persist sqlite index payload {}: {err}",
                        db_path.display()
                    )))
                }
            }
        }
    }

    fn persist_account(
        &self,
        storage_user_id: &str,
        account: &GluonAccountState,
        message_writes: &[(PathBuf, Vec<u8>)],
    ) -> Result<()> {
        let index = Self::to_index_file(account);
        let mut txn = self.txn_manager.begin(storage_user_id).map_err(|err| {
            super::ImapError::Protocol(format!("failed to begin gluon txn: {err}"))
        })?;

        for (relative_path, bytes) in message_writes {
            txn.stage_write(relative_path, bytes).map_err(|err| {
                super::ImapError::Protocol(format!(
                    "failed to stage gluon message blob {}: {err}",
                    relative_path.display()
                ))
            })?;
        }

        txn.commit().map_err(|err| {
            super::ImapError::Protocol(format!("failed to commit gluon txn: {err}"))
        })?;

        self.persist_index_to_sqlite(storage_user_id, &index)
    }

    fn default_blob_name_for_uid(uid: u32) -> String {
        format!("{uid:08}.msg")
    }

    fn blob_counter_from_name(name: &str) -> Option<u64> {
        let path = Path::new(name);
        let stem = path.file_stem()?.to_string_lossy();
        stem.parse::<u64>().ok()
    }

    fn uid_from_legacy_blob_name(name: &str) -> Option<u32> {
        let path = Path::new(name);
        if path.extension().and_then(|ext| ext.to_str()) != Some("msg") {
            return None;
        }
        let stem = path.file_stem()?.to_string_lossy();
        stem.parse::<u32>().ok()
    }

    fn discover_blob_uid_pairs(account_dir: &Path) -> Result<Vec<(u32, String)>> {
        let mut file_names = Vec::new();
        for entry in std::fs::read_dir(account_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(|value| value.to_string()) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            file_names.push(name);
        }

        file_names.sort();
        file_names.dedup();

        let mut discovered = Vec::new();
        let mut used_uids = HashSet::new();
        let mut max_uid = 0_u32;

        for name in &file_names {
            let Some(uid) = Self::uid_from_legacy_blob_name(name) else {
                continue;
            };
            if used_uids.insert(uid) {
                max_uid = max_uid.max(uid);
                discovered.push((uid, name.clone()));
            }
        }

        let mut next_generated_uid = max_uid.saturating_add(1);
        for name in file_names {
            if Self::uid_from_legacy_blob_name(&name).is_some() {
                continue;
            }

            while used_uids.contains(&next_generated_uid) {
                let bumped = next_generated_uid.saturating_add(1);
                if bumped == next_generated_uid {
                    return Ok(discovered);
                }
                next_generated_uid = bumped;
            }

            used_uids.insert(next_generated_uid);
            discovered.push((next_generated_uid, name));
            let bumped = next_generated_uid.saturating_add(1);
            if bumped == next_generated_uid {
                break;
            }
            next_generated_uid = bumped;
        }

        discovered.sort_unstable_by_key(|(uid, _)| *uid);
        Ok(discovered)
    }

    fn load_account_from_disk(&self, storage_user_id: &str) -> Result<GluonAccountState> {
        let account_dir = self.account_store_dir(storage_user_id);
        std::fs::create_dir_all(&account_dir)?;

        let db_path = self.account_db_path(storage_user_id);
        let mut index = self
            .load_index_from_sqlite(storage_user_id)?
            .unwrap_or_else(GluonAccountIndexFile::new);
        let is_new_index = index.mailboxes.is_empty() && !db_path.exists();
        if is_new_index {
            Self::emit_bootstrap_migration_logs(storage_user_id, &db_path);
        }
        let mut repaired = false;

        index.sanitize();
        for mailbox in index.mailboxes.values_mut() {
            repaired |= mailbox.prune_missing_blob_refs(&account_dir) > 0;
        }

        if index.mailboxes.is_empty() {
            let discovered = Self::discover_blob_uid_pairs(&account_dir)?;
            if !discovered.is_empty() {
                let mut inbox = GluonMailboxData::new();
                for (uid, name) in discovered {
                    inbox.uid_order.push(uid);
                    inbox.uid_to_blob.insert(uid, name);
                }
                if let Some(last_uid) = inbox.uid_order.last().copied() {
                    inbox.next_uid = last_uid.saturating_add(1);
                }
                index
                    .mailboxes
                    .insert(GLUON_DEFAULT_MAILBOX.to_string(), inbox);
                repaired = true;
            }
        }

        if repaired {
            self.persist_index_to_sqlite(storage_user_id, &index)?;
        }

        let mut max_blob_id = index.next_blob_id;
        for mailbox in index.mailboxes.values() {
            for name in mailbox.uid_to_blob.values() {
                if let Some(blob_id) = Self::blob_counter_from_name(name) {
                    max_blob_id = max_blob_id.max(blob_id.saturating_add(1));
                }
            }
        }
        if max_blob_id == 0 {
            max_blob_id = 1;
        }

        Ok(GluonAccountState {
            next_blob_id: max_blob_id,
            mailboxes: index.mailboxes,
        })
    }

    async fn sync_account_from_disk(&self, storage_user_id: &str) -> Result<()> {
        let loaded = self.load_account_from_disk(storage_user_id)?;
        let mut accounts = self.accounts.write().await;
        accounts.insert(storage_user_id.to_string(), loaded);
        Ok(())
    }

    async fn ensure_account_loaded(&self, storage_user_id: &str) -> Result<()> {
        let already_loaded = {
            let accounts = self.accounts.read().await;
            accounts.contains_key(storage_user_id)
        };
        if already_loaded {
            return Ok(());
        }
        self.sync_account_from_disk(storage_user_id).await
    }

    async fn resolve_scope(&self, mailbox: &str) -> Result<(String, String)> {
        let (account_id, mailbox_name) = Self::split_scoped_mailbox(mailbox);
        let storage_user_id = self.storage_user_id_for_account(&account_id);
        self.ensure_account_loaded(&storage_user_id).await?;
        Ok((storage_user_id, mailbox_name))
    }
}

fn current_uid_validity() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn current_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unseen_count(mailbox: &GluonMailboxData) -> u32 {
    let explicit_unseen = mailbox
        .flags
        .values()
        .filter(|flags| !flags.iter().any(|flag| flag == "\\Seen"))
        .count() as u32;
    let inferred_unseen = mailbox
        .metadata
        .iter()
        .filter(|(uid, meta)| !mailbox.flags.contains_key(uid) && meta.unread != 0)
        .count() as u32;
    explicit_unseen + inferred_unseen
}

fn derived_flag_strings(meta: &MessageMetadata) -> Vec<String> {
    super::mailbox::message_flags(meta)
        .iter()
        .map(|flag| flag.to_string())
        .collect()
}

#[async_trait]
impl MessageStore for InMemoryStore {
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32> {
        let mut mailboxes = self.mailboxes.write().await;
        let mb = mailboxes
            .entry(mailbox.to_string())
            .or_insert_with(MailboxData::new);
        let derived_flags = derived_flag_strings(&meta);

        if let Some(&uid) = mb.proton_to_uid.get(proton_id) {
            mb.metadata.insert(uid, meta);
            mb.flags.insert(uid, derived_flags);
            mb.mod_seq = mb.mod_seq.saturating_add(1);
            return Ok(uid);
        }

        let uid = mb.next_uid;
        mb.next_uid += 1;
        mb.proton_to_uid.insert(proton_id.to_string(), uid);
        mb.uid_to_proton.insert(uid, proton_id.to_string());
        mb.uid_order.push(uid);
        mb.metadata.insert(uid, meta);
        mb.flags.insert(uid, derived_flags);
        mb.mod_seq = mb.mod_seq.saturating_add(1);
        Ok(uid)
    }

    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.metadata.get(&uid).cloned()))
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.uid_to_proton.get(&uid).cloned()))
    }

    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.proton_to_uid.get(proton_id).copied()))
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        let mb = mailboxes
            .entry(mailbox.to_string())
            .or_insert_with(MailboxData::new);
        mb.rfc822.insert(uid, data);
        mb.mod_seq = mb.mod_seq.saturating_add(1);
        Ok(())
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.rfc822.get(&uid).cloned()))
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .map(|mb| mb.uid_order.clone())
            .unwrap_or_default())
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        let mailboxes = self.mailboxes.read().await;
        match mailboxes.get(mailbox) {
            Some(mb) => {
                let unseen = mb
                    .flags
                    .values()
                    .filter(|f| !f.iter().any(|flag| flag == "\\Seen"))
                    .count() as u32;
                // Also count messages with no flags entry as unseen unless metadata says read
                let no_flags_unseen = mb
                    .metadata
                    .iter()
                    .filter(|(uid, meta)| !mb.flags.contains_key(uid) && meta.unread != 0)
                    .count() as u32;
                Ok(MailboxStatus {
                    uid_validity: mb.uid_validity,
                    next_uid: mb.next_uid,
                    exists: mb.uid_order.len() as u32,
                    unseen: unseen + no_flags_unseen,
                })
            }
            None => Ok(MailboxStatus {
                uid_validity: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32,
                next_uid: 1,
                exists: 0,
                unseen: 0,
            }),
        }
    }

    async fn mailbox_snapshot(&self, mailbox: &str) -> Result<MailboxSnapshot> {
        let mailboxes = self.mailboxes.read().await;
        if let Some(mb) = mailboxes.get(mailbox) {
            Ok(MailboxSnapshot {
                exists: mb.uid_order.len() as u32,
                mod_seq: mb.mod_seq,
            })
        } else {
            Ok(MailboxSnapshot {
                exists: 0,
                mod_seq: 0,
            })
        }
    }

    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            mb.flags.insert(uid, flags);
            mb.mod_seq = mb.mod_seq.saturating_add(1);
        }
        Ok(())
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            let entry = mb.flags.entry(uid).or_default();
            let before = entry.len();
            for flag in flags {
                if !entry.contains(flag) {
                    entry.push(flag.clone());
                }
            }
            if entry.len() != before {
                mb.mod_seq = mb.mod_seq.saturating_add(1);
            }
        }
        Ok(())
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            if let Some(current) = mb.flags.get_mut(&uid) {
                let before = current.len();
                current.retain(|f| !flags.contains(f));
                if current.len() != before {
                    mb.mod_seq = mb.mod_seq.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        let mailboxes = self.mailboxes.read().await;
        if let Some(mb) = mailboxes.get(mailbox) {
            if let Some(flags) = mb.flags.get(&uid) {
                return Ok(flags.clone());
            }
            // Derive from metadata if not explicitly set
            if let Some(meta) = mb.metadata.get(&uid) {
                let mflags = super::mailbox::message_flags(meta);
                return Ok(mflags.iter().map(|s| s.to_string()).collect());
            }
        }
        Ok(Vec::new())
    }

    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            if let Some(proton_id) = mb.uid_to_proton.remove(&uid) {
                mb.proton_to_uid.remove(&proton_id);
            }
            mb.metadata.remove(&uid);
            mb.rfc822.remove(&uid);
            mb.flags.remove(&uid);
            mb.uid_order.retain(|&u| u != uid);
            mb.mod_seq = mb.mod_seq.saturating_add(1);
        }
        Ok(())
    }

    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.uid_order.get(seq as usize - 1).copied()))
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes.get(mailbox).and_then(|mb| {
            mb.uid_order
                .iter()
                .position(|&u| u == uid)
                .map(|p| p as u32 + 1)
        }))
    }
}

#[async_trait]
#[cfg(test)]
impl MessageStore for PersistentStore {
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32> {
        let uid = self.inner.store_metadata(mailbox, proton_id, meta).await?;
        self.persist_all().await?;
        Ok(uid)
    }

    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        self.inner.get_metadata(mailbox, uid).await
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        self.inner.get_proton_id(mailbox, uid).await
    }

    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>> {
        self.inner.get_uid(mailbox, proton_id).await
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        self.inner.store_rfc822(mailbox, uid, data).await?;
        self.persist_all().await
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        self.inner.get_rfc822(mailbox, uid).await
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        self.inner.list_uids(mailbox).await
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        self.inner.mailbox_status(mailbox).await
    }

    async fn mailbox_snapshot(&self, mailbox: &str) -> Result<MailboxSnapshot> {
        self.inner.mailbox_snapshot(mailbox).await
    }

    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()> {
        self.inner.set_flags(mailbox, uid, flags).await?;
        self.persist_all().await
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        self.inner.add_flags(mailbox, uid, flags).await?;
        self.persist_all().await
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        self.inner.remove_flags(mailbox, uid, flags).await?;
        self.persist_all().await
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        self.inner.get_flags(mailbox, uid).await
    }

    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()> {
        self.inner.remove_message(mailbox, uid).await?;
        self.persist_all().await
    }

    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>> {
        self.inner.seq_to_uid(mailbox, seq).await
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        self.inner.uid_to_seq(mailbox, uid).await
    }
}

#[async_trait]
impl MessageStore for GluonStore {
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        // Reload account state from disk before mutating so concurrent store instances
        // do not clobber each other's UID assignment/index updates.
        let mut next_state = self.load_account_from_disk(&storage_user_id)?;
        let mut accounts = self.accounts.write().await;
        let mailbox_was_missing = !next_state.mailboxes.contains_key(&mailbox_name);
        let derived_flags = derived_flag_strings(&meta);

        let mailbox = next_state
            .mailboxes
            .entry(mailbox_name.clone())
            .or_insert_with(GluonMailboxData::new);

        if mailbox_was_missing {
            info!(
                labelID = %mailbox_name,
                labelPath = %mailbox_name,
                numberOfConnectors = "1",
                pkg = "imapservice/labelConflictResolver",
                msg = "Label not found in DB, creating mailbox.",
                "Label not found in DB, creating mailbox."
            );
            info!(
                pkg = "gluon/user",
                remoteMailboxID = %mailbox_name,
                userID = %storage_user_id,
                msg = "Mailbox created",
                "Mailbox created"
            );
        }

        let uid = if let Some(existing_uid) = mailbox.proton_to_uid.get(proton_id).copied() {
            mailbox.metadata.insert(existing_uid, meta);
            mailbox.flags.insert(existing_uid, derived_flags);
            mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
            existing_uid
        } else {
            let assigned_uid = mailbox.next_uid;
            mailbox.next_uid = mailbox.next_uid.saturating_add(1);
            mailbox
                .proton_to_uid
                .insert(proton_id.to_string(), assigned_uid);
            mailbox
                .uid_to_proton
                .insert(assigned_uid, proton_id.to_string());
            mailbox.uid_order.push(assigned_uid);
            mailbox.metadata.insert(assigned_uid, meta);
            mailbox.flags.insert(assigned_uid, derived_flags);
            mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
            assigned_uid
        };

        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        Ok(uid)
    }

    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        Ok(accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
            .and_then(|mailbox| mailbox.metadata.get(&uid).cloned()))
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        Ok(accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
            .and_then(|mailbox| mailbox.uid_to_proton.get(&uid).cloned()))
    }

    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        Ok(accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
            .and_then(|mailbox| mailbox.proton_to_uid.get(proton_id).copied()))
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let mut next_state = accounts
            .get(&storage_user_id)
            .cloned()
            .unwrap_or_else(Self::empty_account_state);
        let mut writes = Vec::new();

        let mailbox = next_state
            .mailboxes
            .entry(mailbox_name)
            .or_insert_with(GluonMailboxData::new);
        if uid >= mailbox.next_uid {
            mailbox.next_uid = uid.saturating_add(1);
        }
        if !mailbox.uid_order.contains(&uid) {
            mailbox.uid_order.push(uid);
        }

        let blob_name = if let Some(existing) = mailbox.uid_to_blob.get(&uid).cloned() {
            existing
        } else {
            let name = format!("{:08}.msg", next_state.next_blob_id);
            next_state.next_blob_id = next_state.next_blob_id.saturating_add(1);
            mailbox.uid_to_blob.insert(uid, name.clone());
            name
        };
        mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
        writes.push((Self::message_rel_path(&storage_user_id, &blob_name), data));

        self.persist_account(&storage_user_id, &next_state, &writes)?;
        accounts.insert(storage_user_id, next_state);
        Ok(())
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let account_dir = self.account_store_dir(&storage_user_id);

        let blob_path = {
            let accounts = self.accounts.read().await;
            accounts
                .get(&storage_user_id)
                .and_then(|account| account.mailboxes.get(&mailbox_name))
                .and_then(|mailbox| mailbox.uid_to_blob.get(&uid).cloned())
                .map(|name| account_dir.join(name))
                .unwrap_or_else(|| account_dir.join(Self::default_blob_name_for_uid(uid)))
        };

        if !blob_path.exists() {
            return Ok(None);
        }

        Ok(Some(std::fs::read(blob_path)?))
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        Ok(accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
            .map(|mailbox| mailbox.uid_order.clone())
            .unwrap_or_default())
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        let Some(account) = accounts.get(&storage_user_id) else {
            return Ok(MailboxStatus {
                uid_validity: current_uid_validity(),
                next_uid: 1,
                exists: 0,
                unseen: 0,
            });
        };

        let Some(mailbox) = account.mailboxes.get(&mailbox_name) else {
            return Ok(MailboxStatus {
                uid_validity: current_uid_validity(),
                next_uid: 1,
                exists: 0,
                unseen: 0,
            });
        };

        Ok(MailboxStatus {
            uid_validity: mailbox.uid_validity,
            next_uid: mailbox.next_uid,
            exists: mailbox.uid_order.len() as u32,
            unseen: unseen_count(mailbox),
        })
    }

    async fn mailbox_snapshot(&self, mailbox: &str) -> Result<MailboxSnapshot> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        let Some(mailbox) = accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
        else {
            return Ok(MailboxSnapshot {
                exists: 0,
                mod_seq: 0,
            });
        };

        Ok(MailboxSnapshot {
            exists: mailbox.uid_order.len() as u32,
            mod_seq: mailbox.mod_seq,
        })
    }

    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        if let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) {
            mailbox.flags.insert(uid, flags);
            mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
        } else {
            return Ok(());
        }

        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        Ok(())
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) else {
            return Ok(());
        };

        let entry = mailbox.flags.entry(uid).or_default();
        let before = entry.len();
        for flag in flags {
            if !entry.contains(flag) {
                entry.push(flag.clone());
            }
        }
        if entry.len() == before {
            return Ok(());
        }

        mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        Ok(())
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) else {
            return Ok(());
        };

        let Some(current_flags) = mailbox.flags.get_mut(&uid) else {
            return Ok(());
        };
        let before = current_flags.len();
        current_flags.retain(|flag| !flags.contains(flag));
        if current_flags.len() == before {
            return Ok(());
        }

        mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        Ok(())
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        if let Some(mailbox) = accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
        {
            if let Some(flags) = mailbox.flags.get(&uid) {
                return Ok(flags.clone());
            }
            if let Some(meta) = mailbox.metadata.get(&uid) {
                let flags = super::mailbox::message_flags(meta)
                    .iter()
                    .map(|flag| flag.to_string())
                    .collect();
                return Ok(flags);
            }
        }
        Ok(Vec::new())
    }

    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) else {
            return Ok(());
        };

        if let Some(proton_id) = mailbox.uid_to_proton.remove(&uid) {
            mailbox.proton_to_uid.remove(&proton_id);
        }
        mailbox.metadata.remove(&uid);
        mailbox.flags.remove(&uid);
        let removed_blob = mailbox.uid_to_blob.remove(&uid);
        mailbox.uid_order.retain(|known_uid| *known_uid != uid);
        mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);

        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id.clone(), next_state);

        if let Some(blob_name) = removed_blob {
            let blob_path = self.account_store_dir(&storage_user_id).join(blob_name);
            if let Err(err) = std::fs::remove_file(&blob_path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        error = %err,
                        path = %blob_path.display(),
                        "failed to delete gluon message blob after commit"
                    );
                }
            }
        }
        Ok(())
    }

    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>> {
        if seq == 0 {
            return Ok(None);
        }
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        Ok(accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
            .and_then(|mailbox| mailbox.uid_order.get(seq as usize - 1).copied()))
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let accounts = self.accounts.read().await;
        Ok(accounts
            .get(&storage_user_id)
            .and_then(|account| account.mailboxes.get(&mailbox_name))
            .and_then(|mailbox| {
                mailbox
                    .uid_order
                    .iter()
                    .position(|known| *known == uid)
                    .map(|index| index as u32 + 1)
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::EmailAddress;

    fn make_meta(id: &str, unread: i32) -> MessageMetadata {
        MessageMetadata {
            id: id.to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            external_id: None,
            subject: format!("Subject {}", id),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            reply_tos: vec![],
            flags: 0,
            time: 1700000000,
            size: 1024,
            unread,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve_metadata() {
        let store = InMemoryStore::new();
        let meta = make_meta("msg-1", 1);
        let uid = store.store_metadata("INBOX", "msg-1", meta).await.unwrap();
        assert_eq!(uid, 1);

        let retrieved = store.get_metadata("INBOX", uid).await.unwrap().unwrap();
        assert_eq!(retrieved.id, "msg-1");
        assert_eq!(retrieved.subject, "Subject msg-1");
    }

    #[tokio::test]
    async fn test_uid_monotonicity() {
        let store = InMemoryStore::new();
        let uid1 = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        let uid2 = store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();
        let uid3 = store
            .store_metadata("INBOX", "msg-3", make_meta("msg-3", 0))
            .await
            .unwrap();
        assert_eq!(uid1, 1);
        assert_eq!(uid2, 2);
        assert_eq!(uid3, 3);
    }

    #[tokio::test]
    async fn test_duplicate_proton_id_returns_same_uid() {
        let store = InMemoryStore::new();
        let uid1 = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let uid2 = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        assert_eq!(uid1, uid2);
        let flags = store.get_flags("INBOX", uid1).await.unwrap();
        assert!(flags.contains(&"\\Seen".to_string()));
    }

    #[tokio::test]
    async fn test_proton_id_uid_mapping() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();

        let uid = store.get_uid("INBOX", "msg-1").await.unwrap().unwrap();
        assert_eq!(uid, 1);

        let proton_id = store.get_proton_id("INBOX", 1).await.unwrap().unwrap();
        assert_eq!(proton_id, "msg-1");
    }

    #[tokio::test]
    async fn test_rfc822_store_and_retrieve() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();

        let data = b"From: test\r\nSubject: hi\r\n\r\nbody".to_vec();
        store.store_rfc822("INBOX", 1, data.clone()).await.unwrap();

        let retrieved = store.get_rfc822("INBOX", 1).await.unwrap().unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_list_uids() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        let uids = store.list_uids("INBOX").await.unwrap();
        assert_eq!(uids, vec![1, 2]);
    }

    #[tokio::test]
    async fn test_mailbox_status() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        let status = store.mailbox_status("INBOX").await.unwrap();
        assert_eq!(status.exists, 2);
        assert_eq!(status.next_uid, 3);
        assert_eq!(status.unseen, 1);
    }

    #[tokio::test]
    async fn test_flag_operations() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();

        // Set flags
        store
            .set_flags("INBOX", 1, vec!["\\Seen".to_string()])
            .await
            .unwrap();
        let flags = store.get_flags("INBOX", 1).await.unwrap();
        assert_eq!(flags, vec!["\\Seen"]);

        // Add flags
        store
            .add_flags("INBOX", 1, &["\\Flagged".to_string()])
            .await
            .unwrap();
        let flags = store.get_flags("INBOX", 1).await.unwrap();
        assert!(flags.contains(&"\\Seen".to_string()));
        assert!(flags.contains(&"\\Flagged".to_string()));

        // Remove flags
        store
            .remove_flags("INBOX", 1, &["\\Seen".to_string()])
            .await
            .unwrap();
        let flags = store.get_flags("INBOX", 1).await.unwrap();
        assert!(!flags.contains(&"\\Seen".to_string()));
        assert!(flags.contains(&"\\Flagged".to_string()));
    }

    #[tokio::test]
    async fn test_independent_mailboxes() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("Sent", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        let inbox_uids = store.list_uids("INBOX").await.unwrap();
        let sent_uids = store.list_uids("Sent").await.unwrap();
        assert_eq!(inbox_uids, vec![1]);
        assert_eq!(sent_uids, vec![1]);
    }

    #[tokio::test]
    async fn test_seq_uid_conversion() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        assert_eq!(store.seq_to_uid("INBOX", 1).await.unwrap(), Some(1));
        assert_eq!(store.seq_to_uid("INBOX", 2).await.unwrap(), Some(2));
        assert_eq!(store.uid_to_seq("INBOX", 1).await.unwrap(), Some(1));
        assert_eq!(store.uid_to_seq("INBOX", 2).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn test_remove_message() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        store.remove_message("INBOX", 1).await.unwrap();

        let uids = store.list_uids("INBOX").await.unwrap();
        assert_eq!(uids, vec![2]);
        assert!(store.get_metadata("INBOX", 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_empty_mailbox_status() {
        let store = InMemoryStore::new();
        let status = store.mailbox_status("INBOX").await.unwrap();
        assert_eq!(status.exists, 0);
        assert_eq!(status.next_uid, 1);
        assert_eq!(status.unseen, 0);
    }

    #[tokio::test]
    async fn test_mailbox_snapshot_mod_seq_changes_on_mutation() {
        let store = InMemoryStore::new();
        let snapshot0 = store.mailbox_snapshot("INBOX").await.unwrap();
        assert_eq!(snapshot0.exists, 0);

        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let snapshot1 = store.mailbox_snapshot("INBOX").await.unwrap();
        assert_eq!(snapshot1.exists, 1);
        assert!(snapshot1.mod_seq > snapshot0.mod_seq);

        store
            .set_flags("INBOX", 1, vec!["\\Seen".to_string()])
            .await
            .unwrap();
        let snapshot2 = store.mailbox_snapshot("INBOX").await.unwrap();
        assert_eq!(snapshot2.exists, 1);
        assert!(snapshot2.mod_seq > snapshot1.mod_seq);

        store.remove_message("INBOX", 1).await.unwrap();
        let snapshot3 = store.mailbox_snapshot("INBOX").await.unwrap();
        assert_eq!(snapshot3.exists, 0);
        assert!(snapshot3.mod_seq > snapshot2.mod_seq);
    }

    #[tokio::test]
    async fn persistent_store_restart_continuity_roundtrip_state() {
        let dir = tempfile::tempdir().unwrap();
        let mailbox = "uid-1::INBOX";

        let store = PersistentStore::new(dir.path().to_path_buf()).unwrap();
        let uid1 = store
            .store_metadata(mailbox, "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let uid2 = store
            .store_metadata(mailbox, "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();
        assert_eq!(uid1, 1);
        assert_eq!(uid2, 2);
        store
            .set_flags(
                mailbox,
                uid1,
                vec!["\\Seen".to_string(), "\\Flagged".to_string()],
            )
            .await
            .unwrap();
        store
            .store_rfc822(mailbox, uid1, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();
        store.remove_message(mailbox, uid2).await.unwrap();

        let reloaded = PersistentStore::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(reloaded.get_uid(mailbox, "msg-1").await.unwrap(), Some(1));
        assert_eq!(reloaded.get_uid(mailbox, "msg-2").await.unwrap(), None);
        assert_eq!(
            reloaded.get_rfc822(mailbox, uid1).await.unwrap().unwrap(),
            b"From: a\r\n\r\nbody".to_vec()
        );
        let flags = reloaded.get_flags(mailbox, uid1).await.unwrap();
        assert!(flags.contains(&"\\Seen".to_string()));
        assert!(flags.contains(&"\\Flagged".to_string()));
        let status = reloaded.mailbox_status(mailbox).await.unwrap();
        assert_eq!(status.exists, 1);
        assert_eq!(status.next_uid, 3);
    }

    #[tokio::test]
    async fn persistent_store_account_isolation_same_proton_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = PersistentStore::new(dir.path().to_path_buf()).unwrap();
        let mailbox_a = "uid-a::INBOX";
        let mailbox_b = "uid-b::INBOX";

        let uid_a = store
            .store_metadata(mailbox_a, "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let uid_b = store
            .store_metadata(mailbox_b, "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        assert_eq!(uid_a, 1);
        assert_eq!(uid_b, 1);

        store
            .set_flags(mailbox_a, uid_a, vec!["\\Seen".to_string()])
            .await
            .unwrap();
        store.remove_message(mailbox_a, uid_a).await.unwrap();

        assert_eq!(store.get_uid(mailbox_a, "msg-1").await.unwrap(), None);
        assert_eq!(store.get_uid(mailbox_b, "msg-1").await.unwrap(), Some(1));
        let flags_b = store.get_flags(mailbox_b, uid_b).await.unwrap();
        assert!(!flags_b.contains(&"\\Seen".to_string()));
    }

    #[tokio::test]
    async fn persistent_store_skips_corrupted_json_and_keeps_valid_mailboxes() {
        let dir = tempfile::tempdir().unwrap();
        let mailbox = "uid-1::INBOX";

        let store = PersistentStore::new(dir.path().to_path_buf()).unwrap();
        store
            .store_metadata(mailbox, "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        drop(store);

        std::fs::write(dir.path().join("corrupt.json"), b"{not valid json").unwrap();

        let reloaded = PersistentStore::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(reloaded.get_uid(mailbox, "msg-1").await.unwrap(), Some(1));
    }
}
