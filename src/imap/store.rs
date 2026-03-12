use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD;
#[cfg(test)]
use base64::Engine;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch, RwLock};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreEventKind {
    MailboxCreated,
    MessageAdded,
    MessageUpdated,
    MessageBodyUpdated,
    MessageFlagsUpdated,
    MessageRemoved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEvent {
    pub mailbox: String,
    pub uid: Option<u32>,
    pub proton_id: Option<String>,
    pub kind: StoreEventKind,
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
    fn subscribe_changes(&self) -> watch::Receiver<u64>;
    fn subscribe_events(&self) -> broadcast::Receiver<StoreEvent>;
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
    change_seq: AtomicU64,
    change_tx: watch::Sender<u64>,
    event_tx: broadcast::Sender<StoreEvent>,
}

impl InMemoryStore {
    pub fn new() -> Arc<Self> {
        let (change_tx, _change_rx) = watch::channel(0);
        let (event_tx, _event_rx) = broadcast::channel(256);
        Arc::new(Self {
            mailboxes: RwLock::new(HashMap::new()),
            change_seq: AtomicU64::new(0),
            change_tx,
            event_tx,
        })
    }

    fn publish_change(&self) {
        let next = self
            .change_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let _ = self.change_tx.send(next);
    }

    fn publish_events<I>(&self, events: I)
    where
        I: IntoIterator<Item = StoreEvent>,
    {
        self.publish_change();
        for event in events {
            let _ = self.event_tx.send(event);
        }
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
                change_seq: AtomicU64::new(0),
                change_tx: watch::channel(0).0,
                event_tx: broadcast::channel(256).0,
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
const GLUON_SQLITE_META_TABLE: &str = "openproton_account_meta";
const GLUON_SQLITE_MAILBOX_TABLE: &str = "openproton_mailboxes";
const GLUON_SQLITE_MESSAGE_TABLE: &str = "openproton_messages";
const GLUON_SQLITE_LABEL_TABLE: &str = "openproton_message_labels";
const GLUON_SQLITE_ADDRESS_TABLE: &str = "openproton_message_addresses";
const GLUON_SQLITE_FLAG_TABLE: &str = "openproton_message_flags";
const GLUON_SQLITE_META_NEXT_BLOB_ID_KEY: &str = "next_blob_id";
const GLUON_DEFAULT_ACCOUNT_SCOPE: &str = "__default__";
const GLUON_DEFAULT_MAILBOX: &str = "INBOX";
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

#[derive(Debug, Clone)]
struct GluonAccountState {
    next_blob_id: u64,
    mailboxes: HashMap<String, GluonMailboxData>,
}

#[derive(Debug)]
struct SqliteMessageRow {
    mailbox_name: String,
    uid: u32,
    proton_id: Option<String>,
    blob_name: Option<String>,
    address_id: Option<String>,
    external_id: Option<String>,
    subject: Option<String>,
    sender_name: Option<String>,
    sender_address: Option<String>,
    flags: Option<i64>,
    time: Option<i64>,
    size: Option<i64>,
    unread: Option<i32>,
    is_replied: Option<i32>,
    is_replied_all: Option<i32>,
    is_forwarded: Option<i32>,
    num_attachments: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressFieldKind {
    To,
    Cc,
    Bcc,
    ReplyTo,
}

impl AddressFieldKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::To => "to",
            Self::Cc => "cc",
            Self::Bcc => "bcc",
            Self::ReplyTo => "reply_to",
        }
    }

    fn from_sql(value: &str) -> Option<Self> {
        match value {
            "to" => Some(Self::To),
            "cc" => Some(Self::Cc),
            "bcc" => Some(Self::Bcc),
            "reply_to" => Some(Self::ReplyTo),
            _ => None,
        }
    }
}

pub struct GluonStore {
    root: PathBuf,
    account_storage_ids: HashMap<String, String>,
    accounts: RwLock<HashMap<String, GluonAccountState>>,
    txn_manager: super::gluon_txn::GluonTxnManager,
    change_seq: AtomicU64,
    change_tx: watch::Sender<u64>,
    event_tx: broadcast::Sender<StoreEvent>,
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
        let (change_tx, _change_rx) = watch::channel(0);
        let (event_tx, _event_rx) = broadcast::channel(256);
        Ok(Arc::new(Self {
            root,
            account_storage_ids,
            accounts: RwLock::new(HashMap::new()),
            txn_manager,
            change_seq: AtomicU64::new(0),
            change_tx,
            event_tx,
        }))
    }

    fn publish_change(&self) {
        let next = self
            .change_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let _ = self.change_tx.send(next);
    }

    fn publish_events<I>(&self, events: I)
    where
        I: IntoIterator<Item = StoreEvent>,
    {
        self.publish_change();
        for event in events {
            let _ = self.event_tx.send(event);
        }
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

    fn sqlite_schema() -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_META_TABLE} (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_MAILBOX_TABLE} (
                mailbox_name TEXT PRIMARY KEY,
                uid_validity INTEGER NOT NULL,
                next_uid INTEGER NOT NULL,
                mod_seq INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_MESSAGE_TABLE} (
                mailbox_name TEXT NOT NULL,
                uid INTEGER NOT NULL,
                proton_id TEXT,
                blob_name TEXT,
                address_id TEXT,
                external_id TEXT,
                subject TEXT,
                sender_name TEXT,
                sender_address TEXT,
                flags INTEGER,
                time INTEGER,
                size INTEGER,
                unread INTEGER,
                is_replied INTEGER,
                is_replied_all INTEGER,
                is_forwarded INTEGER,
                num_attachments INTEGER,
                PRIMARY KEY (mailbox_name, uid)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS openproton_messages_mailbox_proton_idx
                ON {GLUON_SQLITE_MESSAGE_TABLE}(mailbox_name, proton_id)
                WHERE proton_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_LABEL_TABLE} (
                mailbox_name TEXT NOT NULL,
                uid INTEGER NOT NULL,
                ordinal INTEGER NOT NULL,
                label_id TEXT NOT NULL,
                PRIMARY KEY (mailbox_name, uid, ordinal)
            );
            CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_ADDRESS_TABLE} (
                mailbox_name TEXT NOT NULL,
                uid INTEGER NOT NULL,
                field_kind TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                PRIMARY KEY (mailbox_name, uid, field_kind, ordinal)
            );
            CREATE TABLE IF NOT EXISTS {GLUON_SQLITE_FLAG_TABLE} (
                mailbox_name TEXT NOT NULL,
                uid INTEGER NOT NULL,
                ordinal INTEGER NOT NULL,
                flag TEXT NOT NULL,
                PRIMARY KEY (mailbox_name, uid, ordinal)
            );"
        )
    }

    fn initialize_sqlite_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        conn.execute_batch(&Self::sqlite_schema())
    }

    fn load_account_from_sqlite(&self, storage_user_id: &str) -> Result<Option<GluonAccountState>> {
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

        if let Err(err) = Self::initialize_sqlite_schema(&conn) {
            warn!(
                path = %db_path.display(),
                error = %err,
                "failed to initialize sqlite schema for gluon index, falling back to empty index"
            );
            return Ok(None);
        }

        let next_blob_id = match conn
            .query_row(
                &format!("SELECT value FROM {GLUON_SQLITE_META_TABLE} WHERE key = ?1"),
                [GLUON_SQLITE_META_NEXT_BLOB_ID_KEY],
                |row| row.get::<_, String>(0),
            )
            .optional()
        {
            Ok(Some(value)) => value.parse::<u64>().unwrap_or(1).max(1),
            Ok(None) => 1,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite next_blob_id metadata, falling back to empty index"
                );
                return Ok(None);
            }
        };

        let mut mailbox_rows = match conn
            .prepare(&format!(
                "SELECT mailbox_name, uid_validity, next_uid, mod_seq
                 FROM {GLUON_SQLITE_MAILBOX_TABLE}
                 ORDER BY mailbox_name"
            ))
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite mailbox rows, falling back to empty index"
                );
                return Ok(None);
            }
        };

        if mailbox_rows.is_empty() {
            return Ok(None);
        }

        let mut state = GluonAccountState {
            next_blob_id,
            mailboxes: HashMap::new(),
        };

        for (mailbox_name, uid_validity, next_uid, mod_seq) in mailbox_rows.drain(..) {
            state.mailboxes.insert(
                mailbox_name,
                GluonMailboxData {
                    uid_validity,
                    next_uid,
                    proton_to_uid: HashMap::new(),
                    uid_to_proton: HashMap::new(),
                    metadata: HashMap::new(),
                    flags: HashMap::new(),
                    uid_order: Vec::new(),
                    mod_seq,
                    uid_to_blob: HashMap::new(),
                },
            );
        }

        let label_rows = match conn
            .prepare(&format!(
                "SELECT mailbox_name, uid, label_id
                 FROM {GLUON_SQLITE_LABEL_TABLE}
                 ORDER BY mailbox_name, uid, ordinal"
            ))
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite message labels, falling back to empty index"
                );
                return Ok(None);
            }
        };
        let mut labels_by_message: HashMap<(String, u32), Vec<String>> = HashMap::new();
        for (mailbox_name, uid, label_id) in label_rows {
            labels_by_message
                .entry((mailbox_name, uid))
                .or_default()
                .push(label_id);
        }

        let address_rows = match conn
            .prepare(&format!(
                "SELECT mailbox_name, uid, field_kind, name, address
                 FROM {GLUON_SQLITE_ADDRESS_TABLE}
                 ORDER BY mailbox_name, uid, field_kind, ordinal"
            ))
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite message addresses, falling back to empty index"
                );
                return Ok(None);
            }
        };
        let mut addresses_by_message: HashMap<
            (String, u32, AddressFieldKind),
            Vec<crate::api::types::EmailAddress>,
        > = HashMap::new();
        for (mailbox_name, uid, field_kind, name, address) in address_rows {
            let Some(field_kind) = AddressFieldKind::from_sql(&field_kind) else {
                continue;
            };
            addresses_by_message
                .entry((mailbox_name, uid, field_kind))
                .or_default()
                .push(crate::api::types::EmailAddress { name, address });
        }

        let flag_rows = match conn
            .prepare(&format!(
                "SELECT mailbox_name, uid, flag
                 FROM {GLUON_SQLITE_FLAG_TABLE}
                 ORDER BY mailbox_name, uid, ordinal"
            ))
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite message flags, falling back to empty index"
                );
                return Ok(None);
            }
        };
        let mut flags_by_message: HashMap<(String, u32), Vec<String>> = HashMap::new();
        for (mailbox_name, uid, flag) in flag_rows {
            flags_by_message
                .entry((mailbox_name, uid))
                .or_default()
                .push(flag);
        }

        let message_rows = match conn
            .prepare(&format!(
                "SELECT mailbox_name, uid, proton_id, blob_name, address_id, external_id,
                        subject, sender_name, sender_address, flags, time, size, unread,
                        is_replied, is_replied_all, is_forwarded, num_attachments
                 FROM {GLUON_SQLITE_MESSAGE_TABLE}
                 ORDER BY mailbox_name, uid"
            ))
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok(SqliteMessageRow {
                        mailbox_name: row.get(0)?,
                        uid: row.get(1)?,
                        proton_id: row.get(2)?,
                        blob_name: row.get(3)?,
                        address_id: row.get(4)?,
                        external_id: row.get(5)?,
                        subject: row.get(6)?,
                        sender_name: row.get(7)?,
                        sender_address: row.get(8)?,
                        flags: row.get(9)?,
                        time: row.get(10)?,
                        size: row.get(11)?,
                        unread: row.get(12)?,
                        is_replied: row.get(13)?,
                        is_replied_all: row.get(14)?,
                        is_forwarded: row.get(15)?,
                        num_attachments: row.get(16)?,
                    })
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    path = %db_path.display(),
                    error = %err,
                    "failed to read sqlite message rows, falling back to empty index"
                );
                return Ok(None);
            }
        };

        for row in message_rows {
            let Some(mailbox) = state.mailboxes.get_mut(&row.mailbox_name) else {
                continue;
            };

            mailbox.uid_order.push(row.uid);

            if let Some(ref proton_id) = row.proton_id {
                mailbox.proton_to_uid.insert(proton_id.clone(), row.uid);
                mailbox.uid_to_proton.insert(row.uid, proton_id.clone());
            }

            if let Some(ref blob_name) = row.blob_name {
                mailbox.uid_to_blob.insert(row.uid, blob_name.clone());
            }

            if let (
                Some(address_id),
                Some(subject),
                Some(sender_name),
                Some(sender_address),
                Some(flags),
                Some(time),
                Some(size),
                Some(unread),
                Some(is_replied),
                Some(is_replied_all),
                Some(is_forwarded),
                Some(num_attachments),
            ) = (
                row.address_id,
                row.subject,
                row.sender_name,
                row.sender_address,
                row.flags,
                row.time,
                row.size,
                row.unread,
                row.is_replied,
                row.is_replied_all,
                row.is_forwarded,
                row.num_attachments,
            ) {
                let key = (row.mailbox_name.clone(), row.uid);
                let meta = MessageMetadata {
                    id: row.proton_id.clone().unwrap_or_default(),
                    address_id,
                    label_ids: labels_by_message.remove(&key).unwrap_or_default(),
                    external_id: row.external_id,
                    subject,
                    sender: crate::api::types::EmailAddress {
                        name: sender_name,
                        address: sender_address,
                    },
                    to_list: addresses_by_message
                        .remove(&(row.mailbox_name.clone(), row.uid, AddressFieldKind::To))
                        .unwrap_or_default(),
                    cc_list: addresses_by_message
                        .remove(&(row.mailbox_name.clone(), row.uid, AddressFieldKind::Cc))
                        .unwrap_or_default(),
                    bcc_list: addresses_by_message
                        .remove(&(row.mailbox_name.clone(), row.uid, AddressFieldKind::Bcc))
                        .unwrap_or_default(),
                    reply_tos: addresses_by_message
                        .remove(&(row.mailbox_name.clone(), row.uid, AddressFieldKind::ReplyTo))
                        .unwrap_or_default(),
                    flags,
                    time,
                    size,
                    unread,
                    is_replied,
                    is_replied_all,
                    is_forwarded,
                    num_attachments,
                };
                mailbox.metadata.insert(row.uid, meta);
            }

            if let Some(flags) = flags_by_message.remove(&(row.mailbox_name.clone(), row.uid)) {
                mailbox.flags.insert(row.uid, flags);
            }
        }

        Ok(Some(state))
    }

    fn persist_account_to_sqlite_once(
        db_path: &Path,
        account: &GluonAccountState,
    ) -> rusqlite::Result<()> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::initialize_sqlite_schema(&conn)?;

        let tx = conn.unchecked_transaction()?;
        tx.execute(&format!("DELETE FROM {GLUON_SQLITE_META_TABLE}"), [])?;
        tx.execute(&format!("DELETE FROM {GLUON_SQLITE_MAILBOX_TABLE}"), [])?;
        tx.execute(&format!("DELETE FROM {GLUON_SQLITE_MESSAGE_TABLE}"), [])?;
        tx.execute(&format!("DELETE FROM {GLUON_SQLITE_LABEL_TABLE}"), [])?;
        tx.execute(&format!("DELETE FROM {GLUON_SQLITE_ADDRESS_TABLE}"), [])?;
        tx.execute(&format!("DELETE FROM {GLUON_SQLITE_FLAG_TABLE}"), [])?;

        tx.execute(
            &format!("INSERT INTO {GLUON_SQLITE_META_TABLE} (key, value) VALUES (?1, ?2)"),
            rusqlite::params![
                GLUON_SQLITE_META_NEXT_BLOB_ID_KEY,
                account.next_blob_id.to_string()
            ],
        )?;

        for (mailbox_name, mailbox) in &account.mailboxes {
            tx.execute(
                &format!(
                    "INSERT INTO {GLUON_SQLITE_MAILBOX_TABLE} (mailbox_name, uid_validity, next_uid, mod_seq)
                     VALUES (?1, ?2, ?3, ?4)"
                ),
                rusqlite::params![
                    mailbox_name,
                    mailbox.uid_validity,
                    mailbox.next_uid,
                    mailbox.mod_seq
                ],
            )?;

            let mut persisted_uids = mailbox.uid_order.clone();
            let mut known_uids = persisted_uids.iter().copied().collect::<HashSet<_>>();
            for uid in mailbox
                .uid_to_proton
                .keys()
                .chain(mailbox.metadata.keys())
                .chain(mailbox.flags.keys())
                .chain(mailbox.uid_to_blob.keys())
                .copied()
            {
                if known_uids.insert(uid) {
                    persisted_uids.push(uid);
                }
            }
            persisted_uids.sort_unstable();

            for uid in persisted_uids {
                let proton_id = mailbox.uid_to_proton.get(&uid).cloned();
                let blob_name = mailbox.uid_to_blob.get(&uid).cloned();
                let metadata = mailbox.metadata.get(&uid);

                tx.execute(
                    &format!(
                        "INSERT INTO {GLUON_SQLITE_MESSAGE_TABLE} (
                            mailbox_name, uid, proton_id, blob_name, address_id, external_id,
                            subject, sender_name, sender_address, flags, time, size, unread,
                            is_replied, is_replied_all, is_forwarded, num_attachments
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
                    ),
                    rusqlite::params![
                        mailbox_name,
                        uid,
                        proton_id,
                        blob_name,
                        metadata.map(|meta| meta.address_id.clone()),
                        metadata.and_then(|meta| meta.external_id.clone()),
                        metadata.map(|meta| meta.subject.clone()),
                        metadata.map(|meta| meta.sender.name.clone()),
                        metadata.map(|meta| meta.sender.address.clone()),
                        metadata.map(|meta| meta.flags),
                        metadata.map(|meta| meta.time),
                        metadata.map(|meta| meta.size),
                        metadata.map(|meta| meta.unread),
                        metadata.map(|meta| meta.is_replied),
                        metadata.map(|meta| meta.is_replied_all),
                        metadata.map(|meta| meta.is_forwarded),
                        metadata.map(|meta| meta.num_attachments),
                    ],
                )?;

                if let Some(meta) = metadata {
                    for (ordinal, label_id) in meta.label_ids.iter().enumerate() {
                        tx.execute(
                            &format!(
                                "INSERT INTO {GLUON_SQLITE_LABEL_TABLE} (mailbox_name, uid, ordinal, label_id)
                                 VALUES (?1, ?2, ?3, ?4)"
                            ),
                            rusqlite::params![mailbox_name, uid, ordinal as i64, label_id],
                        )?;
                    }

                    for (field_kind, entries) in [
                        (AddressFieldKind::To, &meta.to_list),
                        (AddressFieldKind::Cc, &meta.cc_list),
                        (AddressFieldKind::Bcc, &meta.bcc_list),
                        (AddressFieldKind::ReplyTo, &meta.reply_tos),
                    ] {
                        for (ordinal, entry) in entries.iter().enumerate() {
                            tx.execute(
                                &format!(
                                    "INSERT INTO {GLUON_SQLITE_ADDRESS_TABLE} (
                                        mailbox_name, uid, field_kind, ordinal, name, address
                                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
                                ),
                                rusqlite::params![
                                    mailbox_name,
                                    uid,
                                    field_kind.as_sql(),
                                    ordinal as i64,
                                    entry.name,
                                    entry.address
                                ],
                            )?;
                        }
                    }
                }

                if let Some(flags) = mailbox.flags.get(&uid) {
                    for (ordinal, flag) in flags.iter().enumerate() {
                        tx.execute(
                            &format!(
                                "INSERT INTO {GLUON_SQLITE_FLAG_TABLE} (mailbox_name, uid, ordinal, flag)
                                 VALUES (?1, ?2, ?3, ?4)"
                            ),
                            rusqlite::params![mailbox_name, uid, ordinal as i64, flag],
                        )?;
                    }
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    fn persist_account_to_sqlite(
        &self,
        storage_user_id: &str,
        account: &GluonAccountState,
    ) -> Result<()> {
        let db_path = self.account_db_path(storage_user_id);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut retried_with_recreate = false;
        loop {
            match Self::persist_account_to_sqlite_once(&db_path, account) {
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
                        "failed to persist sqlite account state {}: {err}",
                        db_path.display()
                    )))
                }
            }
        }
    }

    fn build_account_sqlite_snapshot(
        &self,
        storage_user_id: &str,
        account: &GluonAccountState,
    ) -> Result<Vec<u8>> {
        let db_path = self.account_db_path(storage_user_id);
        let temp_root = db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.root.clone());
        std::fs::create_dir_all(&temp_root)?;
        let snapshot_path = temp_root.join(format!(
            "{storage_user_id}.snapshot-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        Self::persist_account_to_sqlite_once(&snapshot_path, account).map_err(|err| {
            super::ImapError::Protocol(format!(
                "failed to build sqlite account snapshot {}: {err}",
                snapshot_path.display()
            ))
        })?;

        let snapshot_bytes = std::fs::read(&snapshot_path).map_err(|err| {
            super::ImapError::Protocol(format!(
                "failed to read sqlite account snapshot {}: {err}",
                snapshot_path.display()
            ))
        })?;

        let _ = std::fs::remove_file(&snapshot_path);
        for sidecar_path in Self::account_db_sidecar_paths(&snapshot_path) {
            let _ = std::fs::remove_file(sidecar_path);
        }

        Ok(snapshot_bytes)
    }

    fn account_db_sidecar_paths(db_path: &Path) -> [PathBuf; 2] {
        [
            PathBuf::from(format!("{}-wal", db_path.display())),
            PathBuf::from(format!("{}-shm", db_path.display())),
        ]
    }

    fn persist_account(
        &self,
        storage_user_id: &str,
        account: &GluonAccountState,
        message_writes: &[(PathBuf, Vec<u8>)],
    ) -> Result<()> {
        let mut txn = self.txn_manager.begin(storage_user_id).map_err(|err| {
            super::ImapError::Protocol(format!("failed to begin gluon txn: {err}"))
        })?;
        let db_path = self.account_db_path(storage_user_id);
        let sqlite_snapshot = self.build_account_sqlite_snapshot(storage_user_id, account)?;

        for (relative_path, bytes) in message_writes {
            txn.stage_write(relative_path, bytes).map_err(|err| {
                super::ImapError::Protocol(format!(
                    "failed to stage gluon message blob {}: {err}",
                    relative_path.display()
                ))
            })?;
        }

        txn.stage_write(&db_path, &sqlite_snapshot).map_err(|err| {
            super::ImapError::Protocol(format!(
                "failed to stage gluon sqlite index {}: {err}",
                db_path.display()
            ))
        })?;

        for sidecar_path in Self::account_db_sidecar_paths(&db_path) {
            txn.stage_delete(&sidecar_path).map_err(|err| {
                super::ImapError::Protocol(format!(
                    "failed to stage gluon sqlite sidecar delete {}: {err}",
                    sidecar_path.display()
                ))
            })?;
        }

        txn.commit()
            .map_err(|err| super::ImapError::Protocol(format!("failed to commit gluon txn: {err}")))
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
        let mut account = self
            .load_account_from_sqlite(storage_user_id)?
            .unwrap_or_else(Self::empty_account_state);
        let is_new_index = account.mailboxes.is_empty() && !db_path.exists();
        if is_new_index {
            Self::emit_bootstrap_migration_logs(storage_user_id, &db_path);
        }
        let mut repaired = false;

        if account.next_blob_id == 0 {
            account.next_blob_id = 1;
        }
        for mailbox in account.mailboxes.values_mut() {
            mailbox.sanitize();
            repaired |= mailbox.prune_missing_blob_refs(&account_dir) > 0;
        }

        if account.mailboxes.is_empty() {
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
                account
                    .mailboxes
                    .insert(GLUON_DEFAULT_MAILBOX.to_string(), inbox);
                repaired = true;
            }
        }

        if repaired {
            // Any index/blob repair can change effective UID->blob mapping.
            // Force new UIDVALIDITY so IMAP clients drop stale UID caches.
            let new_uid_validity = current_uid_validity();
            for mailbox in account.mailboxes.values_mut() {
                mailbox.uid_validity = new_uid_validity;
            }
            self.persist_account_to_sqlite(storage_user_id, &account)?;
            warn!(
                account = %storage_user_id,
                uid_validity = new_uid_validity,
                "gluon index repaired; bumped mailbox uid_validity"
            );
        }

        let mut max_blob_id = account.next_blob_id;
        for mailbox in account.mailboxes.values() {
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
            mailboxes: account.mailboxes,
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

fn is_metadata_derived_flag(flag: &str) -> bool {
    matches!(
        flag,
        "\\Seen" | "\\Flagged" | "\\Draft" | "\\Answered" | "$Forwarded"
    )
}

fn merge_metadata_flags(
    existing_flags: Option<&Vec<String>>,
    meta: &MessageMetadata,
) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = HashSet::new();

    if let Some(existing_flags) = existing_flags {
        for flag in existing_flags {
            if !is_metadata_derived_flag(flag) && seen.insert(flag.clone()) {
                merged.push(flag.clone());
            }
        }
    }

    for flag in derived_flag_strings(meta) {
        if seen.insert(flag.clone()) {
            merged.push(flag);
        }
    }

    merged
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
        let mailbox_was_missing = !mailboxes.contains_key(mailbox);
        let mb = mailboxes
            .entry(mailbox.to_string())
            .or_insert_with(MailboxData::new);

        if let Some(&uid) = mb.proton_to_uid.get(proton_id) {
            let merged_flags = merge_metadata_flags(mb.flags.get(&uid), &meta);
            mb.metadata.insert(uid, meta);
            mb.flags.insert(uid, merged_flags);
            mb.mod_seq = mb.mod_seq.saturating_add(1);
            let mod_seq = mb.mod_seq;
            drop(mailboxes);
            self.publish_events([StoreEvent {
                mailbox: mailbox.to_string(),
                uid: Some(uid),
                proton_id: Some(proton_id.to_string()),
                kind: StoreEventKind::MessageUpdated,
                mod_seq,
            }]);
            return Ok(uid);
        }

        let uid = mb.next_uid;
        mb.next_uid += 1;
        mb.proton_to_uid.insert(proton_id.to_string(), uid);
        mb.uid_to_proton.insert(uid, proton_id.to_string());
        mb.uid_order.push(uid);
        mb.metadata.insert(uid, meta);
        mb.flags.insert(
            uid,
            merge_metadata_flags(None, mb.metadata.get(&uid).unwrap()),
        );
        mb.mod_seq = mb.mod_seq.saturating_add(1);
        let mod_seq = mb.mod_seq;
        drop(mailboxes);
        let mut events = Vec::with_capacity(if mailbox_was_missing { 2 } else { 1 });
        if mailbox_was_missing {
            events.push(StoreEvent {
                mailbox: mailbox.to_string(),
                uid: None,
                proton_id: None,
                kind: StoreEventKind::MailboxCreated,
                mod_seq,
            });
        }
        events.push(StoreEvent {
            mailbox: mailbox.to_string(),
            uid: Some(uid),
            proton_id: Some(proton_id.to_string()),
            kind: StoreEventKind::MessageAdded,
            mod_seq,
        });
        self.publish_events(events);
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
        let mailbox_was_missing = !mailboxes.contains_key(mailbox);
        let mb = mailboxes
            .entry(mailbox.to_string())
            .or_insert_with(MailboxData::new);
        mb.rfc822.insert(uid, data);
        mb.mod_seq = mb.mod_seq.saturating_add(1);
        let mod_seq = mb.mod_seq;
        let proton_id = mb.uid_to_proton.get(&uid).cloned();
        drop(mailboxes);
        let mut events = Vec::with_capacity(if mailbox_was_missing { 2 } else { 1 });
        if mailbox_was_missing {
            events.push(StoreEvent {
                mailbox: mailbox.to_string(),
                uid: None,
                proton_id: None,
                kind: StoreEventKind::MailboxCreated,
                mod_seq,
            });
        }
        events.push(StoreEvent {
            mailbox: mailbox.to_string(),
            uid: Some(uid),
            proton_id,
            kind: StoreEventKind::MessageBodyUpdated,
            mod_seq,
        });
        self.publish_events(events);
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
            let proton_id = mb.uid_to_proton.get(&uid).cloned();
            mb.flags.insert(uid, flags);
            mb.mod_seq = mb.mod_seq.saturating_add(1);
            let mod_seq = mb.mod_seq;
            drop(mailboxes);
            self.publish_events([StoreEvent {
                mailbox: mailbox.to_string(),
                uid: Some(uid),
                proton_id,
                kind: StoreEventKind::MessageFlagsUpdated,
                mod_seq,
            }]);
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
                let mod_seq = mb.mod_seq;
                let proton_id = mb.uid_to_proton.get(&uid).cloned();
                drop(mailboxes);
                self.publish_events([StoreEvent {
                    mailbox: mailbox.to_string(),
                    uid: Some(uid),
                    proton_id,
                    kind: StoreEventKind::MessageFlagsUpdated,
                    mod_seq,
                }]);
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
                    let mod_seq = mb.mod_seq;
                    let proton_id = mb.uid_to_proton.get(&uid).cloned();
                    drop(mailboxes);
                    self.publish_events([StoreEvent {
                        mailbox: mailbox.to_string(),
                        uid: Some(uid),
                        proton_id,
                        kind: StoreEventKind::MessageFlagsUpdated,
                        mod_seq,
                    }]);
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
            let proton_id = if let Some(proton_id) = mb.uid_to_proton.remove(&uid) {
                mb.proton_to_uid.remove(&proton_id);
                Some(proton_id)
            } else {
                None
            };
            mb.metadata.remove(&uid);
            mb.rfc822.remove(&uid);
            mb.flags.remove(&uid);
            mb.uid_order.retain(|&u| u != uid);
            mb.mod_seq = mb.mod_seq.saturating_add(1);
            let mod_seq = mb.mod_seq;
            drop(mailboxes);
            self.publish_events([StoreEvent {
                mailbox: mailbox.to_string(),
                uid: Some(uid),
                proton_id,
                kind: StoreEventKind::MessageRemoved,
                mod_seq,
            }]);
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

    fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.change_tx.subscribe()
    }

    fn subscribe_events(&self) -> broadcast::Receiver<StoreEvent> {
        self.event_tx.subscribe()
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

    fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.inner.subscribe_changes()
    }

    fn subscribe_events(&self) -> broadcast::Receiver<StoreEvent> {
        self.inner.subscribe_events()
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
        let scoped_mailbox = mailbox.to_string();
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        // Reload account state from disk before mutating so concurrent store instances
        // do not clobber each other's UID assignment/index updates.
        let mut next_state = self.load_account_from_disk(&storage_user_id)?;
        let mut accounts = self.accounts.write().await;
        let mailbox_was_missing = !next_state.mailboxes.contains_key(&mailbox_name);

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

        let existing_uid = mailbox.proton_to_uid.get(proton_id).copied();
        let uid = if let Some(existing_uid) = existing_uid {
            let merged_flags = merge_metadata_flags(mailbox.flags.get(&existing_uid), &meta);
            mailbox.metadata.insert(existing_uid, meta);
            mailbox.flags.insert(existing_uid, merged_flags);
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
            mailbox.flags.insert(
                assigned_uid,
                merge_metadata_flags(None, mailbox.metadata.get(&assigned_uid).unwrap()),
            );
            mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
            assigned_uid
        };

        let mod_seq = mailbox.mod_seq;
        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        drop(accounts);
        let mut events = Vec::with_capacity(if mailbox_was_missing { 2 } else { 1 });
        if mailbox_was_missing {
            events.push(StoreEvent {
                mailbox: scoped_mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: StoreEventKind::MailboxCreated,
                mod_seq,
            });
        }
        events.push(StoreEvent {
            mailbox: scoped_mailbox,
            uid: Some(uid),
            proton_id: Some(proton_id.to_string()),
            kind: if existing_uid.is_some() {
                StoreEventKind::MessageUpdated
            } else {
                StoreEventKind::MessageAdded
            },
            mod_seq,
        });
        self.publish_events(events);
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
        let scoped_mailbox = mailbox.to_string();
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let mut next_state = accounts
            .get(&storage_user_id)
            .cloned()
            .unwrap_or_else(Self::empty_account_state);
        let mut writes = Vec::new();
        let mailbox_was_missing = !next_state.mailboxes.contains_key(&mailbox_name);

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
        let mod_seq = mailbox.mod_seq;
        let proton_id = mailbox.uid_to_proton.get(&uid).cloned();
        writes.push((Self::message_rel_path(&storage_user_id, &blob_name), data));

        self.persist_account(&storage_user_id, &next_state, &writes)?;
        accounts.insert(storage_user_id, next_state);
        drop(accounts);
        let mut events = Vec::with_capacity(if mailbox_was_missing { 2 } else { 1 });
        if mailbox_was_missing {
            events.push(StoreEvent {
                mailbox: scoped_mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: StoreEventKind::MailboxCreated,
                mod_seq,
            });
        }
        events.push(StoreEvent {
            mailbox: scoped_mailbox,
            uid: Some(uid),
            proton_id,
            kind: StoreEventKind::MessageBodyUpdated,
            mod_seq,
        });
        self.publish_events(events);
        Ok(())
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let account_dir = self.account_store_dir(&storage_user_id);

        let blob_path = {
            let accounts = self.accounts.read().await;
            match accounts
                .get(&storage_user_id)
                .and_then(|account| account.mailboxes.get(&mailbox_name))
                .and_then(|mailbox| mailbox.uid_to_blob.get(&uid).cloned())
            {
                Some(name) => account_dir.join(name),
                None => return Ok(None), // no mapping; force re-fetch from API
            }
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
        let scoped_mailbox = mailbox.to_string();
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let (mod_seq, proton_id) =
            if let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) {
                let proton_id = mailbox.uid_to_proton.get(&uid).cloned();
                mailbox.flags.insert(uid, flags);
                mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
                (mailbox.mod_seq, proton_id)
            } else {
                return Ok(());
            };

        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        drop(accounts);
        self.publish_events([StoreEvent {
            mailbox: scoped_mailbox,
            uid: Some(uid),
            proton_id,
            kind: StoreEventKind::MessageFlagsUpdated,
            mod_seq,
        }]);
        Ok(())
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let scoped_mailbox = mailbox.to_string();
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) else {
            return Ok(());
        };
        let proton_id = mailbox.uid_to_proton.get(&uid).cloned();

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
        let mod_seq = mailbox.mod_seq;
        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        drop(accounts);
        self.publish_events([StoreEvent {
            mailbox: scoped_mailbox,
            uid: Some(uid),
            proton_id,
            kind: StoreEventKind::MessageFlagsUpdated,
            mod_seq,
        }]);
        Ok(())
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let scoped_mailbox = mailbox.to_string();
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) else {
            return Ok(());
        };
        let proton_id = mailbox.uid_to_proton.get(&uid).cloned();

        let Some(current_flags) = mailbox.flags.get_mut(&uid) else {
            return Ok(());
        };
        let before = current_flags.len();
        current_flags.retain(|flag| !flags.contains(flag));
        if current_flags.len() == before {
            return Ok(());
        }

        mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
        let mod_seq = mailbox.mod_seq;
        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id, next_state);
        drop(accounts);
        self.publish_events([StoreEvent {
            mailbox: scoped_mailbox,
            uid: Some(uid),
            proton_id,
            kind: StoreEventKind::MessageFlagsUpdated,
            mod_seq,
        }]);
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
        let scoped_mailbox = mailbox.to_string();
        let (storage_user_id, mailbox_name) = self.resolve_scope(mailbox).await?;
        let mut accounts = self.accounts.write().await;
        let Some(current_state) = accounts.get(&storage_user_id).cloned() else {
            return Ok(());
        };
        let mut next_state = current_state;
        let Some(mailbox) = next_state.mailboxes.get_mut(&mailbox_name) else {
            return Ok(());
        };

        let proton_id = if let Some(proton_id) = mailbox.uid_to_proton.remove(&uid) {
            mailbox.proton_to_uid.remove(&proton_id);
            Some(proton_id)
        } else {
            None
        };
        mailbox.metadata.remove(&uid);
        mailbox.flags.remove(&uid);
        let removed_blob = mailbox.uid_to_blob.remove(&uid);
        mailbox.uid_order.retain(|known_uid| *known_uid != uid);
        mailbox.mod_seq = mailbox.mod_seq.saturating_add(1);
        let mod_seq = mailbox.mod_seq;

        self.persist_account(&storage_user_id, &next_state, &[])?;
        accounts.insert(storage_user_id.clone(), next_state);
        drop(accounts);
        self.publish_events([StoreEvent {
            mailbox: scoped_mailbox,
            uid: Some(uid),
            proton_id,
            kind: StoreEventKind::MessageRemoved,
            mod_seq,
        }]);

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

    fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.change_tx.subscribe()
    }

    fn subscribe_events(&self) -> broadcast::Receiver<StoreEvent> {
        self.event_tx.subscribe()
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
    async fn test_metadata_refresh_preserves_local_only_flags() {
        let store = InMemoryStore::new();
        let uid = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();

        store
            .add_flags("INBOX", uid, &["\\Deleted".to_string()])
            .await
            .unwrap();

        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();

        let flags = store.get_flags("INBOX", uid).await.unwrap();
        assert!(flags.contains(&"\\Deleted".to_string()));
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

    #[tokio::test]
    async fn store_emits_semantic_events_for_jmap_and_idle_consumers() {
        let store = InMemoryStore::new();
        let mut events = store.subscribe_events();

        let uid = store
            .store_metadata("uid-1::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let created = events.recv().await.unwrap();
        let added = events.recv().await.unwrap();
        assert_eq!(created.kind, StoreEventKind::MailboxCreated);
        assert_eq!(created.mailbox, "uid-1::INBOX");
        assert_eq!(added.kind, StoreEventKind::MessageAdded);
        assert_eq!(added.uid, Some(uid));
        assert_eq!(added.proton_id.as_deref(), Some("msg-1"));

        store
            .set_flags("uid-1::INBOX", uid, vec!["\\Seen".to_string()])
            .await
            .unwrap();
        let flags = events.recv().await.unwrap();
        assert_eq!(flags.kind, StoreEventKind::MessageFlagsUpdated);
        assert_eq!(flags.uid, Some(uid));

        store.remove_message("uid-1::INBOX", uid).await.unwrap();
        let removed = events.recv().await.unwrap();
        assert_eq!(removed.kind, StoreEventKind::MessageRemoved);
        assert_eq!(removed.uid, Some(uid));
    }

    #[test]
    fn gluon_persist_account_stages_sqlite_snapshot_and_sidecar_cleanup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = GluonStore::new(
            temp.path().to_path_buf(),
            HashMap::from([("account-1".to_string(), "user-1".to_string())]),
        )
        .expect("store");

        let mut inbox = GluonMailboxData::new();
        inbox.next_uid = 2;
        inbox.mod_seq = 1;
        inbox.uid_order.push(1);
        inbox.proton_to_uid.insert("msg-1".to_string(), 1);
        inbox.uid_to_proton.insert(1, "msg-1".to_string());
        inbox.metadata.insert(1, make_meta("msg-1", 1));
        inbox.flags.insert(1, vec!["\\Seen".to_string()]);
        inbox.uid_to_blob.insert(1, "00000001.msg".to_string());

        let account = GluonAccountState {
            next_blob_id: 2,
            mailboxes: HashMap::from([("INBOX".to_string(), inbox)]),
        };

        let db_path = store.account_db_path("user-1");
        let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));
        std::fs::create_dir_all(db_path.parent().expect("db parent")).expect("db dir");
        std::fs::write(&wal_path, b"stale wal").expect("write wal");
        std::fs::write(&shm_path, b"stale shm").expect("write shm");

        store
            .persist_account(
                "user-1",
                &account,
                &[(
                    PathBuf::from("backend/store/user-1/00000001.msg"),
                    b"From: staged\r\n\r\nbody".to_vec(),
                )],
            )
            .expect("persist account");

        assert!(db_path.exists());
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());
        assert!(temp
            .path()
            .join("backend/store/user-1/00000001.msg")
            .exists());

        let loaded = store
            .load_account_from_sqlite("user-1")
            .expect("load sqlite")
            .expect("account present");
        let inbox = loaded.mailboxes.get("INBOX").expect("inbox");
        assert_eq!(inbox.uid_to_blob.get(&1), Some(&"00000001.msg".to_string()));
        assert_eq!(inbox.uid_to_proton.get(&1), Some(&"msg-1".to_string()));
    }
}
