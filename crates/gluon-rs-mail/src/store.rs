use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gluon_rs_core::{
    decode_blob, encode_blob, AccountBootstrap, AccountPaths, DeferredDeleteManager, GluonCoreError,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{
    db::SchemaProbe,
    error::{GluonError, Result},
    types::StoreBootstrap,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamMailbox {
    pub internal_id: u64,
    pub remote_id: String,
    pub name: String,
    pub uid_validity: u32,
    pub subscribed: bool,
    pub attributes: Vec<String>,
    pub flags: Vec<String>,
    pub permanent_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamMessageSummary {
    pub internal_id: String,
    pub remote_id: String,
    pub uid: u32,
    pub recent: bool,
    pub mailbox_deleted: bool,
    pub message_deleted: bool,
    pub size: i64,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMailbox {
    pub remote_id: String,
    pub name: String,
    pub uid_validity: u32,
    pub subscribed: bool,
    pub attributes: Vec<String>,
    pub flags: Vec<String>,
    pub permanent_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    pub internal_id: String,
    pub remote_id: String,
    pub flags: Vec<String>,
    pub blob: Vec<u8>,
    pub body: String,
    pub body_structure: String,
    pub envelope: String,
    pub size: i64,
    pub recent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamMailboxMessage {
    pub summary: UpstreamMessageSummary,
    pub body: String,
    pub body_structure: String,
    pub envelope: String,
    pub blob_path: std::path::PathBuf,
    pub blob_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamMailboxSnapshot {
    pub mailbox: UpstreamMailbox,
    pub next_uid: u32,
    pub message_count: usize,
    pub recent_count: usize,
    pub messages: Vec<UpstreamMailboxMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectSnapshotEntry {
    pub uid: u32,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectSnapshot {
    pub uid_validity: u32,
    pub next_uid: u32,
    pub entries: Vec<SelectSnapshotEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedSubscription {
    pub name: String,
    pub remote_id: String,
}

/// A shared handle to a single rusqlite `Connection` for one account.
/// Callers that previously accepted `&SqlitePool` now accept `&ConnHandle`.
pub type ConnHandle = Arc<Mutex<Connection>>;

#[derive(Debug, Clone)]
pub struct CompatibleStore {
    bootstrap: StoreBootstrap,
    accounts_by_storage_user_id: HashMap<String, AccountBootstrap>,
    connections: Arc<Mutex<HashMap<String, ConnHandle>>>,
    /// Cache: (storage_user_id, mailbox_name_lower) -> internal_id.
    mailbox_id_cache: Arc<Mutex<HashMap<(String, String), u64>>>,
}

impl CompatibleStore {
    pub fn open(bootstrap: StoreBootstrap) -> Result<Self> {
        Self::open_with_mode(bootstrap, true)
    }

    pub fn open_read_only(bootstrap: StoreBootstrap) -> Result<Self> {
        Self::open_with_mode(bootstrap, false)
    }

    fn open_with_mode(bootstrap: StoreBootstrap, create_dirs: bool) -> Result<Self> {
        bootstrap.validate()?;
        if create_dirs {
            bootstrap.layout.ensure_base_dirs()?;
            DeferredDeleteManager::new(bootstrap.layout.db_dir())?.cleanup_deferred_delete_dir()?;
        } else if !bootstrap.layout.root().exists() {
            return Err(GluonCoreError::MissingCacheRoot {
                path: bootstrap.layout.root().to_path_buf(),
            }
            .into());
        }

        let mut accounts_by_storage_user_id = HashMap::new();
        for account in &bootstrap.accounts {
            let account_paths = bootstrap
                .layout
                .account_paths(account.storage_user_id.clone())?;
            if create_dirs {
                std::fs::create_dir_all(account_paths.store_dir()).map_err(GluonCoreError::from)?;
            }

            accounts_by_storage_user_id.insert(account.storage_user_id.clone(), account.clone());
        }

        Ok(Self {
            bootstrap,
            accounts_by_storage_user_id,
            connections: Arc::new(Mutex::new(HashMap::new())),
            mailbox_id_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn bootstrap(&self) -> &StoreBootstrap {
        &self.bootstrap
    }

    pub fn account(&self, storage_user_id: &str) -> Result<&AccountBootstrap> {
        self.accounts_by_storage_user_id
            .get(storage_user_id)
            .ok_or_else(|| {
                GluonCoreError::UnknownStorageUserId {
                    storage_user_id: storage_user_id.to_string(),
                }
                .into()
            })
    }

    pub fn account_paths(&self, storage_user_id: &str) -> Result<AccountPaths> {
        self.account(storage_user_id)?;
        Ok(self.bootstrap.layout.account_paths(storage_user_id)?)
    }

    /// Return the shared connection handle for this account, creating it on
    /// first access with all pragmas and schema initialization.
    pub fn conn_for(&self, storage_user_id: &str) -> Result<ConnHandle> {
        // Fast path: clone existing handle under a brief lock.
        {
            let conns = self.connections.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(handle) = conns.get(storage_user_id) {
                return Ok(handle.clone());
            }
        }

        // Slow path: open new connection (happens once per account per process).
        let account_paths = self.account_paths(storage_user_id)?;
        let db_path = account_paths.primary_db_path();

        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        conn.pragma_update(None, "journal_mode", "wal")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "cache_size", -8000)?;
        conn.pragma_update(None, "mmap_size", 67_108_864)?;

        // Initialize schema.
        for stmt in UPSTREAM_SCHEMA_STATEMENTS {
            conn.execute_batch(stmt)?;
        }
        conn.execute(
            "INSERT INTO connector_settings(id, value) VALUES(0, NULL) ON CONFLICT(id) DO NOTHING",
            [],
        )?;
        conn.execute(
            "INSERT INTO gluon_version(id, version) VALUES(0, 3) ON CONFLICT(id) DO NOTHING",
            [],
        )?;

        let handle = Arc::new(Mutex::new(conn));
        let mut conns = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        conns.insert(storage_user_id.to_string(), handle.clone());
        Ok(handle)
    }

    /// Fast mailbox name -> internal_id resolution with caching.
    /// Avoids scanning mailboxes_v2 on every operation.
    pub fn resolve_mailbox_id(
        &self,
        storage_user_id: &str,
        mailbox_name: &str,
    ) -> Result<Option<u64>> {
        let key = (
            storage_user_id.to_string(),
            mailbox_name.to_ascii_lowercase(),
        );
        if let Ok(cache) = self.mailbox_id_cache.lock() {
            if let Some(&id) = cache.get(&key) {
                return Ok(Some(id));
            }
        }
        // Cache miss: scan DB
        let mailboxes = self.list_upstream_mailboxes(storage_user_id)?;
        let mut found = None;
        if let Ok(mut cache) = self.mailbox_id_cache.lock() {
            for mb in &mailboxes {
                let k = (storage_user_id.to_string(), mb.name.to_ascii_lowercase());
                cache.insert(k, mb.internal_id);
                if mb.name.eq_ignore_ascii_case(mailbox_name) {
                    found = Some(mb.internal_id);
                }
            }
        }
        Ok(found)
    }

    /// Invalidate cached mailbox ids for an account (after create/delete/rename).
    pub fn invalidate_mailbox_cache(&self, storage_user_id: &str) {
        if let Ok(mut cache) = self.mailbox_id_cache.lock() {
            cache.retain(|(uid, _), _| uid != storage_user_id);
        }
    }

    pub fn schema_probe(&self, storage_user_id: &str) -> Result<SchemaProbe> {
        let account_paths = self.account_paths(storage_user_id)?;
        SchemaProbe::inspect(&account_paths.primary_db_path())
    }

    /// Acquire a pre-connected session for batching multiple queries.
    pub fn session(&self, storage_user_id: &str) -> Result<StoreSession> {
        let handle = self.conn_for(storage_user_id)?;
        Ok(StoreSession { conn: handle })
    }

    pub fn initialize_upstream_schema(&self, storage_user_id: &str) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());

        for stmt in UPSTREAM_SCHEMA_STATEMENTS {
            conn.execute_batch(stmt)?;
        }

        conn.execute(
            "INSERT INTO connector_settings(id, value) VALUES(0, NULL)
             ON CONFLICT(id) DO NOTHING",
            [],
        )?;

        conn.execute(
            "INSERT INTO gluon_version(id, version) VALUES(0, 3)
             ON CONFLICT(id) DO NOTHING",
            [],
        )?;

        Ok(())
    }

    pub fn create_mailbox(
        &self,
        storage_user_id: &str,
        mailbox: &NewMailbox,
    ) -> Result<UpstreamMailbox> {
        self.initialize_upstream_schema(storage_user_id)?;
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());

        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO mailboxes_v2(remote_id, name, uid_validity, subscribed)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                &mailbox.remote_id,
                &mailbox.name,
                mailbox.uid_validity,
                mailbox.subscribed
            ],
        )?;

        let internal_id = tx.last_insert_rowid() as u64;

        let create_table_sql = create_mailbox_message_table_sql(internal_id);
        tx.execute_batch(&create_table_sql)?;

        insert_mailbox_flags(&tx, "mailbox_flags_v2", internal_id, &mailbox.flags)?;
        insert_mailbox_flags(
            &tx,
            "mailbox_perm_flags_v2",
            internal_id,
            &mailbox.permanent_flags,
        )?;
        insert_mailbox_flags(&tx, "mailbox_attrs_v2", internal_id, &mailbox.attributes)?;
        tx.commit()?;

        get_upstream_mailbox(&conn, internal_id)
    }

    pub fn append_message(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        message: &NewMessage,
    ) -> Result<UpstreamMessageSummary> {
        self.initialize_upstream_schema(storage_user_id)?;
        let account_paths = self.account_paths(storage_user_id)?;
        std::fs::create_dir_all(account_paths.store_dir()).map_err(GluonCoreError::from)?;
        let blob_path = account_paths.blob_path(&message.internal_id)?;
        let encoded = encode_blob(&self.account(storage_user_id)?.key, &message.blob)?;
        std::fs::write(&blob_path, encoded).map_err(GluonCoreError::from)?;

        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO messages_v2(id, remote_id, date, size, body, body_structure, envelope, deleted)
             VALUES(?1, ?2, datetime('now'), ?3, ?4, ?5, ?6, FALSE)",
            params![
                &message.internal_id,
                &message.remote_id,
                message.size,
                &message.body,
                &message.body_structure,
                &message.envelope,
            ],
        )?;

        tx.execute(
            "INSERT INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, ?2)",
            params![&message.internal_id, mailbox_internal_id as i64],
        )?;

        tx.execute(
            &format!(
                "INSERT INTO mailbox_message_{mailbox_internal_id}(message_id, message_remote_id, recent, deleted)
                 VALUES(?1, ?2, ?3, FALSE)"
            ),
            params![&message.internal_id, &message.remote_id, message.recent],
        )?;

        insert_message_flags(&tx, &message.internal_id, &message.flags)?;
        tx.commit()?;
        drop(conn);

        let listed = self.list_upstream_mailbox_messages(storage_user_id, mailbox_internal_id)?;
        listed
            .into_iter()
            .last()
            .ok_or_else(|| GluonError::MissingRequiredTable {
                table: format!("mailbox_message_{mailbox_internal_id}"),
            })
    }

    pub fn replace_message_content(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        blob: &[u8],
        body: &str,
        body_structure: &str,
        envelope: &str,
        size: i64,
    ) -> Result<()> {
        self.initialize_upstream_schema(storage_user_id)?;
        let account_paths = self.account_paths(storage_user_id)?;
        std::fs::create_dir_all(account_paths.store_dir()).map_err(GluonCoreError::from)?;
        let blob_path = account_paths.blob_path(internal_message_id)?;
        let encoded = encode_blob(&self.account(storage_user_id)?.key, blob)?;
        std::fs::write(&blob_path, encoded).map_err(GluonCoreError::from)?;

        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE messages_v2
             SET size = ?2, body = ?3, body_structure = ?4, envelope = ?5
             WHERE id = ?1",
            params![internal_message_id, size, body, body_structure, envelope],
        )?;

        Ok(())
    }

    pub fn delete_account_database_files(&self, storage_user_id: &str) -> Result<usize> {
        Ok(DeferredDeleteManager::new(self.bootstrap.layout.db_dir())?
            .delete_db_files(storage_user_id)?)
    }

    pub fn cleanup_deferred_database_files(&self) -> Result<()> {
        Ok(DeferredDeleteManager::new(self.bootstrap.layout.db_dir())?
            .cleanup_deferred_delete_dir()?)
    }

    pub fn add_message_flags(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        flags: &[String],
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;
        insert_message_flags_ignore_duplicates(&tx, internal_message_id, flags)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_message_flags(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        flags: &[String],
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;
        for flag in flags {
            tx.execute(
                "DELETE FROM message_flags_v2 WHERE message_id = ?1 AND value = ?2",
                params![internal_message_id, flag],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_message_flags(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        flags: &[String],
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "DELETE FROM message_flags_v2 WHERE message_id = ?1",
            params![internal_message_id],
        )?;
        insert_message_flags_ignore_duplicates(&tx, internal_message_id, flags)?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_mailbox_message_deleted(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        internal_message_id: &str,
        deleted: bool,
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            &format!(
                "UPDATE mailbox_message_{mailbox_internal_id}
                 SET deleted = ?1
                 WHERE message_id = ?2"
            ),
            params![deleted, internal_message_id],
        )?;
        Ok(())
    }

    pub fn set_message_deleted(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        deleted: bool,
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE messages_v2
             SET deleted = ?1
             WHERE id = ?2",
            params![deleted, internal_message_id],
        )?;
        Ok(())
    }

    pub fn add_existing_message_to_mailbox(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        internal_message_id: &str,
    ) -> Result<UpstreamMessageSummary> {
        let handle = self.conn_for(storage_user_id)?;
        {
            let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
            let tx = conn.unchecked_transaction()?;

            let remote_id: String = tx.query_row(
                "SELECT remote_id FROM messages_v2 WHERE id = ?1",
                params![internal_message_id],
                |row| row.get(0),
            )?;

            tx.execute(
                "INSERT OR IGNORE INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, ?2)",
                params![internal_message_id, mailbox_internal_id as i64],
            )?;

            tx.execute(
                &format!(
                    "INSERT INTO mailbox_message_{mailbox_internal_id}(message_id, message_remote_id)
                     VALUES(?1, ?2)"
                ),
                params![internal_message_id, &remote_id],
            )?;

            tx.commit()?;
        }

        let messages = self.list_upstream_mailbox_messages(storage_user_id, mailbox_internal_id)?;
        messages
            .into_iter()
            .find(|message| message.internal_id == internal_message_id)
            .ok_or_else(|| GluonError::MissingRequiredTable {
                table: format!("mailbox_message_{mailbox_internal_id}"),
            })
    }

    pub fn find_message_internal_id_by_remote_id(
        &self,
        storage_user_id: &str,
        remote_id: &str,
    ) -> Result<Option<String>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let result: Option<String> = conn
            .query_row(
                "SELECT id FROM messages_v2 WHERE remote_id = ?1 LIMIT 1",
                params![remote_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    pub fn update_message_content(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        message: &NewMessage,
    ) -> Result<()> {
        let account_paths = self.account_paths(storage_user_id)?;
        std::fs::create_dir_all(account_paths.store_dir()).map_err(GluonCoreError::from)?;
        let blob_path = account_paths.blob_path(internal_message_id)?;
        let encoded = encode_blob(&self.account(storage_user_id)?.key, &message.blob)?;
        std::fs::write(&blob_path, encoded).map_err(GluonCoreError::from)?;

        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE messages_v2
             SET remote_id = ?1, size = ?2, body = ?3, body_structure = ?4, envelope = ?5
             WHERE id = ?6",
            params![
                &message.remote_id,
                message.size,
                &message.body,
                &message.body_structure,
                &message.envelope,
                internal_message_id,
            ],
        )?;

        Ok(())
    }

    pub fn remove_message_from_mailbox(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        internal_message_id: &str,
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            &format!(
                "DELETE FROM mailbox_message_{mailbox_internal_id}
                 WHERE message_id = ?1"
            ),
            params![internal_message_id],
        )?;

        tx.execute(
            "DELETE FROM message_to_mailbox
             WHERE message_id = ?1 AND mailbox_id = ?2",
            params![internal_message_id, mailbox_internal_id as i64],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn rename_mailbox(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        new_name: &str,
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE mailboxes_v2
             SET name = ?1
             WHERE id = ?2",
            params![new_name, mailbox_internal_id as i64],
        )?;
        Ok(())
    }

    pub fn set_mailbox_subscribed(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        subscribed: bool,
    ) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE mailboxes_v2
             SET subscribed = ?1
             WHERE id = ?2",
            params![subscribed, mailbox_internal_id as i64],
        )?;
        Ok(())
    }

    pub fn delete_mailbox(&self, storage_user_id: &str, mailbox_internal_id: u64) -> Result<()> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;

        let (remote_id, name, subscribed): (String, String, bool) = tx.query_row(
            "SELECT remote_id, name, subscribed
             FROM mailboxes_v2
             WHERE id = ?1",
            params![mailbox_internal_id as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        if subscribed {
            tx.execute(
                "UPDATE deleted_subscriptions
                 SET remote_id = ?1
                 WHERE name = ?2",
                params![&remote_id, &name],
            )?;

            tx.execute(
                "INSERT INTO deleted_subscriptions(name, remote_id)
                 SELECT ?1, ?2
                 WHERE NOT EXISTS (
                     SELECT 1 FROM deleted_subscriptions WHERE name = ?1
                 )",
                params![&name, &remote_id],
            )?;
        }

        tx.execute(
            "DELETE FROM message_to_mailbox
             WHERE mailbox_id = ?1",
            params![mailbox_internal_id as i64],
        )?;

        tx.execute(
            "DELETE FROM mailbox_flags_v2
             WHERE mailbox_id = ?1",
            params![mailbox_internal_id as i64],
        )?;

        tx.execute(
            "DELETE FROM mailbox_perm_flags_v2
             WHERE mailbox_id = ?1",
            params![mailbox_internal_id as i64],
        )?;

        tx.execute(
            "DELETE FROM mailbox_attrs_v2
             WHERE mailbox_id = ?1",
            params![mailbox_internal_id as i64],
        )?;

        tx.execute(
            "DELETE FROM mailboxes_v2
             WHERE id = ?1",
            params![mailbox_internal_id as i64],
        )?;

        tx.execute_batch(&format!("DROP TABLE mailbox_message_{mailbox_internal_id}"))?;

        tx.commit()?;
        Ok(())
    }

    pub fn list_deleted_subscriptions(
        &self,
        storage_user_id: &str,
    ) -> Result<Vec<DeletedSubscription>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT name, remote_id
             FROM deleted_subscriptions
             ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DeletedSubscription {
                name: row.get(0)?,
                remote_id: row.get(1)?,
            })
        })?;

        let mut deleted = Vec::new();
        for row in rows {
            deleted.push(row?);
        }
        Ok(deleted)
    }

    pub fn list_upstream_mailboxes(&self, storage_user_id: &str) -> Result<Vec<UpstreamMailbox>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        list_upstream_mailboxes_on(&conn)
    }

    pub fn list_upstream_mailboxes_rw(
        &self,
        storage_user_id: &str,
    ) -> Result<Vec<UpstreamMailbox>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        list_upstream_mailboxes_on(&conn)
    }

    pub fn list_upstream_mailbox_messages(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
    ) -> Result<Vec<UpstreamMessageSummary>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        list_upstream_mailbox_messages_on(&conn, mailbox_internal_id)
    }

    pub fn read_message_blob(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
    ) -> Result<Vec<u8>> {
        let account_paths = self.account_paths(storage_user_id)?;
        let encoded = std::fs::read(account_paths.blob_path(internal_message_id)?)
            .map_err(GluonCoreError::from)?;
        Ok(decode_blob(&self.account(storage_user_id)?.key, &encoded)?)
    }

    pub fn mailbox_snapshot(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
    ) -> Result<UpstreamMailboxSnapshot> {
        let account_paths = self.account_paths(storage_user_id)?;
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let mailbox = get_upstream_mailbox(&conn, mailbox_internal_id)?;
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let next_uid = next_uid_for_mailbox(&conn, &table_name)?;
        let recent_count = query_count(
            &conn,
            &format!("SELECT COUNT(*) FROM {table_name} WHERE recent = TRUE"),
        )? as usize;

        let mut stmt = conn.prepare(&format!(
            "SELECT mm.message_id, mm.message_remote_id, mm.uid, mm.recent, mm.deleted,
                    m.size, m.deleted, m.body, m.body_structure, m.envelope
             FROM {table_name} AS mm
             JOIN messages_v2 AS m ON m.id = mm.message_id
             ORDER BY mm.uid"
        ))?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let (
                internal_id,
                remote_id,
                uid,
                recent,
                mailbox_deleted,
                size,
                message_deleted,
                body,
                body_structure,
                envelope,
            ) = row?;

            let flags = query_string_vec_on(
                &conn,
                "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
                &internal_id,
            )?;
            let blob_path = account_paths.blob_path(&internal_id)?;

            messages.push(UpstreamMailboxMessage {
                summary: UpstreamMessageSummary {
                    internal_id,
                    remote_id,
                    uid,
                    recent,
                    mailbox_deleted,
                    message_deleted,
                    size,
                    flags,
                },
                body,
                body_structure,
                envelope,
                blob_exists: blob_path.exists(),
                blob_path,
            });
        }

        Ok(UpstreamMailboxSnapshot {
            mailbox,
            next_uid,
            message_count: messages.len(),
            recent_count,
            messages,
        })
    }

    pub fn mailbox_select_data(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
    ) -> Result<SelectSnapshot> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let mailbox = get_upstream_mailbox(&conn, mailbox_internal_id)?;
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let next_uid = next_uid_for_mailbox(&conn, &table_name)?;

        let mut stmt = conn.prepare(&format!(
            "SELECT mm.uid, GROUP_CONCAT(f.value, char(0)) AS flags
             FROM {table_name} AS mm
             LEFT JOIN message_flags_v2 AS f ON f.message_id = mm.message_id
             GROUP BY mm.message_id
             ORDER BY mm.uid"
        ))?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Option<String>>(1)?))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (uid, flags_concat) = row?;
            let flags = flags_concat
                .map(|s| s.split('\0').map(String::from).collect())
                .unwrap_or_default();
            entries.push(SelectSnapshotEntry { uid, flags });
        }

        Ok(SelectSnapshot {
            uid_validity: mailbox.uid_validity,
            next_uid,
            entries,
        })
    }

    pub fn message_by_uid(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        uid: u32,
    ) -> Result<Option<UpstreamMailboxMessage>> {
        let account_paths = self.account_paths(storage_user_id)?;
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");

        let result = conn
            .query_row(
                &format!(
                    "SELECT mm.message_id, mm.message_remote_id, mm.uid, mm.recent, mm.deleted,
                            m.size, m.deleted, m.body, m.body_structure, m.envelope
                     FROM {table_name} AS mm
                     JOIN messages_v2 AS m ON m.id = mm.message_id
                     WHERE mm.uid = ?1"
                ),
                params![uid],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            internal_id,
            remote_id,
            uid_val,
            recent,
            mailbox_deleted,
            size,
            message_deleted,
            body,
            body_structure,
            envelope,
        )) = result
        else {
            return Ok(None);
        };

        let flags = query_string_vec_on(
            &conn,
            "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
            &internal_id,
        )?;
        let blob_path = account_paths.blob_path(&internal_id)?;

        Ok(Some(UpstreamMailboxMessage {
            summary: UpstreamMessageSummary {
                internal_id,
                remote_id,
                uid: uid_val,
                recent,
                mailbox_deleted,
                message_deleted,
                size,
                flags,
            },
            body,
            body_structure,
            envelope,
            blob_exists: blob_path.exists(),
            blob_path,
        }))
    }

    pub fn message_internal_id_by_uid(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        uid: u32,
    ) -> Result<Option<String>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let result: Option<String> = conn
            .query_row(
                &format!("SELECT message_id FROM {table_name} WHERE uid = ?1"),
                params![uid],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    pub fn message_flags_by_internal_id(
        &self,
        storage_user_id: &str,
        internal_id: &str,
    ) -> Result<Vec<String>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        query_string_vec_on(
            &conn,
            "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
            internal_id,
        )
    }

    pub fn message_remote_id_by_uid(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        uid: u32,
    ) -> Result<Option<String>> {
        let handle = self.conn_for(storage_user_id)?;
        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let result: Option<String> = conn
            .query_row(
                &format!("SELECT message_remote_id FROM {table_name} WHERE uid = ?1"),
                params![uid],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    /// Return the shared connection handle for this account. Callers that
    /// previously received a `SqlitePool` now get a `ConnHandle`.
    pub fn open_connection(&self, storage_user_id: &str) -> Result<ConnHandle> {
        self.conn_for(storage_user_id)
    }

    pub fn open_connection_rw(&self, storage_user_id: &str) -> Result<ConnHandle> {
        self.conn_for(storage_user_id)
    }

    pub fn batch_find_uids_by_remote_id(
        &self,
        handle: &ConnHandle,
        mailbox_internal_id: u64,
        remote_ids: &[&str],
    ) -> Result<HashMap<String, u32>> {
        if remote_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let placeholders = remote_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let sql = format!(
            "SELECT mm.message_remote_id, mm.uid
             FROM {table_name} AS mm
             WHERE mm.message_remote_id IN ({placeholders})"
        );

        let mut stmt = conn.prepare(&sql)?;
        let param_values: Vec<&dyn rusqlite::types::ToSql> = remote_ids
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt.query_map(param_values.as_slice(), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;

        let mut result = HashMap::new();
        for row in rows {
            let (remote_id, uid) = row?;
            result.insert(remote_id, uid);
        }

        Ok(result)
    }

    pub fn batch_find_internal_ids_by_remote_id(
        &self,
        handle: &ConnHandle,
        remote_ids: &[&str],
    ) -> Result<HashMap<String, String>> {
        if remote_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let placeholders = remote_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let sql =
            format!("SELECT remote_id, id FROM messages_v2 WHERE remote_id IN ({placeholders})");

        let mut stmt = conn.prepare(&sql)?;
        let param_values: Vec<&dyn rusqlite::types::ToSql> = remote_ids
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt.query_map(param_values.as_slice(), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut result = HashMap::new();
        for row in rows {
            let (remote_id, internal_id) = row?;
            result.insert(remote_id, internal_id);
        }

        Ok(result)
    }

    pub fn batch_set_message_flags_on_conn(
        &self,
        handle: &ConnHandle,
        entries: &[(&str, &[String])],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;
        for (internal_message_id, flags) in entries {
            tx.execute(
                "DELETE FROM message_flags_v2 WHERE message_id = ?1",
                params![*internal_message_id],
            )?;
            insert_message_flags_ignore_duplicates(&tx, internal_message_id, flags)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn batch_add_existing_messages_to_mailbox(
        &self,
        handle: &ConnHandle,
        mailbox_internal_id: u64,
        internal_message_ids: &[&str],
    ) -> Result<()> {
        if internal_message_ids.is_empty() {
            return Ok(());
        }

        let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;
        for internal_message_id in internal_message_ids {
            let remote_id: String = tx.query_row(
                "SELECT remote_id FROM messages_v2 WHERE id = ?1",
                params![*internal_message_id],
                |row| row.get(0),
            )?;

            tx.execute(
                "INSERT OR IGNORE INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, ?2)",
                params![*internal_message_id, mailbox_internal_id as i64],
            )?;

            tx.execute(
                &format!(
                    "INSERT INTO mailbox_message_{mailbox_internal_id}(message_id, message_remote_id)
                     VALUES(?1, ?2)"
                ),
                params![*internal_message_id, &remote_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn batch_append_messages(
        &self,
        storage_user_id: &str,
        handle: &ConnHandle,
        mailbox_internal_id: u64,
        messages: &[NewMessage],
    ) -> Result<Vec<UpstreamMessageSummary>> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        let account_paths = self.account_paths(storage_user_id)?;
        let account = self.account(storage_user_id)?;
        std::fs::create_dir_all(account_paths.store_dir()).map_err(GluonCoreError::from)?;

        for message in messages {
            let blob_path = account_paths.blob_path(&message.internal_id)?;
            let encoded = encode_blob(&account.key, &message.blob)?;
            std::fs::write(&blob_path, encoded).map_err(GluonCoreError::from)?;
        }

        {
            let conn = handle.lock().unwrap_or_else(|e| e.into_inner());
            let tx = conn.unchecked_transaction()?;
            for message in messages {
                tx.execute(
                    "INSERT INTO messages_v2(id, remote_id, date, size, body, body_structure, envelope, deleted)
                     VALUES(?1, ?2, datetime('now'), ?3, ?4, ?5, ?6, FALSE)",
                    params![
                        &message.internal_id,
                        &message.remote_id,
                        message.size,
                        &message.body,
                        &message.body_structure,
                        &message.envelope,
                    ],
                )?;

                tx.execute(
                    "INSERT INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, ?2)",
                    params![&message.internal_id, mailbox_internal_id as i64],
                )?;

                tx.execute(
                    &format!(
                        "INSERT INTO mailbox_message_{mailbox_internal_id}(message_id, message_remote_id, recent, deleted)
                         VALUES(?1, ?2, ?3, FALSE)"
                    ),
                    params![&message.internal_id, &message.remote_id, message.recent],
                )?;

                insert_message_flags(&tx, &message.internal_id, &message.flags)?;
            }
            tx.commit()?;
        }

        let all_messages =
            self.list_upstream_mailbox_messages(storage_user_id, mailbox_internal_id)?;
        let appended_ids: std::collections::HashSet<&str> = messages
            .iter()
            .map(|message| message.internal_id.as_str())
            .collect();
        Ok(all_messages
            .into_iter()
            .filter(|summary| appended_ids.contains(summary.internal_id.as_str()))
            .collect())
    }
}

/// A pre-connected session for batching multiple queries with a single connection.
pub struct StoreSession {
    conn: ConnHandle,
}

impl StoreSession {
    pub fn mailbox_select_data(&self, mailbox_internal_id: u64) -> Result<SelectSnapshot> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let uid_validity: u32 = conn.query_row(
            "SELECT uid_validity FROM mailboxes_v2 WHERE id = ?",
            params![mailbox_internal_id as i64],
            |row| row.get(0),
        )?;

        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let next_uid = next_uid_for_mailbox(&conn, &table_name)?;

        let mut stmt = conn.prepare(&format!(
            "SELECT mm.uid, GROUP_CONCAT(f.value, char(0)) AS flags
             FROM {table_name} AS mm
             LEFT JOIN message_flags_v2 AS f ON f.message_id = mm.message_id
             GROUP BY mm.message_id
             ORDER BY mm.uid"
        ))?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Option<String>>(1)?))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (uid, flags_concat) = row?;
            let flags = flags_concat
                .map(|s| s.split('\0').map(String::from).collect())
                .unwrap_or_default();
            entries.push(SelectSnapshotEntry { uid, flags });
        }

        Ok(SelectSnapshot {
            uid_validity,
            next_uid,
            entries,
        })
    }

    pub fn message_internal_id_by_uid(
        &self,
        mailbox_internal_id: u64,
        uid: u32,
    ) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        Ok(conn
            .query_row(
                &format!("SELECT message_id FROM {table_name} WHERE uid = ?"),
                params![uid],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn message_flags_by_internal_id(&self, internal_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        query_string_vec_on(
            &conn,
            "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
            internal_id,
        )
    }

    pub fn set_message_flags(&self, internal_message_id: &str, flags: &[String]) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "DELETE FROM message_flags_v2 WHERE message_id = ?",
            params![internal_message_id],
        )?;
        for flag in flags {
            conn.execute(
                "INSERT OR IGNORE INTO message_flags_v2(message_id, value) VALUES(?, ?)",
                params![internal_message_id, flag],
            )?;
        }
        Ok(())
    }

    pub fn add_message_flags(&self, internal_message_id: &str, flags: &[String]) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for flag in flags {
            conn.execute(
                "INSERT OR IGNORE INTO message_flags_v2(message_id, value) VALUES(?, ?)",
                params![internal_message_id, flag],
            )?;
        }
        Ok(())
    }

    pub fn remove_message_flags(&self, internal_message_id: &str, flags: &[String]) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for flag in flags {
            conn.execute(
                "DELETE FROM message_flags_v2 WHERE message_id = ? AND value = ?",
                params![internal_message_id, flag],
            )?;
        }
        Ok(())
    }

    pub fn remove_message_from_mailbox(
        &self,
        mailbox_internal_id: u64,
        internal_message_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        conn.execute(
            &format!("DELETE FROM {table_name} WHERE message_id = ?"),
            params![internal_message_id],
        )?;
        conn.execute(
            "DELETE FROM message_to_mailbox WHERE message_id = ? AND mailbox_id = ?",
            params![internal_message_id, mailbox_internal_id as i64],
        )?;
        Ok(())
    }

    pub fn message_remote_id_by_uid(
        &self,
        mailbox_internal_id: u64,
        uid: u32,
    ) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        Ok(conn
            .query_row(
                &format!("SELECT message_remote_id FROM {table_name} WHERE uid = ?"),
                params![uid],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn message_by_uid(
        &self,
        mailbox_internal_id: u64,
        uid: u32,
        account_paths: &AccountPaths,
    ) -> Result<Option<UpstreamMailboxMessage>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let result = conn
            .query_row(
                &format!(
                    "SELECT mm.message_id, mm.message_remote_id, mm.uid, mm.recent, mm.deleted,
                            m.size, m.deleted, m.body, m.body_structure, m.envelope
                     FROM {table_name} AS mm
                     JOIN messages_v2 AS m ON m.id = mm.message_id
                     WHERE mm.uid = ?"
                ),
                params![uid],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            internal_id,
            remote_id,
            uid_val,
            recent,
            mailbox_deleted,
            size,
            message_deleted,
            body,
            body_structure,
            envelope,
        )) = result
        else {
            return Ok(None);
        };

        let flags = query_string_vec_on(
            &conn,
            "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
            &internal_id,
        )?;

        let blob_path = account_paths.blob_path(&internal_id)?;

        Ok(Some(UpstreamMailboxMessage {
            summary: UpstreamMessageSummary {
                internal_id,
                remote_id,
                uid: uid_val,
                recent,
                mailbox_deleted,
                message_deleted,
                size,
                flags,
            },
            body,
            body_structure,
            envelope,
            blob_exists: blob_path.exists(),
            blob_path,
        }))
    }

    pub fn list_uids(&self, mailbox_internal_id: u64) -> Result<Vec<u32>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&format!(
            "SELECT uid FROM mailbox_message_{mailbox_internal_id} ORDER BY uid"
        ))?;
        let rows = stmt.query_map([], |row| row.get::<_, u32>(0))?;
        let mut uids = Vec::new();
        for row in rows {
            uids.push(row?);
        }
        Ok(uids)
    }

    pub fn mailbox_status(&self, mailbox_internal_id: u64) -> Result<(u32, u32, u32)> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let exists: u32 =
            conn.query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
                row.get(0)
            })?;
        let next_uid = next_uid_for_mailbox(&conn, &table_name)?;
        let uid_validity: u32 = conn.query_row(
            "SELECT uid_validity FROM mailboxes_v2 WHERE id = ?",
            params![mailbox_internal_id as i64],
            |row| row.get(0),
        )?;
        Ok((uid_validity, next_uid, exists))
    }

    pub fn read_rfc822(
        &self,
        mailbox_internal_id: u64,
        uid: u32,
        account_paths: &AccountPaths,
        key: &gluon_rs_core::GluonKey,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let internal_id: Option<String> = conn
            .query_row(
                &format!("SELECT message_id FROM {table_name} WHERE uid = ?"),
                params![uid],
                |row| row.get(0),
            )
            .optional()?;
        let Some(internal_id) = internal_id else {
            return Ok(None);
        };
        let blob_path = account_paths.blob_path(&internal_id)?;
        if !blob_path.exists() {
            return Ok(None);
        }
        let encoded = std::fs::read(&blob_path).map_err(gluon_rs_core::GluonCoreError::from)?;
        Ok(Some(decode_blob(key, &encoded)?))
    }

    pub fn store_rfc822(
        &self,
        mailbox_internal_id: u64,
        uid: u32,
        data: &[u8],
        account_paths: &AccountPaths,
        key: &gluon_rs_core::GluonKey,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let internal_id: Option<String> = conn
            .query_row(
                &format!("SELECT message_id FROM {table_name} WHERE uid = ?"),
                params![uid],
                |row| row.get(0),
            )
            .optional()?;
        let Some(internal_id) = internal_id else {
            return Ok(());
        };
        std::fs::create_dir_all(account_paths.store_dir())
            .map_err(gluon_rs_core::GluonCoreError::from)?;
        let blob_path = account_paths.blob_path(&internal_id)?;
        let encoded = encode_blob(key, data)?;
        std::fs::write(&blob_path, encoded).map_err(gluon_rs_core::GluonCoreError::from)?;
        Ok(())
    }

    pub fn list_upstream_mailboxes(&self) -> Result<Vec<UpstreamMailbox>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT id, remote_id, name, uid_validity, subscribed FROM mailboxes_v2 ORDER BY id",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, bool>(4)?,
            ))
        })?;

        let mut mailboxes = Vec::new();
        for row in rows {
            let (id, remote_id, name, uid_validity, subscribed) = row?;
            mailboxes.push(UpstreamMailbox {
                internal_id: id as u64,
                remote_id,
                name,
                uid_validity,
                subscribed,
                attributes: Vec::new(),
                flags: Vec::new(),
                permanent_flags: Vec::new(),
            });
        }
        Ok(mailboxes)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn query_string_vec_on(conn: &Connection, sql: &str, param: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![param], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

fn query_count(conn: &Connection, sql: &str) -> Result<u32> {
    let count: u32 = conn.query_row(sql, [], |row| row.get(0))?;
    Ok(count)
}

fn next_uid_for_mailbox(conn: &Connection, table_name: &str) -> Result<u32> {
    let result: Option<u32> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = ?",
            params![table_name],
            |row| row.get(0),
        )
        .optional()?;
    match result {
        Some(seq) => Ok(seq.saturating_add(1)),
        None => Ok(1),
    }
}

fn insert_mailbox_flags(
    conn: &Connection,
    table_name: &str,
    mailbox_id: u64,
    values: &[String],
) -> Result<()> {
    let sql = format!("INSERT INTO {table_name}(mailbox_id, value) VALUES(?1, ?2)");
    for value in values {
        conn.execute(&sql, params![mailbox_id as i64, value])?;
    }
    Ok(())
}

fn insert_message_flags(conn: &Connection, message_id: &str, values: &[String]) -> Result<()> {
    for value in values {
        conn.execute(
            "INSERT INTO message_flags_v2(message_id, value) VALUES(?1, ?2)",
            params![message_id, value],
        )?;
    }
    Ok(())
}

fn insert_message_flags_ignore_duplicates(
    conn: &Connection,
    message_id: &str,
    values: &[String],
) -> Result<()> {
    for value in values {
        conn.execute(
            "INSERT OR IGNORE INTO message_flags_v2(message_id, value) VALUES(?1, ?2)",
            params![message_id, value],
        )?;
    }
    Ok(())
}

fn create_mailbox_message_table_sql(mailbox_internal_id: u64) -> String {
    format!(
        "CREATE TABLE `mailbox_message_{mailbox_internal_id}` (
            `uid` integer NOT NULL PRIMARY KEY AUTOINCREMENT,
            `deleted` bool NOT NULL DEFAULT false,
            `recent` bool NOT NULL DEFAULT true,
            `message_id` text NOT NULL UNIQUE,
            `message_remote_id` text NOT NULL UNIQUE,
            CONSTRAINT `mailbox_message_{mailbox_internal_id}_message_id`
                FOREIGN KEY (`message_id`) REFERENCES `messages_v2` (`id`) ON DELETE SET NULL
        )"
    )
}

fn get_upstream_mailbox(conn: &Connection, mailbox_internal_id: u64) -> Result<UpstreamMailbox> {
    let (internal_id, remote_id, name, uid_validity, subscribed): (i64, String, String, u32, bool) =
        conn.query_row(
            "SELECT id, remote_id, name, uid_validity, subscribed
         FROM mailboxes_v2
         WHERE id = ?",
            params![mailbox_internal_id as i64],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;

    let internal_id = internal_id as u64;

    Ok(UpstreamMailbox {
        internal_id,
        remote_id,
        name,
        uid_validity,
        subscribed,
        attributes: query_string_vec_on(
            conn,
            "SELECT value FROM mailbox_attrs_v2 WHERE mailbox_id = ? ORDER BY value",
            &(internal_id as i64).to_string(),
        )
        .unwrap_or_default(),
        flags: query_string_vec_on(
            conn,
            "SELECT value FROM mailbox_flags_v2 WHERE mailbox_id = ? ORDER BY value",
            &(internal_id as i64).to_string(),
        )
        .unwrap_or_default(),
        permanent_flags: query_string_vec_on(
            conn,
            "SELECT value FROM mailbox_perm_flags_v2 WHERE mailbox_id = ? ORDER BY value",
            &(internal_id as i64).to_string(),
        )
        .unwrap_or_default(),
    })
}

fn list_upstream_mailboxes_on(conn: &Connection) -> Result<Vec<UpstreamMailbox>> {
    let mut stmt = conn.prepare(
        "SELECT id, remote_id, name, uid_validity, subscribed
         FROM mailboxes_v2
         ORDER BY id",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, u32>(3)?,
            row.get::<_, bool>(4)?,
        ))
    })?;

    let mut mailboxes = Vec::new();
    for row in rows {
        let (id, remote_id, name, uid_validity, subscribed) = row?;
        let internal_id = id as u64;
        mailboxes.push(UpstreamMailbox {
            internal_id,
            remote_id,
            name,
            uid_validity,
            subscribed,
            attributes: query_string_vec_on(
                conn,
                "SELECT value FROM mailbox_attrs_v2 WHERE mailbox_id = ? ORDER BY value",
                &(internal_id as i64).to_string(),
            )
            .unwrap_or_default(),
            flags: query_string_vec_on(
                conn,
                "SELECT value FROM mailbox_flags_v2 WHERE mailbox_id = ? ORDER BY value",
                &(internal_id as i64).to_string(),
            )
            .unwrap_or_default(),
            permanent_flags: query_string_vec_on(
                conn,
                "SELECT value FROM mailbox_perm_flags_v2 WHERE mailbox_id = ? ORDER BY value",
                &(internal_id as i64).to_string(),
            )
            .unwrap_or_default(),
        });
    }

    Ok(mailboxes)
}

fn list_upstream_mailbox_messages_on(
    conn: &Connection,
    mailbox_internal_id: u64,
) -> Result<Vec<UpstreamMessageSummary>> {
    let table_name = format!("mailbox_message_{mailbox_internal_id}");
    let mut stmt = conn.prepare(&format!(
        "SELECT mm.message_id, mm.message_remote_id, mm.uid, mm.recent, mm.deleted,
                m.size, m.deleted,
                GROUP_CONCAT(mf.value) AS flags_csv
         FROM {table_name} AS mm
         JOIN messages_v2 AS m ON m.id = mm.message_id
         LEFT JOIN message_flags_v2 AS mf ON mf.message_id = mm.message_id
         GROUP BY mm.message_id
         ORDER BY mm.uid"
    ))?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u32>(2)?,
            row.get::<_, bool>(3)?,
            row.get::<_, bool>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, bool>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;

    let mut messages = Vec::new();
    for row in rows {
        let (
            internal_id,
            remote_id,
            uid,
            recent,
            mailbox_deleted,
            size,
            message_deleted,
            flags_csv,
        ) = row?;
        let flags = flags_csv
            .map(|csv| csv.split(',').map(String::from).collect())
            .unwrap_or_default();
        messages.push(UpstreamMessageSummary {
            internal_id,
            remote_id,
            uid,
            recent,
            mailbox_deleted,
            size,
            message_deleted,
            flags,
        });
    }

    Ok(messages)
}

const UPSTREAM_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS deleted_subscriptions(
        name TEXT NOT NULL,
        remote_id TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS mailboxes_v2(
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        remote_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        uid_validity INTEGER NOT NULL,
        subscribed BOOLEAN NOT NULL DEFAULT TRUE
    )",
    "CREATE TABLE IF NOT EXISTS mailbox_flags_v2(
        value TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(value, mailbox_id)
    )",
    "CREATE TABLE IF NOT EXISTS mailbox_attrs_v2(
        value TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(value, mailbox_id)
    )",
    "CREATE TABLE IF NOT EXISTS mailbox_perm_flags_v2(
        value TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(value, mailbox_id)
    )",
    "CREATE TABLE IF NOT EXISTS messages_v2(
        id TEXT NOT NULL PRIMARY KEY,
        remote_id TEXT NOT NULL UNIQUE,
        date TEXT,
        size INTEGER NOT NULL,
        body TEXT NOT NULL,
        body_structure TEXT NOT NULL,
        envelope TEXT NOT NULL,
        deleted BOOLEAN NOT NULL DEFAULT FALSE
    )",
    "CREATE TABLE IF NOT EXISTS message_flags_v2(
        value TEXT NOT NULL,
        message_id TEXT NOT NULL,
        PRIMARY KEY(value, message_id)
    )",
    "CREATE INDEX IF NOT EXISTS message_flags_message_id_index ON message_flags_v2(message_id)",
    "CREATE TABLE IF NOT EXISTS message_to_mailbox(
        message_id TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(message_id, mailbox_id)
    )",
    "CREATE TABLE IF NOT EXISTS connector_settings(
        id INTEGER NOT NULL PRIMARY KEY,
        value TEXT
    )",
    "CREATE TABLE IF NOT EXISTS gluon_version(
        id INTEGER NOT NULL PRIMARY KEY CHECK(id = 0),
        version INTEGER NOT NULL
    )",
];

#[cfg(test)]
mod tests {
    use std::fs;

    use gluon_rs_core::{CacheLayout, DeferredDeleteManager, GluonKey};
    use rusqlite::Connection;
    use tempfile::tempdir;

    use crate::{encode_blob, target::CompatibilityTarget, AccountBootstrap, StoreBootstrap};

    use super::{CompatibleStore, DeletedSubscription, NewMailbox, NewMessage};

    #[test]
    fn opens_store_and_creates_layout() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path()),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[3u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let account_paths = store.account_paths("user-1").expect("account paths");
        assert!(account_paths.store_dir().exists());
        assert_eq!(
            store.schema_probe("user-1").expect("schema probe").family,
            crate::SchemaFamily::Missing
        );
    }

    #[test]
    fn reads_upstream_mailboxes_and_messages_from_real_table_shape() {
        let temp = tempdir().expect("tempdir");
        let cache_root = temp.path().join("gluon");
        let layout = CacheLayout::new(&cache_root);
        layout.ensure_base_dirs().expect("base dirs");

        let account_paths = layout.account_paths("user-1").expect("account paths");
        fs::create_dir_all(account_paths.store_dir()).expect("store dir");
        fs::write(
            account_paths
                .blob_path("11111111-1111-1111-1111-111111111111")
                .expect("blob path"),
            encode_blob(
                &GluonKey::try_from_slice(&[4u8; 32]).expect("key"),
                b"blob payload",
            )
            .expect("encode blob"),
        )
        .expect("blob");

        // Set up schema using rusqlite directly.
        let db_path = account_paths.primary_db_path();
        let conn = Connection::open(&db_path).expect("open db");

        let schema_stmts = [
            "CREATE TABLE deleted_subscriptions(name TEXT, remote_id TEXT)",
            "CREATE TABLE mailboxes_v2(
                id INTEGER PRIMARY KEY,
                remote_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE,
                uid_validity INTEGER NOT NULL,
                subscribed BOOLEAN NOT NULL
            )",
            "CREATE TABLE mailbox_flags_v2(
                value TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(value, mailbox_id)
            )",
            "CREATE TABLE mailbox_attrs_v2(
                value TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(value, mailbox_id)
            )",
            "CREATE TABLE mailbox_perm_flags_v2(
                value TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(value, mailbox_id)
            )",
            "CREATE TABLE messages_v2(
                id TEXT NOT NULL PRIMARY KEY,
                remote_id TEXT NOT NULL UNIQUE,
                date TEXT,
                size INTEGER NOT NULL,
                body TEXT,
                body_structure TEXT,
                envelope TEXT,
                deleted BOOLEAN NOT NULL DEFAULT false
            )",
            "CREATE TABLE message_flags_v2(
                value TEXT NOT NULL,
                message_id TEXT NOT NULL,
                PRIMARY KEY(value, message_id)
            )",
            "CREATE TABLE message_to_mailbox(
                message_id TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(message_id, mailbox_id)
            )",
            "CREATE TABLE connector_settings(
                id INTEGER NOT NULL PRIMARY KEY,
                value TEXT
            )",
            "CREATE TABLE gluon_version(
                id INTEGER NOT NULL PRIMARY KEY,
                version INTEGER NOT NULL
            )",
            "CREATE TABLE mailbox_message_1(
                uid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                deleted BOOLEAN NOT NULL DEFAULT false,
                recent BOOLEAN NOT NULL DEFAULT true,
                message_id TEXT NOT NULL UNIQUE,
                message_remote_id TEXT NOT NULL UNIQUE
            )",
        ];
        for stmt in schema_stmts {
            conn.execute_batch(stmt).expect("schema");
        }

        conn.execute(
            "INSERT INTO mailboxes_v2(id, remote_id, name, uid_validity, subscribed) VALUES(1, ?1, ?2, ?3, ?4)",
            rusqlite::params!["mbox-remote-1", "INBOX", 777u32, true],
        ).expect("insert mailbox");
        conn.execute(
            "INSERT INTO mailbox_attrs_v2(value, mailbox_id) VALUES(?1, 1)",
            rusqlite::params!["\\HasNoChildren"],
        )
        .expect("insert attr");
        conn.execute(
            "INSERT INTO mailbox_flags_v2(value, mailbox_id) VALUES(?1, 1)",
            rusqlite::params!["\\Draft"],
        )
        .expect("insert mailbox flag");
        conn.execute(
            "INSERT INTO mailbox_perm_flags_v2(value, mailbox_id) VALUES(?1, 1)",
            rusqlite::params!["\\Seen"],
        )
        .expect("insert mailbox perm flag");
        conn.execute(
            "INSERT INTO messages_v2(id, remote_id, date, size, body, body_structure, envelope, deleted)
             VALUES(?1, ?2, '2026-03-11T10:00:00Z', 123, '', '', '', false)",
            rusqlite::params!["11111111-1111-1111-1111-111111111111", "msg-remote-1"],
        ).expect("insert message");
        conn.execute(
            "INSERT INTO message_flags_v2(value, message_id) VALUES(?1, ?2)",
            rusqlite::params!["\\Seen", "11111111-1111-1111-1111-111111111111"],
        )
        .expect("insert message flag");
        conn.execute(
            "INSERT INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, 1)",
            rusqlite::params!["11111111-1111-1111-1111-111111111111"],
        )
        .expect("insert message map");
        conn.execute(
            "INSERT INTO connector_settings(id, value) VALUES(0, NULL)",
            [],
        )
        .expect("insert connector settings");
        conn.execute("INSERT INTO gluon_version(id, version) VALUES(0, 3)", [])
            .expect("insert version");
        conn.execute(
            "INSERT INTO mailbox_message_1(message_id, message_remote_id, recent, deleted) VALUES(?1, ?2, true, false)",
            rusqlite::params!["11111111-1111-1111-1111-111111111111", "msg-remote-1"],
        ).expect("insert mailbox message");
        drop(conn);

        let store = CompatibleStore::open_read_only(StoreBootstrap::new(
            layout,
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[4u8; 32]).expect("key"),
            )],
        ))
        .expect("open readonly store");

        let mailboxes = store
            .list_upstream_mailboxes("user-1")
            .expect("list mailboxes");
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].name, "INBOX");
        assert_eq!(
            mailboxes[0].attributes,
            vec![String::from("\\HasNoChildren")]
        );
        assert_eq!(mailboxes[0].flags, vec![String::from("\\Draft")]);
        assert_eq!(mailboxes[0].permanent_flags, vec![String::from("\\Seen")]);

        let messages = store
            .list_upstream_mailbox_messages("user-1", 1)
            .expect("list messages");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, 1);
        assert_eq!(messages[0].remote_id, "msg-remote-1");
        assert_eq!(messages[0].flags, vec![String::from("\\Seen")]);
        let snapshot = store.mailbox_snapshot("user-1", 1).expect("snapshot");
        assert_eq!(snapshot.mailbox.name, "INBOX");
        assert_eq!(snapshot.next_uid, 2);
        assert_eq!(snapshot.message_count, 1);
        assert_eq!(snapshot.recent_count, 1);
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.messages[0].summary.uid, 1);
        assert_eq!(
            snapshot.messages[0].summary.flags,
            vec![String::from("\\Seen")]
        );
        assert!(snapshot.messages[0].blob_exists);
        assert_eq!(snapshot.messages[0].body, "");
        assert_eq!(
            store
                .read_message_blob("user-1", "11111111-1111-1111-1111-111111111111")
                .expect("read blob"),
            b"blob payload"
        );
    }

    #[test]
    fn creates_mailbox_and_appends_message_using_upstream_tables() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[5u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-1".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 999,
                    subscribed: true,
                    attributes: vec!["\\HasNoChildren".to_string()],
                    flags: vec!["\\Draft".to_string()],
                    permanent_flags: vec!["\\Seen".to_string()],
                },
            )
            .expect("create mailbox");
        assert_eq!(mailbox.internal_id, 1);

        let summary = store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "22222222-2222-2222-2222-222222222222".to_string(),
                    remote_id: "msg-2".to_string(),
                    flags: vec!["\\Seen".to_string()],
                    blob: b"hello world".to_vec(),
                    body: "body".to_string(),
                    body_structure: "body-structure".to_string(),
                    envelope: "envelope".to_string(),
                    size: 11,
                    recent: true,
                },
            )
            .expect("append message");
        assert_eq!(summary.uid, 1);
        assert_eq!(summary.internal_id, "22222222-2222-2222-2222-222222222222");

        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(snapshot.next_uid, 2);
        assert_eq!(snapshot.message_count, 1);
        assert_eq!(snapshot.messages[0].body, "body");
        assert_eq!(
            store
                .read_message_blob("user-1", "22222222-2222-2222-2222-222222222222")
                .expect("blob"),
            b"hello world"
        );
        assert_eq!(
            store.cleanup_deferred_database_files().map(|_| ()).is_ok(),
            true
        );
    }

    #[test]
    fn replaces_message_content_without_changing_uid() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[4u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-1".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 999,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec!["\\Seen".to_string()],
                },
            )
            .expect("create mailbox");

        let summary = store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "aaaaaaa1-2222-3333-4444-555555555555".to_string(),
                    remote_id: "msg-4".to_string(),
                    flags: vec![],
                    blob: b"placeholder".to_vec(),
                    body: "placeholder".to_string(),
                    body_structure: "placeholder-structure".to_string(),
                    envelope: "placeholder-envelope".to_string(),
                    size: 11,
                    recent: false,
                },
            )
            .expect("append message");
        assert_eq!(summary.uid, 1);

        store
            .replace_message_content(
                "user-1",
                "aaaaaaa1-2222-3333-4444-555555555555",
                b"updated body",
                "updated",
                "updated-structure",
                "updated-envelope",
                12,
            )
            .expect("replace message content");

        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(snapshot.messages[0].summary.uid, 1);
        assert_eq!(snapshot.messages[0].summary.size, 12);
        assert_eq!(snapshot.messages[0].body, "updated");
        assert_eq!(snapshot.messages[0].body_structure, "updated-structure");
        assert_eq!(snapshot.messages[0].envelope, "updated-envelope");
        assert_eq!(
            store
                .read_message_blob("user-1", "aaaaaaa1-2222-3333-4444-555555555555")
                .expect("blob"),
            b"updated body"
        );
    }

    #[test]
    fn defers_account_database_deletion_like_upstream() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[2u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");
        let account_paths = store.account_paths("user-1").expect("account paths");
        std::fs::create_dir_all(account_paths.primary_db_path().parent().expect("db parent"))
            .expect("db dir");
        std::fs::write(account_paths.primary_db_path(), b"db").expect("db");
        std::fs::write(account_paths.wal_path(), b"wal").expect("wal");
        std::fs::write(account_paths.shm_path(), b"shm").expect("shm");

        let moved = store
            .delete_account_database_files("user-1")
            .expect("defer db delete");
        assert_eq!(moved, 3);
        assert!(!account_paths.primary_db_path().exists());
        assert!(!account_paths.wal_path().exists());
        assert!(!account_paths.shm_path().exists());
        assert_eq!(
            std::fs::read_dir(
                DeferredDeleteManager::new(store.bootstrap.layout.db_dir())
                    .expect("manager")
                    .deferred_delete_dir()
            )
            .expect("read deferred")
            .count(),
            3
        );
    }

    #[test]
    fn mutates_message_flags_with_upstream_semantics() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[6u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-1".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 999,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec!["\\Seen".to_string(), "\\Flagged".to_string()],
                },
            )
            .expect("create mailbox");

        store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "33333333-3333-3333-3333-333333333333".to_string(),
                    remote_id: "msg-3".to_string(),
                    flags: vec!["\\Seen".to_string()],
                    blob: b"flag-body".to_vec(),
                    body: "body".to_string(),
                    body_structure: "body-structure".to_string(),
                    envelope: "envelope".to_string(),
                    size: 9,
                    recent: true,
                },
            )
            .expect("append");

        store
            .add_message_flags(
                "user-1",
                "33333333-3333-3333-3333-333333333333",
                &[
                    "\\Flagged".to_string(),
                    "\\Seen".to_string(),
                    "\\Answered".to_string(),
                ],
            )
            .expect("add flags");
        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(
            snapshot.messages[0].summary.flags,
            vec![
                "\\Answered".to_string(),
                "\\Flagged".to_string(),
                "\\Seen".to_string()
            ]
        );

        store
            .remove_message_flags(
                "user-1",
                "33333333-3333-3333-3333-333333333333",
                &["\\Seen".to_string()],
            )
            .expect("remove flag");
        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(
            snapshot.messages[0].summary.flags,
            vec!["\\Answered".to_string(), "\\Flagged".to_string()]
        );

        store
            .set_message_flags(
                "user-1",
                "33333333-3333-3333-3333-333333333333",
                &["\\Draft".to_string()],
            )
            .expect("set flags");
        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(
            snapshot.messages[0].summary.flags,
            vec!["\\Draft".to_string()]
        );
    }

    #[test]
    fn tracks_mailbox_local_and_global_delete_state_separately() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-1".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 1001,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create mailbox");

        store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "44444444-4444-4444-4444-444444444444".to_string(),
                    remote_id: "msg-4".to_string(),
                    flags: vec![],
                    blob: b"delete-body".to_vec(),
                    body: "body".to_string(),
                    body_structure: "body-structure".to_string(),
                    envelope: "envelope".to_string(),
                    size: 11,
                    recent: false,
                },
            )
            .expect("append");

        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert!(!snapshot.messages[0].summary.mailbox_deleted);
        assert!(!snapshot.messages[0].summary.message_deleted);

        store
            .set_mailbox_message_deleted(
                "user-1",
                mailbox.internal_id,
                "44444444-4444-4444-4444-444444444444",
                true,
            )
            .expect("mark mailbox deleted");
        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert!(snapshot.messages[0].summary.mailbox_deleted);
        assert!(!snapshot.messages[0].summary.message_deleted);

        store
            .set_message_deleted("user-1", "44444444-4444-4444-4444-444444444444", true)
            .expect("mark global deleted");
        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert!(snapshot.messages[0].summary.mailbox_deleted);
        assert!(snapshot.messages[0].summary.message_deleted);

        store
            .set_mailbox_message_deleted(
                "user-1",
                mailbox.internal_id,
                "44444444-4444-4444-4444-444444444444",
                false,
            )
            .expect("clear mailbox deleted");
        store
            .set_message_deleted("user-1", "44444444-4444-4444-4444-444444444444", false)
            .expect("clear global deleted");
        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert!(!snapshot.messages[0].summary.mailbox_deleted);
        assert!(!snapshot.messages[0].summary.message_deleted);
    }

    #[test]
    fn adds_and_removes_existing_message_across_mailboxes() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[8u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let inbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-inbox".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 2001,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create inbox");
        let archive = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-archive".to_string(),
                    name: "Archive".to_string(),
                    uid_validity: 2002,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create archive");

        let initial = store
            .append_message(
                "user-1",
                inbox.internal_id,
                &NewMessage {
                    internal_id: "55555555-5555-5555-5555-555555555555".to_string(),
                    remote_id: "msg-5".to_string(),
                    flags: vec!["\\Seen".to_string()],
                    blob: b"copy-body".to_vec(),
                    body: "body".to_string(),
                    body_structure: "body-structure".to_string(),
                    envelope: "envelope".to_string(),
                    size: 9,
                    recent: true,
                },
            )
            .expect("append");
        assert_eq!(initial.uid, 1);

        let copied = store
            .add_existing_message_to_mailbox(
                "user-1",
                archive.internal_id,
                "55555555-5555-5555-5555-555555555555",
            )
            .expect("add to archive");
        assert_eq!(copied.uid, 1);
        assert_eq!(copied.remote_id, "msg-5");
        assert_eq!(copied.flags, vec!["\\Seen".to_string()]);

        let inbox_snapshot = store
            .mailbox_snapshot("user-1", inbox.internal_id)
            .expect("inbox");
        let archive_snapshot = store
            .mailbox_snapshot("user-1", archive.internal_id)
            .expect("archive");
        assert_eq!(inbox_snapshot.message_count, 1);
        assert_eq!(archive_snapshot.message_count, 1);
        assert_eq!(
            archive_snapshot.messages[0].summary.internal_id,
            "55555555-5555-5555-5555-555555555555"
        );
        assert_eq!(archive_snapshot.next_uid, 2);

        store
            .remove_message_from_mailbox(
                "user-1",
                inbox.internal_id,
                "55555555-5555-5555-5555-555555555555",
            )
            .expect("remove from inbox");

        let inbox_snapshot = store
            .mailbox_snapshot("user-1", inbox.internal_id)
            .expect("inbox");
        let archive_snapshot = store
            .mailbox_snapshot("user-1", archive.internal_id)
            .expect("archive");
        assert_eq!(inbox_snapshot.message_count, 0);
        assert_eq!(archive_snapshot.message_count, 1);
        assert_eq!(
            store
                .read_message_blob("user-1", "55555555-5555-5555-5555-555555555555")
                .expect("blob"),
            b"copy-body"
        );
    }

    #[test]
    fn renames_subscribes_and_deletes_mailbox_with_deleted_subscription_tracking() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[9u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-projects".to_string(),
                    name: "Projects".to_string(),
                    uid_validity: 3001,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create mailbox");

        store
            .rename_mailbox("user-1", mailbox.internal_id, "Projects/2026")
            .expect("rename");
        store
            .set_mailbox_subscribed("user-1", mailbox.internal_id, false)
            .expect("unsubscribe");

        let mailboxes = store
            .list_upstream_mailboxes("user-1")
            .expect("list mailboxes");
        assert_eq!(mailboxes[0].name, "Projects/2026");
        assert!(!mailboxes[0].subscribed);

        store
            .delete_mailbox("user-1", mailbox.internal_id)
            .expect("delete mailbox");
        assert!(store
            .list_upstream_mailboxes("user-1")
            .expect("mailboxes after delete")
            .is_empty());
        assert!(
            store
                .list_deleted_subscriptions("user-1")
                .expect("deleted subs")
                .is_empty(),
            "unsubscribed mailbox should not be recorded as deleted subscription"
        );

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "mbox-archive".to_string(),
                    name: "Archive".to_string(),
                    uid_validity: 3002,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create mailbox again");
        store
            .delete_mailbox("user-1", mailbox.internal_id)
            .expect("delete subscribed mailbox");

        assert_eq!(
            store
                .list_deleted_subscriptions("user-1")
                .expect("deleted subs"),
            vec![DeletedSubscription {
                name: "Archive".to_string(),
                remote_id: "mbox-archive".to_string(),
            }]
        );
    }

    #[test]
    fn finds_message_by_remote_id_and_updates_message_content() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[9u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "0".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 4001,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create mailbox");

        store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "77777777-7777-7777-7777-777777777777".to_string(),
                    remote_id: "msg-remote".to_string(),
                    flags: vec![],
                    blob: b"Subject: old\r\n\r\nold-body".to_vec(),
                    body: "old-body".to_string(),
                    body_structure: "old-structure".to_string(),
                    envelope: "old-envelope".to_string(),
                    size: 21,
                    recent: false,
                },
            )
            .expect("append");

        assert_eq!(
            store
                .find_message_internal_id_by_remote_id("user-1", "msg-remote")
                .expect("find"),
            Some("77777777-7777-7777-7777-777777777777".to_string())
        );

        let updated = NewMessage {
            internal_id: "77777777-7777-7777-7777-777777777777".to_string(),
            remote_id: "msg-remote".to_string(),
            flags: vec![],
            blob: b"Subject: new\r\n\r\nnew-body".to_vec(),
            body: "new-body".to_string(),
            body_structure: "new-structure".to_string(),
            envelope: "new-envelope".to_string(),
            size: 24,
            recent: false,
        };
        store
            .update_message_content("user-1", &updated.internal_id, &updated)
            .expect("update");

        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(snapshot.messages[0].body, "new-body");
        assert_eq!(snapshot.messages[0].body_structure, "new-structure");
        assert_eq!(snapshot.messages[0].envelope, "new-envelope");
        assert_eq!(
            store
                .read_message_blob("user-1", &updated.internal_id)
                .expect("blob"),
            b"Subject: new\r\n\r\nnew-body"
        );
    }

    #[test]
    fn batch_find_uids_returns_uid_map_for_known_remote_ids() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[10u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "0".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 5001,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create mailbox");

        store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "aaa-1".to_string(),
                    remote_id: "remote-1".to_string(),
                    flags: vec!["\\Seen".to_string()],
                    blob: b"body-1".to_vec(),
                    body: String::new(),
                    body_structure: String::new(),
                    envelope: String::new(),
                    size: 6,
                    recent: false,
                },
            )
            .expect("append 1");
        store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "aaa-2".to_string(),
                    remote_id: "remote-2".to_string(),
                    flags: vec![],
                    blob: b"body-2".to_vec(),
                    body: String::new(),
                    body_structure: String::new(),
                    envelope: String::new(),
                    size: 6,
                    recent: false,
                },
            )
            .expect("append 2");

        let conn = store.open_connection("user-1").expect("open conn");
        let result = store
            .batch_find_uids_by_remote_id(
                &conn,
                mailbox.internal_id,
                &["remote-1", "remote-2", "remote-missing"],
            )
            .expect("batch find");

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("remote-1"), Some(&1));
        assert_eq!(result.get("remote-2"), Some(&2));
        assert!(result.get("remote-missing").is_none());
    }

    #[test]
    fn batch_append_and_set_flags_in_single_transaction() {
        let temp = tempdir().expect("tempdir");
        let store = CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(temp.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[11u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");

        let mailbox = store
            .create_mailbox(
                "user-1",
                &NewMailbox {
                    remote_id: "0".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 6001,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![],
                },
            )
            .expect("create mailbox");

        let conn = store.open_connection_rw("user-1").expect("open conn rw");
        let messages = vec![
            NewMessage {
                internal_id: "batch-1".to_string(),
                remote_id: "r-1".to_string(),
                flags: vec!["\\Seen".to_string()],
                blob: b"body-1".to_vec(),
                body: String::new(),
                body_structure: String::new(),
                envelope: String::new(),
                size: 6,
                recent: false,
            },
            NewMessage {
                internal_id: "batch-2".to_string(),
                remote_id: "r-2".to_string(),
                flags: vec![],
                blob: b"body-2".to_vec(),
                body: String::new(),
                body_structure: String::new(),
                envelope: String::new(),
                size: 6,
                recent: false,
            },
        ];

        let summaries = store
            .batch_append_messages("user-1", &conn, mailbox.internal_id, &messages)
            .expect("batch append");
        assert_eq!(summaries.len(), 2);

        store
            .batch_set_message_flags_on_conn(
                &conn,
                &[
                    ("batch-1", &["\\Flagged".to_string()]),
                    ("batch-2", &["\\Seen".to_string(), "\\Answered".to_string()]),
                ],
            )
            .expect("batch set flags");
        drop(conn);

        let snapshot = store
            .mailbox_snapshot("user-1", mailbox.internal_id)
            .expect("snapshot");
        assert_eq!(snapshot.message_count, 2);
        assert_eq!(
            snapshot.messages[0].summary.flags,
            vec!["\\Flagged".to_string()]
        );
        assert_eq!(
            snapshot.messages[1].summary.flags,
            vec!["\\Answered".to_string(), "\\Seen".to_string()]
        );
    }
}
