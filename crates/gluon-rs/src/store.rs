use std::collections::HashMap;

use rusqlite::{Connection, OpenFlags};

use crate::{
    db::SchemaProbe,
    error::{GluonError, Result},
    layout::AccountPaths,
    types::{AccountBootstrap, StoreBootstrap},
};

#[derive(Debug, Clone)]
pub struct CompatibleStore {
    bootstrap: StoreBootstrap,
    accounts_by_storage_user_id: HashMap<String, AccountBootstrap>,
}

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
pub struct DeletedSubscription {
    pub name: String,
    pub remote_id: String,
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
        } else if !bootstrap.layout.root().exists() {
            return Err(GluonError::MissingCacheRoot {
                path: bootstrap.layout.root().to_path_buf(),
            });
        }

        let mut accounts_by_storage_user_id = HashMap::new();
        for account in &bootstrap.accounts {
            let account_paths = bootstrap
                .layout
                .account_paths(account.storage_user_id.clone())?;
            if create_dirs {
                std::fs::create_dir_all(account_paths.store_dir())?;
            }

            accounts_by_storage_user_id
                .insert(account.storage_user_id.clone(), account.clone());
        }

        Ok(Self {
            bootstrap,
            accounts_by_storage_user_id,
        })
    }

    pub fn bootstrap(&self) -> &StoreBootstrap {
        &self.bootstrap
    }

    pub fn account(&self, storage_user_id: &str) -> Result<&AccountBootstrap> {
        self.accounts_by_storage_user_id
            .get(storage_user_id)
            .ok_or_else(|| GluonError::UnknownStorageUserId {
                storage_user_id: storage_user_id.to_string(),
            })
    }

    pub fn account_paths(&self, storage_user_id: &str) -> Result<AccountPaths> {
        self.account(storage_user_id)?;
        self.bootstrap.layout.account_paths(storage_user_id)
    }

    pub fn schema_probe(&self, storage_user_id: &str) -> Result<SchemaProbe> {
        let account_paths = self.account_paths(storage_user_id)?;
        SchemaProbe::inspect(&account_paths.primary_db_path())
    }

    pub fn initialize_upstream_schema(&self, storage_user_id: &str) -> Result<()> {
        let account_paths = self.account_paths(storage_user_id)?;
        let conn = Connection::open(account_paths.primary_db_path())?;
        conn.execute_batch(UPSTREAM_BASE_SCHEMA)?;
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
        let account_paths = self.account_paths(storage_user_id)?;
        let conn = Connection::open(account_paths.primary_db_path())?;
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO mailboxes_v2(remote_id, name, uid_validity, subscribed)
             VALUES(?1, ?2, ?3, ?4)",
            (
                &mailbox.remote_id,
                &mailbox.name,
                mailbox.uid_validity,
                mailbox.subscribed,
            ),
        )?;
        let internal_id = tx.last_insert_rowid() as u64;
        tx.execute_batch(&create_mailbox_message_table_sql(internal_id))?;

        insert_mailbox_flags(&tx, "mailbox_flags_v2", internal_id, &mailbox.flags)?;
        insert_mailbox_flags(
            &tx,
            "mailbox_perm_flags_v2",
            internal_id,
            &mailbox.permanent_flags,
        )?;
        insert_mailbox_flags(&tx, "mailbox_attrs_v2", internal_id, &mailbox.attributes)?;
        tx.commit()?;

        let conn = self.open_upstream_db_rw(storage_user_id)?;
        self.get_upstream_mailbox(&conn, internal_id)
    }

    pub fn append_message(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        message: &NewMessage,
    ) -> Result<UpstreamMessageSummary> {
        self.initialize_upstream_schema(storage_user_id)?;
        let account_paths = self.account_paths(storage_user_id)?;
        std::fs::create_dir_all(account_paths.store_dir())?;

        let blob_path = account_paths.blob_path(&message.internal_id)?;
        std::fs::write(&blob_path, &message.blob)?;

        let conn = Connection::open(account_paths.primary_db_path())?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO messages_v2(id, remote_id, date, size, body, body_structure, envelope, deleted)
             VALUES(?1, ?2, datetime('now'), ?3, ?4, ?5, ?6, FALSE)",
            (
                &message.internal_id,
                &message.remote_id,
                message.size,
                &message.body,
                &message.body_structure,
                &message.envelope,
            ),
        )?;
        tx.execute(
            "INSERT INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, ?2)",
            (&message.internal_id, mailbox_internal_id),
        )?;
        tx.execute(
            &format!(
                "INSERT INTO mailbox_message_{mailbox_internal_id}(message_id, message_remote_id, recent, deleted)
                 VALUES(?1, ?2, ?3, FALSE)"
            ),
            (&message.internal_id, &message.remote_id, message.recent),
        )?;
        insert_message_flags(&tx, &message.internal_id, &message.flags)?;
        tx.commit()?;

        let mut listed = self.list_upstream_mailbox_messages(storage_user_id, mailbox_internal_id)?;
        listed
            .pop()
            .ok_or_else(|| GluonError::MissingRequiredTable {
                table: format!("mailbox_message_{mailbox_internal_id}"),
            })
    }

    pub fn add_message_flags(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        flags: &[String],
    ) -> Result<()> {
        let conn = self.open_upstream_db_rw(storage_user_id)?;
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
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        let tx = conn.unchecked_transaction()?;
        for flag in flags {
            tx.execute(
                "DELETE FROM message_flags_v2 WHERE message_id = ?1 AND value = ?2",
                (internal_message_id, flag),
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
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "DELETE FROM message_flags_v2 WHERE message_id = ?1",
            (internal_message_id,),
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
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        conn.execute(
            &format!(
                "UPDATE mailbox_message_{mailbox_internal_id}
                 SET deleted = ?1
                 WHERE message_id = ?2"
            ),
            (deleted, internal_message_id),
        )?;
        Ok(())
    }

    pub fn set_message_deleted(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
        deleted: bool,
    ) -> Result<()> {
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        conn.execute(
            "UPDATE messages_v2
             SET deleted = ?1
             WHERE id = ?2",
            (deleted, internal_message_id),
        )?;
        Ok(())
    }

    pub fn add_existing_message_to_mailbox(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        internal_message_id: &str,
    ) -> Result<UpstreamMessageSummary> {
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        let tx = conn.unchecked_transaction()?;
        let remote_id = tx.query_row(
            "SELECT remote_id FROM messages_v2 WHERE id = ?1",
            (internal_message_id,),
            |row| row.get::<_, String>(0),
        )?;

        tx.execute(
            "INSERT OR IGNORE INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, ?2)",
            (internal_message_id, mailbox_internal_id),
        )?;
        tx.execute(
            &format!(
                "INSERT INTO mailbox_message_{mailbox_internal_id}(message_id, message_remote_id)
                 VALUES(?1, ?2)"
            ),
            (internal_message_id, &remote_id),
        )?;
        tx.commit()?;

        let messages = self.list_upstream_mailbox_messages(storage_user_id, mailbox_internal_id)?;
        messages
            .into_iter()
            .find(|message| message.internal_id == internal_message_id)
            .ok_or_else(|| GluonError::MissingRequiredTable {
                table: format!("mailbox_message_{mailbox_internal_id}"),
            })
    }

    pub fn remove_message_from_mailbox(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        internal_message_id: &str,
    ) -> Result<()> {
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            &format!(
                "DELETE FROM mailbox_message_{mailbox_internal_id}
                 WHERE message_id = ?1"
            ),
            (internal_message_id,),
        )?;
        tx.execute(
            "DELETE FROM message_to_mailbox
             WHERE message_id = ?1 AND mailbox_id = ?2",
            (internal_message_id, mailbox_internal_id),
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
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        conn.execute(
            "UPDATE mailboxes_v2
             SET name = ?1
             WHERE id = ?2",
            (new_name, mailbox_internal_id),
        )?;
        Ok(())
    }

    pub fn set_mailbox_subscribed(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
        subscribed: bool,
    ) -> Result<()> {
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        conn.execute(
            "UPDATE mailboxes_v2
             SET subscribed = ?1
             WHERE id = ?2",
            (subscribed, mailbox_internal_id),
        )?;
        Ok(())
    }

    pub fn delete_mailbox(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
    ) -> Result<()> {
        let conn = self.open_upstream_db_rw(storage_user_id)?;
        let tx = conn.unchecked_transaction()?;

        let (remote_id, name, subscribed) = tx.query_row(
            "SELECT remote_id, name, subscribed
             FROM mailboxes_v2
             WHERE id = ?1",
            (mailbox_internal_id,),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )?;

        if subscribed {
            tx.execute(
                "UPDATE deleted_subscriptions
                 SET remote_id = ?1
                 WHERE name = ?2",
                (&remote_id, &name),
            )?;
            tx.execute(
                "INSERT INTO deleted_subscriptions(name, remote_id)
                 SELECT ?1, ?2
                 WHERE NOT EXISTS (
                     SELECT 1 FROM deleted_subscriptions WHERE name = ?1
                 )",
                (&name, &remote_id),
            )?;
        }

        tx.execute(
            "DELETE FROM message_to_mailbox
             WHERE mailbox_id = ?1",
            (mailbox_internal_id,),
        )?;
        tx.execute(
            "DELETE FROM mailbox_flags_v2
             WHERE mailbox_id = ?1",
            (mailbox_internal_id,),
        )?;
        tx.execute(
            "DELETE FROM mailbox_perm_flags_v2
             WHERE mailbox_id = ?1",
            (mailbox_internal_id,),
        )?;
        tx.execute(
            "DELETE FROM mailbox_attrs_v2
             WHERE mailbox_id = ?1",
            (mailbox_internal_id,),
        )?;
        tx.execute(
            "DELETE FROM mailboxes_v2
             WHERE id = ?1",
            (mailbox_internal_id,),
        )?;
        tx.execute_batch(&format!("DROP TABLE mailbox_message_{mailbox_internal_id}"))?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_deleted_subscriptions(
        &self,
        storage_user_id: &str,
    ) -> Result<Vec<DeletedSubscription>> {
        let conn = self.open_upstream_db(storage_user_id)?;
        let mut stmt = conn.prepare(
            "SELECT name, remote_id
             FROM deleted_subscriptions
             ORDER BY name",
        )?;
        let mut rows = stmt.query([])?;
        let mut deleted = Vec::new();

        while let Some(row) = rows.next()? {
            deleted.push(DeletedSubscription {
                name: row.get::<_, String>(0)?,
                remote_id: row.get::<_, String>(1)?,
            });
        }

        Ok(deleted)
    }

    pub fn list_upstream_mailboxes(&self, storage_user_id: &str) -> Result<Vec<UpstreamMailbox>> {
        let conn = self.open_upstream_db(storage_user_id)?;
        let mut stmt = conn.prepare(
            "SELECT id, remote_id, name, uid_validity, subscribed
             FROM mailboxes_v2
             ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        let mut mailboxes = Vec::new();

        while let Some(row) = rows.next()? {
            let internal_id = row.get::<_, u64>(0)?;
            let remote_id = row.get::<_, String>(1)?;
            let name = row.get::<_, String>(2)?;
            let uid_validity = row.get::<_, u32>(3)?;
            let subscribed = row.get::<_, bool>(4)?;

            mailboxes.push(UpstreamMailbox {
                internal_id,
                remote_id,
                name,
                uid_validity,
                subscribed,
                attributes: query_string_vec(
                    &conn,
                    "SELECT value FROM mailbox_attrs_v2 WHERE mailbox_id = ? ORDER BY value",
                    (internal_id,),
                )?,
                flags: query_string_vec(
                    &conn,
                    "SELECT value FROM mailbox_flags_v2 WHERE mailbox_id = ? ORDER BY value",
                    (internal_id,),
                )?,
                permanent_flags: query_string_vec(
                    &conn,
                    "SELECT value FROM mailbox_perm_flags_v2 WHERE mailbox_id = ? ORDER BY value",
                    (internal_id,),
                )?,
            });
        }

        Ok(mailboxes)
    }

    pub fn list_upstream_mailbox_messages(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
    ) -> Result<Vec<UpstreamMessageSummary>> {
        let conn = self.open_upstream_db(storage_user_id)?;
        let table_name = format!("mailbox_message_{mailbox_internal_id}");
        let mut stmt = conn.prepare(&format!(
            "SELECT mm.message_id, mm.message_remote_id, mm.uid, mm.recent, mm.deleted, m.size, m.deleted
             FROM {table_name} AS mm
             JOIN messages_v2 AS m ON m.id = mm.message_id
             ORDER BY mm.uid"
        ))?;
        let mut rows = stmt.query([])?;
        let mut messages = Vec::new();

        while let Some(row) = rows.next()? {
            let internal_id = row.get::<_, String>(0)?;
            messages.push(UpstreamMessageSummary {
                internal_id: internal_id.clone(),
                remote_id: row.get::<_, String>(1)?,
                uid: row.get::<_, u32>(2)?,
                recent: row.get::<_, bool>(3)?,
                mailbox_deleted: row.get::<_, bool>(4)?,
                size: row.get::<_, i64>(5)?,
                message_deleted: row.get::<_, bool>(6)?,
                flags: query_string_vec(
                    &conn,
                    "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
                    (&internal_id,),
                )?,
            });
        }

        Ok(messages)
    }

    pub fn read_message_blob(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
    ) -> Result<Vec<u8>> {
        let account_paths = self.account_paths(storage_user_id)?;
        Ok(std::fs::read(account_paths.blob_path(internal_message_id)?)?)
    }

    pub fn mailbox_snapshot(
        &self,
        storage_user_id: &str,
        mailbox_internal_id: u64,
    ) -> Result<UpstreamMailboxSnapshot> {
        let account_paths = self.account_paths(storage_user_id)?;
        let conn = self.open_upstream_db(storage_user_id)?;
        let mailbox = self.get_upstream_mailbox(&conn, mailbox_internal_id)?;
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
        let mut rows = stmt.query([])?;
        let mut messages = Vec::new();

        while let Some(row) = rows.next()? {
            let internal_id = row.get::<_, String>(0)?;
            let summary = UpstreamMessageSummary {
                internal_id: internal_id.clone(),
                remote_id: row.get::<_, String>(1)?,
                uid: row.get::<_, u32>(2)?,
                recent: row.get::<_, bool>(3)?,
                mailbox_deleted: row.get::<_, bool>(4)?,
                size: row.get::<_, i64>(5)?,
                message_deleted: row.get::<_, bool>(6)?,
                flags: query_string_vec(
                    &conn,
                    "SELECT value FROM message_flags_v2 WHERE message_id = ? ORDER BY value",
                    (&internal_id,),
                )?,
            };
            let blob_path = account_paths.blob_path(&internal_id)?;

            messages.push(UpstreamMailboxMessage {
                summary,
                body: row.get::<_, String>(7)?,
                body_structure: row.get::<_, String>(8)?,
                envelope: row.get::<_, String>(9)?,
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

    fn open_upstream_db(&self, storage_user_id: &str) -> Result<Connection> {
        let account_paths = self.account_paths(storage_user_id)?;
        let probe = SchemaProbe::inspect(&account_paths.primary_db_path())?;
        if !probe.is_upstream_compatible() {
            return Err(GluonError::IncompatibleSchema {
                family: format!("{:?}", probe.family),
            });
        }

        Ok(Connection::open_with_flags(
            account_paths.primary_db_path(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?)
    }

    fn open_upstream_db_rw(&self, storage_user_id: &str) -> Result<Connection> {
        let account_paths = self.account_paths(storage_user_id)?;
        let probe = SchemaProbe::inspect(&account_paths.primary_db_path())?;
        if !matches!(
            probe.family,
            crate::SchemaFamily::UpstreamCore | crate::SchemaFamily::Missing | crate::SchemaFamily::Empty
        ) {
            return Err(GluonError::IncompatibleSchema {
                family: format!("{:?}", probe.family),
            });
        }

        Ok(Connection::open(account_paths.primary_db_path())?)
    }

    fn get_upstream_mailbox(&self, conn: &Connection, mailbox_internal_id: u64) -> Result<UpstreamMailbox> {
        let (internal_id, remote_id, name, uid_validity, subscribed) = conn.query_row(
            "SELECT id, remote_id, name, uid_validity, subscribed
             FROM mailboxes_v2
             WHERE id = ?",
            (mailbox_internal_id,),
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )?;

        Ok(UpstreamMailbox {
            internal_id,
            remote_id,
            name,
            uid_validity,
            subscribed,
            attributes: query_string_vec(
                conn,
                "SELECT value FROM mailbox_attrs_v2 WHERE mailbox_id = ? ORDER BY value",
                (internal_id,),
            )?,
            flags: query_string_vec(
                conn,
                "SELECT value FROM mailbox_flags_v2 WHERE mailbox_id = ? ORDER BY value",
                (internal_id,),
            )?,
            permanent_flags: query_string_vec(
                conn,
                "SELECT value FROM mailbox_perm_flags_v2 WHERE mailbox_id = ? ORDER BY value",
                (internal_id,),
            )?,
        })
    }
}

fn query_string_vec<P>(conn: &Connection, sql: &str, param: P) -> Result<Vec<String>>
where
    P: rusqlite::Params,
{
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(param)?;
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        values.push(row.get::<_, String>(0)?);
    }
    Ok(values)
}

fn query_count(conn: &Connection, sql: &str) -> Result<u32> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, u32>(0))?)
}

fn next_uid_for_mailbox(conn: &Connection, table_name: &str) -> Result<u32> {
    let uid = conn.query_row(
        "SELECT seq FROM sqlite_sequence WHERE name = ?",
        (table_name,),
        |row| row.get::<_, u32>(0),
    );
    match uid {
        Ok(seq) => Ok(seq.saturating_add(1)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(1),
        Err(err) => Err(err.into()),
    }
}

fn insert_mailbox_flags(
    tx: &rusqlite::Transaction<'_>,
    table_name: &str,
    mailbox_id: u64,
    values: &[String],
) -> Result<()> {
    let sql = format!("INSERT INTO {table_name}(mailbox_id, value) VALUES(?1, ?2)");
    for value in values {
        tx.execute(&sql, (mailbox_id, value))?;
    }
    Ok(())
}

fn insert_message_flags(
    tx: &rusqlite::Transaction<'_>,
    message_id: &str,
    values: &[String],
) -> Result<()> {
    for value in values {
        tx.execute(
            "INSERT INTO message_flags_v2(message_id, value) VALUES(?1, ?2)",
            (message_id, value),
        )?;
    }
    Ok(())
}

fn insert_message_flags_ignore_duplicates(
    tx: &rusqlite::Transaction<'_>,
    message_id: &str,
    values: &[String],
) -> Result<()> {
    for value in values {
        tx.execute(
            "INSERT OR IGNORE INTO message_flags_v2(message_id, value) VALUES(?1, ?2)",
            (message_id, value),
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

const UPSTREAM_BASE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS deleted_subscriptions(
        name TEXT NOT NULL,
        remote_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mailboxes_v2(
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        remote_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        uid_validity INTEGER NOT NULL,
        subscribed BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS mailbox_flags_v2(
        value TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(value, mailbox_id)
    );
    CREATE TABLE IF NOT EXISTS mailbox_attrs_v2(
        value TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(value, mailbox_id)
    );
    CREATE TABLE IF NOT EXISTS mailbox_perm_flags_v2(
        value TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(value, mailbox_id)
    );
    CREATE TABLE IF NOT EXISTS messages_v2(
        id TEXT NOT NULL PRIMARY KEY,
        remote_id TEXT NOT NULL UNIQUE,
        date TEXT,
        size INTEGER NOT NULL,
        body TEXT NOT NULL,
        body_structure TEXT NOT NULL,
        envelope TEXT NOT NULL,
        deleted BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS message_flags_v2(
        value TEXT NOT NULL,
        message_id TEXT NOT NULL,
        PRIMARY KEY(value, message_id)
    );
    CREATE INDEX IF NOT EXISTS message_flags_message_id_index ON message_flags_v2(message_id);
    CREATE TABLE IF NOT EXISTS message_to_mailbox(
        message_id TEXT NOT NULL,
        mailbox_id INTEGER NOT NULL,
        PRIMARY KEY(message_id, mailbox_id)
    );
    CREATE TABLE IF NOT EXISTS connector_settings(
        id INTEGER NOT NULL PRIMARY KEY,
        value TEXT
    );
    CREATE TABLE IF NOT EXISTS gluon_version(
        id INTEGER NOT NULL PRIMARY KEY CHECK(id = 0),
        version INTEGER NOT NULL
    );
";

#[cfg(test)]
mod tests {
    use std::fs;

    use rusqlite::{params, Connection};
    use tempfile::tempdir;

    use crate::{
        key::GluonKey,
        layout::CacheLayout,
        target::CompatibilityTarget,
        types::{AccountBootstrap, StoreBootstrap},
    };

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
            store
                .schema_probe("user-1")
                .expect("schema probe")
                .family,
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
            b"blob payload",
        )
        .expect("blob");

        let conn = Connection::open(account_paths.primary_db_path()).expect("open db");
        conn.execute_batch(
            "
            CREATE TABLE deleted_subscriptions(name TEXT, remote_id TEXT);
            CREATE TABLE mailboxes_v2(
                id INTEGER PRIMARY KEY,
                remote_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE,
                uid_validity INTEGER NOT NULL,
                subscribed BOOLEAN NOT NULL
            );
            CREATE TABLE mailbox_flags_v2(
                value TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(value, mailbox_id)
            );
            CREATE TABLE mailbox_attrs_v2(
                value TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(value, mailbox_id)
            );
            CREATE TABLE mailbox_perm_flags_v2(
                value TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(value, mailbox_id)
            );
            CREATE TABLE messages_v2(
                id TEXT NOT NULL PRIMARY KEY,
                remote_id TEXT NOT NULL UNIQUE,
                date TEXT,
                size INTEGER NOT NULL,
                body TEXT,
                body_structure TEXT,
                envelope TEXT,
                deleted BOOLEAN NOT NULL DEFAULT false
            );
            CREATE TABLE message_flags_v2(
                value TEXT NOT NULL,
                message_id TEXT NOT NULL,
                PRIMARY KEY(value, message_id)
            );
            CREATE TABLE message_to_mailbox(
                message_id TEXT NOT NULL,
                mailbox_id INTEGER NOT NULL,
                PRIMARY KEY(message_id, mailbox_id)
            );
            CREATE TABLE connector_settings(
                id INTEGER NOT NULL PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE gluon_version(
                id INTEGER NOT NULL PRIMARY KEY,
                version INTEGER NOT NULL
            );
            CREATE TABLE mailbox_message_1(
                uid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                deleted BOOLEAN NOT NULL DEFAULT false,
                recent BOOLEAN NOT NULL DEFAULT true,
                message_id TEXT NOT NULL UNIQUE,
                message_remote_id TEXT NOT NULL UNIQUE
            );
            ",
        )
        .expect("create schema");
        conn.execute(
            "INSERT INTO mailboxes_v2(id, remote_id, name, uid_validity, subscribed) VALUES(1, ?1, ?2, ?3, ?4)",
            params!["mbox-remote-1", "INBOX", 777u32, true],
        )
        .expect("insert mailbox");
        conn.execute(
            "INSERT INTO mailbox_attrs_v2(value, mailbox_id) VALUES(?1, 1)",
            params!["\\HasNoChildren"],
        )
        .expect("insert attr");
        conn.execute(
            "INSERT INTO mailbox_flags_v2(value, mailbox_id) VALUES(?1, 1)",
            params!["\\Draft"],
        )
        .expect("insert mailbox flag");
        conn.execute(
            "INSERT INTO mailbox_perm_flags_v2(value, mailbox_id) VALUES(?1, 1)",
            params!["\\Seen"],
        )
        .expect("insert mailbox perm flag");
        conn.execute(
            "INSERT INTO messages_v2(id, remote_id, date, size, body, body_structure, envelope, deleted)
             VALUES(?1, ?2, '2026-03-11T10:00:00Z', 123, '', '', '', false)",
            params![
                "11111111-1111-1111-1111-111111111111",
                "msg-remote-1"
            ],
        )
        .expect("insert message");
        conn.execute(
            "INSERT INTO message_flags_v2(value, message_id) VALUES(?1, ?2)",
            params!["\\Seen", "11111111-1111-1111-1111-111111111111"],
        )
        .expect("insert message flag");
        conn.execute(
            "INSERT INTO message_to_mailbox(message_id, mailbox_id) VALUES(?1, 1)",
            params!["11111111-1111-1111-1111-111111111111"],
        )
        .expect("insert message map");
        conn.execute(
            "INSERT INTO connector_settings(id, value) VALUES(0, NULL)",
            [],
        )
        .expect("insert connector settings");
        conn.execute(
            "INSERT INTO gluon_version(id, version) VALUES(0, 3)",
            [],
        )
        .expect("insert version");
        conn.execute(
            "INSERT INTO mailbox_message_1(message_id, message_remote_id, recent, deleted) VALUES(?1, ?2, true, false)",
            params![
                "11111111-1111-1111-1111-111111111111",
                "msg-remote-1"
            ],
        )
        .expect("insert mailbox message");
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
        assert_eq!(mailboxes[0].attributes, vec![String::from("\\HasNoChildren")]);
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
        assert_eq!(snapshot.messages[0].summary.flags, vec![String::from("\\Seen")]);
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

        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
        assert_eq!(snapshot.next_uid, 2);
        assert_eq!(snapshot.message_count, 1);
        assert_eq!(snapshot.messages[0].body, "body");
        assert_eq!(
            store
                .read_message_blob("user-1", "22222222-2222-2222-2222-222222222222")
                .expect("blob"),
            b"hello world"
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
        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
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
        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
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
        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
        assert_eq!(snapshot.messages[0].summary.flags, vec!["\\Draft".to_string()]);
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

        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
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
        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
        assert!(snapshot.messages[0].summary.mailbox_deleted);
        assert!(!snapshot.messages[0].summary.message_deleted);

        store
            .set_message_deleted("user-1", "44444444-4444-4444-4444-444444444444", true)
            .expect("mark global deleted");
        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
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
        let snapshot = store.mailbox_snapshot("user-1", mailbox.internal_id).expect("snapshot");
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

        let inbox_snapshot = store.mailbox_snapshot("user-1", inbox.internal_id).expect("inbox");
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

        let inbox_snapshot = store.mailbox_snapshot("user-1", inbox.internal_id).expect("inbox");
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
        assert!(
            store
                .list_upstream_mailboxes("user-1")
                .expect("mailboxes after delete")
                .is_empty()
        );
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
}
