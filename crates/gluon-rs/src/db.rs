use std::{collections::BTreeSet, path::Path};

use rusqlite::Connection;

use crate::error::Result;

const UPSTREAM_CORE_TABLES: &[&str] = &[
    "deleted_subscriptions",
    "mailboxes_v2",
    "mailbox_flags_v2",
    "mailbox_attrs_v2",
    "mailbox_perm_flags_v2",
    "messages_v2",
    "message_flags_v2",
    "message_to_mailbox",
    "connector_settings",
    "gluon_version",
];

const OPENPROTON_CUSTOM_TABLES: &[&str] = &[
    "openproton_account_meta",
    "openproton_mailboxes",
    "openproton_messages",
    "openproton_message_labels",
    "openproton_message_addresses",
    "openproton_message_flags",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaFamily {
    Missing,
    Empty,
    UpstreamCore,
    OpenProtonCustom,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaProbe {
    pub family: SchemaFamily,
    pub tables: BTreeSet<String>,
    pub journal_mode: Option<String>,
}

impl SchemaProbe {
    pub fn inspect(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                family: SchemaFamily::Missing,
                tables: BTreeSet::new(),
                journal_mode: None,
            });
        }

        let conn = Connection::open(path)?;
        let journal_mode = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .ok();

        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let mut rows = stmt.query([])?;
        let mut tables = BTreeSet::new();
        while let Some(row) = rows.next()? {
            tables.insert(row.get::<_, String>(0)?);
        }

        let family = classify_tables(&tables);
        Ok(Self {
            family,
            tables,
            journal_mode,
        })
    }

    pub fn is_upstream_compatible(&self) -> bool {
        matches!(self.family, SchemaFamily::UpstreamCore)
    }

    pub fn mailbox_message_tables(&self) -> Vec<&str> {
        self.tables
            .iter()
            .filter_map(|table| table.strip_prefix("mailbox_message_").map(|_| table.as_str()))
            .collect()
    }
}

fn classify_tables(tables: &BTreeSet<String>) -> SchemaFamily {
    if tables.is_empty() {
        return SchemaFamily::Empty;
    }

    let has_upstream = UPSTREAM_CORE_TABLES
        .iter()
        .all(|table| tables.contains(*table));
    let has_custom = OPENPROTON_CUSTOM_TABLES
        .iter()
        .any(|table| tables.contains(*table));

    match (has_upstream, has_custom) {
        (true, false) => SchemaFamily::UpstreamCore,
        (false, true) => SchemaFamily::OpenProtonCustom,
        (true, true) => SchemaFamily::Mixed,
        (false, false) => SchemaFamily::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::{SchemaFamily, SchemaProbe};

    #[test]
    fn classifies_upstream_schema() {
        let temp = tempdir().expect("tempdir");
        let db_path = temp.path().join("user.db");
        let conn = Connection::open(&db_path).expect("open db");
        conn.execute_batch(
            "
            CREATE TABLE deleted_subscriptions(id INTEGER);
            CREATE TABLE mailboxes_v2(id INTEGER);
            CREATE TABLE mailbox_flags_v2(id INTEGER);
            CREATE TABLE mailbox_attrs_v2(id INTEGER);
            CREATE TABLE mailbox_perm_flags_v2(id INTEGER);
            CREATE TABLE messages_v2(id INTEGER);
            CREATE TABLE message_flags_v2(id INTEGER);
            CREATE TABLE message_to_mailbox(id INTEGER);
            CREATE TABLE connector_settings(id INTEGER);
            CREATE TABLE gluon_version(id INTEGER);
            CREATE TABLE mailbox_message_1(id INTEGER);
            ",
        )
        .expect("create schema");

        let probe = SchemaProbe::inspect(&db_path).expect("inspect");
        assert_eq!(probe.family, SchemaFamily::UpstreamCore);
        assert!(probe.is_upstream_compatible());
        assert_eq!(probe.mailbox_message_tables(), vec!["mailbox_message_1"]);
    }
}
