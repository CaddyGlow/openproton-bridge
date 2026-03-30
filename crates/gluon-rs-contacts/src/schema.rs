use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use crate::error::Result;

pub const SCHEMA_COMPONENT: &str = "contacts_cache";
#[cfg(test)]
pub const SCHEMA_VERSION: u32 = 1;

struct Migration {
    version: u32,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    applied_at_ms INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);

CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    create_time INTEGER NOT NULL DEFAULT 0,
    modify_time INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contacts_modify_time
    ON contacts(modify_time DESC);

CREATE TABLE IF NOT EXISTS contact_cards (
    contact_id TEXT NOT NULL,
    card_index INTEGER NOT NULL,
    card_type INTEGER NOT NULL,
    data TEXT NOT NULL,
    signature TEXT,
    PRIMARY KEY (contact_id, card_index),
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contact_emails (
    id TEXT PRIMARY KEY,
    contact_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    kind_json TEXT NOT NULL DEFAULT '[]',
    defaults_value INTEGER,
    order_value INTEGER,
    label_ids_json TEXT NOT NULL DEFAULT '[]',
    last_used_time INTEGER,
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_contact_emails_email
    ON contact_emails(email);
CREATE INDEX IF NOT EXISTS idx_contact_emails_contact
    ON contact_emails(contact_id);

CREATE TABLE IF NOT EXISTS sync_state (
    scope TEXT PRIMARY KEY,
    value_text TEXT NOT NULL DEFAULT '',
    value_int INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
"#,
}];

pub fn migrate(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            component TEXT NOT NULL,
            version INTEGER NOT NULL,
            applied_at_ms INTEGER NOT NULL,
            PRIMARY KEY (component, version)
        );",
    )?;

    let applied = {
        let mut stmt =
            conn.prepare("SELECT version FROM schema_migrations WHERE component = ?1")?;
        let rows = stmt.query_map([SCHEMA_COMPONENT], |row| row.get::<_, u32>(0))?;
        rows.collect::<std::result::Result<HashSet<u32>, _>>()?
    };

    for migration in MIGRATIONS {
        if applied.contains(&migration.version) {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (component, version, applied_at_ms)
             VALUES (?1, ?2, ?3)",
            params![SCHEMA_COMPONENT, migration.version, epoch_millis() as i64],
        )?;
        tx.commit()?;
    }

    Ok(())
}

#[cfg(test)]
pub fn current_version(conn: &Connection) -> Result<u32> {
    use rusqlite::OptionalExtension;
    let version = conn
        .query_row(
            "SELECT MAX(version) FROM schema_migrations WHERE component = ?1",
            [SCHEMA_COMPONENT],
            |row| row.get::<_, Option<u32>>(0),
        )
        .optional()?
        .flatten()
        .unwrap_or(0);
    Ok(version)
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_is_idempotent_and_tracks_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();

        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();

        let version = current_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        let applied_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE component = ?1",
                [SCHEMA_COMPONENT],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(applied_count, 1);
    }

    #[test]
    fn migrate_creates_core_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut conn).unwrap();

        let expected_tables = ["contacts", "contact_cards", "contact_emails", "sync_state"];

        for table in expected_tables {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "missing table: {table}");
        }
    }
}
