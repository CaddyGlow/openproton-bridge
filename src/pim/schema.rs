use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use super::Result;

pub const PIM_SCHEMA_COMPONENT: &str = "pim_cache";
pub const PIM_SCHEMA_VERSION: u32 = 1;

struct Migration {
    version: u32,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: r#"
CREATE TABLE IF NOT EXISTS openproton_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    applied_at_ms INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);

CREATE TABLE IF NOT EXISTS pim_contacts (
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
CREATE INDEX IF NOT EXISTS idx_pim_contacts_modify_time
    ON pim_contacts(modify_time DESC);

CREATE TABLE IF NOT EXISTS pim_contact_cards (
    contact_id TEXT NOT NULL,
    card_index INTEGER NOT NULL,
    card_type INTEGER NOT NULL,
    data TEXT NOT NULL,
    signature TEXT,
    PRIMARY KEY (contact_id, card_index),
    FOREIGN KEY (contact_id) REFERENCES pim_contacts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pim_contact_emails (
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
    FOREIGN KEY (contact_id) REFERENCES pim_contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pim_contact_emails_email
    ON pim_contact_emails(email);
CREATE INDEX IF NOT EXISTS idx_pim_contact_emails_contact
    ON pim_contact_emails(contact_id);

CREATE TABLE IF NOT EXISTS pim_calendars (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '',
    display INTEGER NOT NULL DEFAULT 0,
    calendar_type INTEGER NOT NULL DEFAULT 0,
    flags INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pim_calendar_members (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '',
    display INTEGER NOT NULL DEFAULT 0,
    permissions INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_members_calendar
    ON pim_calendar_members(calendar_id);

CREATE TABLE IF NOT EXISTS pim_calendar_keys (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    passphrase_id TEXT NOT NULL DEFAULT '',
    private_key TEXT NOT NULL DEFAULT '',
    flags INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_keys_calendar
    ON pim_calendar_keys(calendar_id);

CREATE TABLE IF NOT EXISTS pim_calendar_settings (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    default_event_duration INTEGER NOT NULL DEFAULT 0,
    default_part_day_notifications_json TEXT NOT NULL DEFAULT '[]',
    default_full_day_notifications_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_settings_calendar
    ON pim_calendar_settings(calendar_id);

CREATE TABLE IF NOT EXISTS pim_calendar_events (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    uid TEXT NOT NULL DEFAULT '',
    shared_event_id TEXT NOT NULL DEFAULT '',
    create_time INTEGER NOT NULL DEFAULT 0,
    last_edit_time INTEGER NOT NULL DEFAULT 0,
    start_time INTEGER NOT NULL DEFAULT 0,
    end_time INTEGER NOT NULL DEFAULT 0,
    start_timezone TEXT NOT NULL DEFAULT '',
    end_timezone TEXT NOT NULL DEFAULT '',
    full_day INTEGER NOT NULL DEFAULT 0,
    author TEXT NOT NULL DEFAULT '',
    permissions INTEGER NOT NULL DEFAULT 0,
    attendees_json TEXT NOT NULL DEFAULT '[]',
    shared_key_packet TEXT NOT NULL DEFAULT '',
    calendar_key_packet TEXT NOT NULL DEFAULT '',
    shared_events_json TEXT NOT NULL DEFAULT '[]',
    calendar_events_json TEXT NOT NULL DEFAULT '[]',
    attendees_events_json TEXT NOT NULL DEFAULT '[]',
    personal_events_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_events_calendar_time
    ON pim_calendar_events(calendar_id, start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_events_uid
    ON pim_calendar_events(uid);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_events_edit_time
    ON pim_calendar_events(last_edit_time DESC);

CREATE TABLE IF NOT EXISTS pim_sync_state (
    scope TEXT PRIMARY KEY,
    value_text TEXT NOT NULL DEFAULT '',
    value_int INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
"#,
}];

pub fn migrate(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS openproton_schema_migrations (
            component TEXT NOT NULL,
            version INTEGER NOT NULL,
            applied_at_ms INTEGER NOT NULL,
            PRIMARY KEY (component, version)
        );",
    )?;

    let applied = {
        let mut stmt =
            conn.prepare("SELECT version FROM openproton_schema_migrations WHERE component = ?1")?;
        let rows = stmt.query_map([PIM_SCHEMA_COMPONENT], |row| row.get::<_, u32>(0))?;
        let versions = rows.collect::<std::result::Result<HashSet<u32>, _>>()?;
        versions
    };

    for migration in MIGRATIONS {
        if applied.contains(&migration.version) {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO openproton_schema_migrations (component, version, applied_at_ms)
             VALUES (?1, ?2, ?3)",
            params![
                PIM_SCHEMA_COMPONENT,
                migration.version,
                epoch_millis() as i64
            ],
        )?;
        tx.commit()?;
    }

    Ok(())
}

pub fn current_version(conn: &Connection) -> Result<u32> {
    let version = conn
        .query_row(
            "SELECT MAX(version) FROM openproton_schema_migrations WHERE component = ?1",
            [PIM_SCHEMA_COMPONENT],
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
        assert_eq!(version, PIM_SCHEMA_VERSION);

        let applied_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM openproton_schema_migrations WHERE component = ?1",
                [PIM_SCHEMA_COMPONENT],
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

        let expected_tables = [
            "pim_contacts",
            "pim_contact_cards",
            "pim_contact_emails",
            "pim_calendars",
            "pim_calendar_events",
            "pim_sync_state",
        ];

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
