//! Schema migration support for the gluon store database.

use rusqlite::Connection;

use crate::error::Result;

/// Current schema version.
pub const CURRENT_VERSION: u32 = 1;

/// Run any pending migrations on the database.
pub fn migrate(conn: &Connection) -> Result<()> {
    ensure_version_table(conn)?;
    let version = get_version(conn)?;
    if version < 1 {
        migrate_v0_to_v1(conn)?;
    }
    // Future: if version < 2 { migrate_v1_to_v2(conn)?; }
    Ok(())
}

fn ensure_version_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS gluon_version (
             id INTEGER PRIMARY KEY,
             version INTEGER NOT NULL DEFAULT 0
         )",
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO gluon_version(id, version) VALUES(0, 0)",
        [],
    )?;
    Ok(())
}

fn get_version(conn: &Connection) -> Result<u32> {
    let result = conn.query_row(
        "SELECT version FROM gluon_version WHERE id = 0",
        [],
        |row| row.get::<_, u32>(0),
    );
    match result {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

fn set_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute(
        "UPDATE gluon_version SET version = ?1 WHERE id = 0",
        [version],
    )?;
    Ok(())
}

/// v0 -> v1: Add message_date column to messages_v2 (if missing).
fn migrate_v0_to_v1(conn: &Connection) -> Result<()> {
    let has_column = conn
        .prepare("SELECT message_date FROM messages_v2 LIMIT 0")
        .is_ok();
    if !has_column {
        // The table may not exist yet during first-run initialization;
        // ALTER TABLE is only safe when the table already exists.
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='messages_v2'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if table_exists {
            conn.execute_batch("ALTER TABLE messages_v2 ADD COLUMN message_date TEXT")?;
        }
    }
    set_version(conn, 1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Minimal messages_v2 table for migration testing.
        conn.execute_batch(
            "CREATE TABLE messages_v2 (
                 id TEXT PRIMARY KEY,
                 remote_id TEXT,
                 date TEXT,
                 size INTEGER,
                 body TEXT,
                 body_structure TEXT,
                 envelope TEXT,
                 deleted BOOLEAN
             )",
        )
        .unwrap();
        conn
    }

    #[test]
    fn migrate_from_scratch_adds_column() {
        let conn = memory_db();
        migrate(&conn).unwrap();

        // Verify version.
        let version = get_version(&conn).unwrap();
        assert_eq!(version, CURRENT_VERSION);

        // Verify column exists (no error on select).
        conn.execute_batch("SELECT message_date FROM messages_v2 LIMIT 0")
            .unwrap();
    }

    #[test]
    fn migrate_is_idempotent() {
        let conn = memory_db();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        let version = get_version(&conn).unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn migrate_no_table_still_sets_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let version = get_version(&conn).unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }
}
