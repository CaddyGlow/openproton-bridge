use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{CalendarStoreError, Result};
use crate::schema;
use crate::types::*;

pub struct CalendarStore {
    db_path: PathBuf,
}

impl CalendarStore {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = open_connection(&db_path)?;
        schema::migrate(&mut conn)?;

        Ok(Self { db_path })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn upsert_calendar(&self, calendar: &CalendarUpsert) -> Result<()> {
        if calendar.id.trim().is_empty() {
            return Err(CalendarStoreError::InvalidState(
                "cannot upsert calendar with empty ID".to_string(),
            ));
        }

        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO calendars (
                id, name, description, color, display, calendar_type, flags, raw_json, deleted, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                color = excluded.color,
                display = excluded.display,
                calendar_type = excluded.calendar_type,
                flags = excluded.flags,
                raw_json = excluded.raw_json,
                deleted = 0,
                updated_at_ms = excluded.updated_at_ms",
            params![
                calendar.id,
                calendar.name,
                calendar.description,
                calendar.color,
                calendar.display,
                calendar.calendar_type,
                calendar.flags,
                calendar.raw_json,
                epoch_millis() as i64,
            ],
        )?;
        Ok(())
    }

    pub fn soft_delete_calendar(&self, calendar_id: &str) -> Result<()> {
        if calendar_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute(
            "UPDATE calendars SET deleted = 1, updated_at_ms = ?2 WHERE id = ?1",
            params![calendar_id, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn hard_delete_calendar(&self, calendar_id: &str) -> Result<()> {
        if calendar_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute("DELETE FROM calendars WHERE id = ?1", [calendar_id])?;
        Ok(())
    }

    pub fn upsert_calendar_member(&self, member: &CalendarMemberUpsert) -> Result<()> {
        if member.id.trim().is_empty() {
            return Err(CalendarStoreError::InvalidState(
                "cannot upsert calendar member with empty ID".to_string(),
            ));
        }
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO calendar_members (
                id, calendar_id, email, color, display, permissions, raw_json, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                calendar_id = excluded.calendar_id,
                email = excluded.email,
                color = excluded.color,
                display = excluded.display,
                permissions = excluded.permissions,
                raw_json = excluded.raw_json,
                updated_at_ms = excluded.updated_at_ms",
            params![
                member.id,
                member.calendar_id,
                member.email,
                member.color,
                member.display,
                member.permissions,
                member.raw_json,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_calendar_key(&self, key: &CalendarKeyUpsert) -> Result<()> {
        if key.id.trim().is_empty() {
            return Err(CalendarStoreError::InvalidState(
                "cannot upsert calendar key with empty ID".to_string(),
            ));
        }
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO calendar_keys (
                id, calendar_id, passphrase_id, private_key, flags, raw_json, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                calendar_id = excluded.calendar_id,
                passphrase_id = excluded.passphrase_id,
                private_key = excluded.private_key,
                flags = excluded.flags,
                raw_json = excluded.raw_json,
                updated_at_ms = excluded.updated_at_ms",
            params![
                key.id,
                key.calendar_id,
                key.passphrase_id,
                key.private_key,
                key.flags,
                key.raw_json,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_calendar_settings(&self, settings: &CalendarSettingsUpsert) -> Result<()> {
        if settings.calendar_id.trim().is_empty() {
            return Err(CalendarStoreError::InvalidState(
                "cannot upsert calendar settings with empty CalendarID".to_string(),
            ));
        }
        let settings_id = if settings.id.trim().is_empty() {
            format!("settings:{}", settings.calendar_id)
        } else {
            settings.id.clone()
        };
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO calendar_settings (
                id, calendar_id, default_event_duration,
                default_part_day_notifications_json,
                default_full_day_notifications_json,
                raw_json, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                calendar_id = excluded.calendar_id,
                default_event_duration = excluded.default_event_duration,
                default_part_day_notifications_json = excluded.default_part_day_notifications_json,
                default_full_day_notifications_json = excluded.default_full_day_notifications_json,
                raw_json = excluded.raw_json,
                updated_at_ms = excluded.updated_at_ms",
            params![
                settings_id,
                settings.calendar_id,
                settings.default_event_duration,
                settings.default_part_day_notifications_json,
                settings.default_full_day_notifications_json,
                settings.raw_json,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_calendar_event(&self, event: &CalendarEventUpsert) -> Result<()> {
        if event.id.trim().is_empty() {
            return Err(CalendarStoreError::InvalidState(
                "cannot upsert calendar event with empty ID".to_string(),
            ));
        }
        if event.calendar_id.trim().is_empty() {
            return Err(CalendarStoreError::InvalidState(format!(
                "calendar event {} has empty CalendarID",
                event.id
            )));
        }

        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO calendar_events (
                id, calendar_id, uid, shared_event_id, create_time, last_edit_time, start_time, end_time,
                start_timezone, end_timezone, full_day, author, permissions, attendees_json,
                shared_key_packet, calendar_key_packet, shared_events_json, calendar_events_json,
                attendees_events_json, personal_events_json, raw_json, deleted, updated_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21, 0, ?22
             )
             ON CONFLICT(id) DO UPDATE SET
                calendar_id = excluded.calendar_id,
                uid = excluded.uid,
                shared_event_id = excluded.shared_event_id,
                create_time = excluded.create_time,
                last_edit_time = excluded.last_edit_time,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                start_timezone = excluded.start_timezone,
                end_timezone = excluded.end_timezone,
                full_day = excluded.full_day,
                author = excluded.author,
                permissions = excluded.permissions,
                attendees_json = excluded.attendees_json,
                shared_key_packet = excluded.shared_key_packet,
                calendar_key_packet = excluded.calendar_key_packet,
                shared_events_json = excluded.shared_events_json,
                calendar_events_json = excluded.calendar_events_json,
                attendees_events_json = excluded.attendees_events_json,
                personal_events_json = excluded.personal_events_json,
                raw_json = excluded.raw_json,
                deleted = 0,
                updated_at_ms = excluded.updated_at_ms",
            params![
                event.id,
                event.calendar_id,
                event.uid,
                event.shared_event_id,
                event.create_time,
                event.last_edit_time,
                event.start_time,
                event.end_time,
                event.start_timezone,
                event.end_timezone,
                event.full_day,
                event.author,
                event.permissions,
                event.attendees_json,
                event.shared_key_packet,
                event.calendar_key_packet,
                event.shared_events_json,
                event.calendar_events_json,
                event.attendees_events_json,
                event.personal_events_json,
                event.raw_json,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn soft_delete_calendar_event(&self, event_id: &str) -> Result<()> {
        if event_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute(
            "UPDATE calendar_events SET deleted = 1, updated_at_ms = ?2 WHERE id = ?1",
            params![event_id, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn hard_delete_calendar_event(&self, event_id: &str) -> Result<()> {
        if event_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute("DELETE FROM calendar_events WHERE id = ?1", [event_id])?;
        Ok(())
    }

    pub fn set_sync_state_text(&self, scope: &str, value: &str) -> Result<()> {
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO sync_state (scope, value_text, value_int, updated_at_ms)
             VALUES (?1, ?2, 0, ?3)
             ON CONFLICT(scope) DO UPDATE SET
               value_text = excluded.value_text,
               updated_at_ms = excluded.updated_at_ms",
            params![scope, value, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn get_sync_state_text(&self, scope: &str) -> Result<Option<String>> {
        let conn = self.open_connection()?;
        let value = conn
            .query_row(
                "SELECT value_text FROM sync_state WHERE scope = ?1",
                [scope],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_sync_state_int(&self, scope: &str, value: i64) -> Result<()> {
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO sync_state (scope, value_text, value_int, updated_at_ms)
             VALUES (?1, '', ?2, ?3)
             ON CONFLICT(scope) DO UPDATE SET
               value_int = excluded.value_int,
               updated_at_ms = excluded.updated_at_ms",
            params![scope, value, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn get_sync_state_int(&self, scope: &str) -> Result<Option<i64>> {
        let conn = self.open_connection()?;
        let value = conn
            .query_row(
                "SELECT value_int FROM sync_state WHERE scope = ?1",
                [scope],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn is_synced(&self) -> Result<bool> {
        match self.get_sync_state_int("calendar.last_full_sync_ms")? {
            Some(ms) if ms > 0 => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn count_events(&self) -> Result<i64> {
        let conn = self.open_connection()?;
        let count = conn.query_row(
            "SELECT COUNT(*) FROM calendar_events WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn list_active_calendar_ids(&self) -> Result<Vec<String>> {
        let conn = self.open_connection()?;
        let mut stmt = conn.prepare("SELECT id FROM calendars WHERE deleted = 0 ORDER BY id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_active_calendar_ids_limited(&self, limit: usize) -> Result<Vec<String>> {
        let conn = self.open_connection()?;
        let mut stmt =
            conn.prepare("SELECT id FROM calendars WHERE deleted = 0 ORDER BY id LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_cached_calendar_ids(&self) -> Result<Vec<String>> {
        let conn = self.open_connection()?;
        let mut stmt = conn.prepare("SELECT id FROM calendars WHERE deleted = 0")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_cached_event_ids(
        &self,
        calendar_id: &str,
        start_from: Option<i64>,
        start_to: Option<i64>,
    ) -> Result<Vec<String>> {
        let conn = self.open_connection()?;
        let mut stmt = conn.prepare(
            "SELECT id
             FROM calendar_events
             WHERE calendar_id = ?1
               AND deleted = 0
               AND (?2 IS NULL OR start_time >= ?2)
               AND (?3 IS NULL OR start_time <= ?3)",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![calendar_id, start_from, start_to],
            |row| row.get::<_, String>(0),
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub(crate) fn open_connection(&self) -> Result<Connection> {
        open_connection(&self.db_path)
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    Ok(conn)
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
    use tempfile::tempdir;

    fn test_store() -> CalendarStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        CalendarStore::new(db_path).unwrap()
    }

    fn sample_calendar() -> CalendarUpsert {
        CalendarUpsert {
            id: "cal-1".to_string(),
            name: "Personal".to_string(),
            description: "Primary".to_string(),
            color: "#00AAFF".to_string(),
            display: 1,
            calendar_type: 0,
            flags: 0,
            raw_json: r#"{"ID":"cal-1"}"#.to_string(),
        }
    }

    fn sample_calendar_event() -> CalendarEventUpsert {
        CalendarEventUpsert {
            id: "event-1".to_string(),
            calendar_id: "cal-1".to_string(),
            uid: "uid-event-1".to_string(),
            shared_event_id: "shared-1".to_string(),
            create_time: 1700000010,
            last_edit_time: 1700000011,
            start_time: 1700001000,
            end_time: 1700004600,
            start_timezone: "UTC".to_string(),
            end_timezone: "UTC".to_string(),
            full_day: 0,
            author: "alice@proton.me".to_string(),
            permissions: 2,
            attendees_json: "[]".to_string(),
            shared_key_packet: "skp".to_string(),
            calendar_key_packet: "ckp".to_string(),
            shared_events_json: "[]".to_string(),
            calendar_events_json: "[]".to_string(),
            attendees_events_json: "[]".to_string(),
            personal_events_json: "[]".to_string(),
            raw_json: r#"{"ID":"event-1"}"#.to_string(),
        }
    }

    #[test]
    fn upsert_calendar_and_soft_delete_event() {
        let store = test_store();
        store.upsert_calendar(&sample_calendar()).unwrap();

        store
            .upsert_calendar_member(&CalendarMemberUpsert {
                id: "member-1".to_string(),
                calendar_id: "cal-1".to_string(),
                email: "alice@proton.me".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                permissions: 2,
                raw_json: r#"{"ID":"member-1"}"#.to_string(),
            })
            .unwrap();
        store
            .upsert_calendar_key(&CalendarKeyUpsert {
                id: "key-1".to_string(),
                calendar_id: "cal-1".to_string(),
                passphrase_id: "pp-1".to_string(),
                private_key: "private".to_string(),
                flags: 0,
                raw_json: r#"{"ID":"key-1"}"#.to_string(),
            })
            .unwrap();
        store
            .upsert_calendar_settings(&CalendarSettingsUpsert {
                id: "settings-1".to_string(),
                calendar_id: "cal-1".to_string(),
                default_event_duration: 30,
                default_part_day_notifications_json: "[]".to_string(),
                default_full_day_notifications_json: "[]".to_string(),
                raw_json: r#"{"ID":"settings-1"}"#.to_string(),
            })
            .unwrap();
        store
            .upsert_calendar_event(&sample_calendar_event())
            .unwrap();
        store.soft_delete_calendar_event("event-1").unwrap();

        let conn = store.open_connection().unwrap();
        let deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM calendar_events WHERE id = 'event-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(deleted, 1);
    }

    #[test]
    fn hard_delete_calendar_cascades_child_rows() {
        let store = test_store();
        store.upsert_calendar(&sample_calendar()).unwrap();
        store
            .upsert_calendar_member(&CalendarMemberUpsert {
                id: "member-1".to_string(),
                calendar_id: "cal-1".to_string(),
                email: "alice@proton.me".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                permissions: 2,
                raw_json: r#"{"ID":"member-1"}"#.to_string(),
            })
            .unwrap();
        store
            .upsert_calendar_key(&CalendarKeyUpsert {
                id: "key-1".to_string(),
                calendar_id: "cal-1".to_string(),
                passphrase_id: "pp-1".to_string(),
                private_key: "private".to_string(),
                flags: 0,
                raw_json: r#"{"ID":"key-1"}"#.to_string(),
            })
            .unwrap();
        store
            .upsert_calendar_settings(&CalendarSettingsUpsert {
                id: "settings-1".to_string(),
                calendar_id: "cal-1".to_string(),
                default_event_duration: 30,
                default_part_day_notifications_json: "[]".to_string(),
                default_full_day_notifications_json: "[]".to_string(),
                raw_json: r#"{"ID":"settings-1"}"#.to_string(),
            })
            .unwrap();
        store
            .upsert_calendar_event(&sample_calendar_event())
            .unwrap();

        store.hard_delete_calendar("cal-1").unwrap();

        let conn = store.open_connection().unwrap();
        for (table, expected) in [
            ("calendars", 0),
            ("calendar_members", 0),
            ("calendar_keys", 0),
            ("calendar_settings", 0),
            ("calendar_events", 0),
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, expected, "table {table} should have {expected} rows");
        }
    }

    #[test]
    fn is_synced_and_count() {
        let store = test_store();
        assert!(!store.is_synced().unwrap());
        assert_eq!(store.count_events().unwrap(), 0);

        store.upsert_calendar(&sample_calendar()).unwrap();
        store
            .upsert_calendar_event(&sample_calendar_event())
            .unwrap();
        assert_eq!(store.count_events().unwrap(), 1);

        store
            .set_sync_state_int("calendar.last_full_sync_ms", 1700009999)
            .unwrap();
        assert!(store.is_synced().unwrap());
    }
}
