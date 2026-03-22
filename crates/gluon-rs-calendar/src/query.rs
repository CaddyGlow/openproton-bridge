use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

use crate::error::Result;
use crate::store::CalendarStore;
use crate::types::{
    CalendarEventRange, QueryPage, StoredCalendar, StoredCalendarEvent, MAX_PAGE_LIMIT,
};

impl CalendarStore {
    pub fn list_calendars(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendar>> {
        let conn = open_read_connection(self)?;
        let (limit, offset) = normalize_page(page);
        let mut stmt = conn.prepare(
            "SELECT id, name, description, color, display, calendar_type, flags, deleted, updated_at_ms
             FROM calendars
             WHERE (?1 = 1 OR deleted = 0)
             ORDER BY LOWER(name) ASC, id ASC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(
            [bool_to_sql(include_deleted), limit, offset],
            map_calendar_row,
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_calendar(
        &self,
        calendar_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendar>> {
        if calendar_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let mut stmt = conn.prepare(
            "SELECT id, name, description, color, display, calendar_type, flags, deleted, updated_at_ms
             FROM calendars
             WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
        )?;
        let mut rows = stmt.query(rusqlite::params![calendar_id, bool_to_sql(include_deleted)])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(map_calendar_row(row)?));
        }
        Ok(None)
    }

    pub fn calendar_collection_version(&self, calendar_id: &str) -> Result<i64> {
        if calendar_id.trim().is_empty() {
            return Ok(0);
        }
        let conn = open_read_connection(self)?;
        let calendar_version = conn
            .query_row(
                "SELECT updated_at_ms FROM calendars WHERE id = ?1",
                [calendar_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or_default();
        let event_version = conn
            .query_row(
                "SELECT MAX(updated_at_ms) FROM calendar_events WHERE calendar_id = ?1",
                [calendar_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .unwrap_or_default();
        Ok(calendar_version.max(event_version))
    }

    pub fn list_calendar_events(
        &self,
        calendar_id: &str,
        include_deleted: bool,
        range: CalendarEventRange,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendarEvent>> {
        if calendar_id.trim().is_empty() {
            return Ok(Vec::new());
        }
        let conn = open_read_connection(self)?;
        let (limit, offset) = normalize_page(page);
        let mut stmt = conn.prepare(
            "SELECT id, calendar_id, uid, shared_event_id, start_time, end_time, deleted, updated_at_ms
             FROM calendar_events
             WHERE calendar_id = ?1
               AND (?2 = 1 OR deleted = 0)
               AND (?3 IS NULL OR start_time >= ?3)
               AND (?4 IS NULL OR start_time <= ?4)
             ORDER BY start_time ASC, end_time ASC, id ASC
             LIMIT ?5 OFFSET ?6",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![
                calendar_id,
                bool_to_sql(include_deleted),
                range.start_time_from,
                range.start_time_to,
                limit,
                offset
            ],
            map_calendar_event_row,
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_calendar_event(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendarEvent>> {
        if event_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let mut stmt = conn.prepare(
            "SELECT id, calendar_id, uid, shared_event_id, start_time, end_time, deleted, updated_at_ms
             FROM calendar_events
             WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
        )?;
        let mut rows = stmt.query(rusqlite::params![event_id, bool_to_sql(include_deleted)])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(map_calendar_event_row(row)?));
        }
        Ok(None)
    }

    pub fn get_calendar_event_raw_json(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<String>> {
        if event_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let raw_json = conn
            .query_row(
                "SELECT raw_json
                 FROM calendar_events
                 WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
                rusqlite::params![event_id, bool_to_sql(include_deleted)],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(raw_json)
    }

    pub fn get_calendar_event_raw_json_as_value(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<Value>> {
        match self.get_calendar_event_raw_json(event_id, include_deleted)? {
            Some(raw) => {
                let value: Value = serde_json::from_str(&raw).map_err(|e| {
                    crate::error::CalendarStoreError::InvalidState(format!(
                        "invalid JSON for event {event_id}: {e}"
                    ))
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

fn normalize_page(page: QueryPage) -> (i64, i64) {
    let limit = page.limit.clamp(1, MAX_PAGE_LIMIT) as i64;
    let offset = page.offset as i64;
    (limit, offset)
}

fn bool_to_sql(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn open_read_connection(store: &CalendarStore) -> Result<Connection> {
    let conn = Connection::open(store.db_path())?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

fn map_calendar_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredCalendar> {
    Ok(StoredCalendar {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        color: row.get(3)?,
        display: row.get(4)?,
        calendar_type: row.get(5)?,
        flags: row.get(6)?,
        deleted: row.get::<_, i64>(7)? != 0,
        updated_at_ms: row.get(8)?,
    })
}

fn map_calendar_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredCalendarEvent> {
    Ok(StoredCalendarEvent {
        id: row.get(0)?,
        calendar_id: row.get(1)?,
        uid: row.get(2)?,
        shared_event_id: row.get(3)?,
        start_time: row.get(4)?,
        end_time: row.get(5)?,
        deleted: row.get::<_, i64>(6)? != 0,
        updated_at_ms: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::types::{CalendarEventUpsert, CalendarUpsert};

    fn test_store() -> CalendarStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        CalendarStore::new(db_path).unwrap()
    }

    fn calendar(id: &str, name: &str) -> CalendarUpsert {
        CalendarUpsert {
            id: id.to_string(),
            name: name.to_string(),
            description: "".to_string(),
            color: "#00AAFF".to_string(),
            display: 1,
            calendar_type: 0,
            flags: 0,
            raw_json: format!(r#"{{"ID":"{id}"}}"#),
        }
    }

    fn calendar_event(
        id: &str,
        calendar_id: &str,
        start_time: i64,
        end_time: i64,
    ) -> CalendarEventUpsert {
        CalendarEventUpsert {
            id: id.to_string(),
            calendar_id: calendar_id.to_string(),
            uid: format!("uid-{id}"),
            shared_event_id: format!("shared-{id}"),
            create_time: start_time - 10,
            last_edit_time: start_time - 5,
            start_time,
            end_time,
            start_timezone: "UTC".to_string(),
            end_timezone: "UTC".to_string(),
            full_day: 0,
            author: "".to_string(),
            permissions: 0,
            attendees_json: "[]".to_string(),
            shared_key_packet: "".to_string(),
            calendar_key_packet: "".to_string(),
            shared_events_json: "[]".to_string(),
            calendar_events_json: "[]".to_string(),
            attendees_events_json: "[]".to_string(),
            personal_events_json: "[]".to_string(),
            raw_json: format!(r#"{{"ID":"{id}"}}"#),
        }
    }

    #[test]
    fn calendar_queries_filter_deleted_and_time_range() {
        let store = test_store();
        store.upsert_calendar(&calendar("cal-a", "Alpha")).unwrap();
        store.upsert_calendar(&calendar("cal-b", "Beta")).unwrap();
        store.soft_delete_calendar("cal-b").unwrap();

        store
            .upsert_calendar_event(&calendar_event("evt-1", "cal-a", 100, 200))
            .unwrap();
        store
            .upsert_calendar_event(&calendar_event("evt-2", "cal-a", 300, 400))
            .unwrap();
        store
            .upsert_calendar_event(&calendar_event("evt-3", "cal-a", 500, 600))
            .unwrap();
        store.soft_delete_calendar_event("evt-2").unwrap();

        let calendars = store
            .list_calendars(
                false,
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].id, "cal-a");

        let events = store
            .list_calendar_events(
                "cal-a",
                false,
                CalendarEventRange {
                    start_time_from: Some(50),
                    start_time_to: Some(450),
                },
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-1");

        let events_with_deleted = store
            .list_calendar_events(
                "cal-a",
                true,
                CalendarEventRange {
                    start_time_from: Some(50),
                    start_time_to: Some(450),
                },
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(events_with_deleted.len(), 2);
    }
}
