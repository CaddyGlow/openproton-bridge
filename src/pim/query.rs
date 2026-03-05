use rusqlite::{Connection, OptionalExtension};

use crate::api::{calendar, contacts};

use super::store::PimStore;
use super::types::{StoredCalendar, StoredCalendarEvent, StoredContact};
use super::Result;

const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPage {
    pub limit: usize,
    pub offset: usize,
}

impl Default for QueryPage {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalendarEventRange {
    pub start_time_from: Option<i64>,
    pub start_time_to: Option<i64>,
}

impl PimStore {
    pub fn list_contacts(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>> {
        let conn = open_read_connection(self)?;
        let (limit, offset) = normalize_page(page);
        let mut stmt = conn.prepare(
            "SELECT id, uid, name, size, create_time, modify_time, deleted, updated_at_ms
             FROM pim_contacts
             WHERE (?1 = 1 OR deleted = 0)
             ORDER BY modify_time DESC, id ASC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(
            [bool_to_sql(include_deleted), limit, offset],
            map_contact_row,
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_contact(
        &self,
        contact_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredContact>> {
        if contact_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let mut stmt = conn.prepare(
            "SELECT id, uid, name, size, create_time, modify_time, deleted, updated_at_ms
             FROM pim_contacts
             WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
        )?;
        let mut rows = stmt.query(rusqlite::params![contact_id, bool_to_sql(include_deleted)])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(map_contact_row(row)?));
        }
        Ok(None)
    }

    pub fn get_contact_payload(
        &self,
        contact_id: &str,
        include_deleted: bool,
    ) -> Result<Option<contacts::Contact>> {
        if contact_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let raw_json = conn
            .query_row(
                "SELECT raw_json
                 FROM pim_contacts
                 WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
                rusqlite::params![contact_id, bool_to_sql(include_deleted)],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match raw_json {
            Some(raw) => Ok(Some(serde_json::from_str::<contacts::Contact>(&raw)?)),
            None => Ok(None),
        }
    }

    pub fn search_contacts_by_email(
        &self,
        email_like: &str,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>> {
        if email_like.trim().is_empty() {
            return Ok(Vec::new());
        }
        let conn = open_read_connection(self)?;
        let pattern = if email_like.contains('%') || email_like.contains('_') {
            email_like.to_string()
        } else {
            format!("%{email_like}%")
        };
        let (limit, offset) = normalize_page(page);
        let mut stmt = conn.prepare(
            "SELECT DISTINCT c.id, c.uid, c.name, c.size, c.create_time, c.modify_time, c.deleted, c.updated_at_ms
             FROM pim_contact_emails e
             INNER JOIN pim_contacts c ON c.id = e.contact_id
             WHERE c.deleted = 0 AND e.email LIKE ?1 COLLATE NOCASE
             ORDER BY c.modify_time DESC, c.id ASC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(rusqlite::params![pattern, limit, offset], map_contact_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_calendars(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendar>> {
        let conn = open_read_connection(self)?;
        let (limit, offset) = normalize_page(page);
        let mut stmt = conn.prepare(
            "SELECT id, name, description, color, display, calendar_type, flags, deleted, updated_at_ms
             FROM pim_calendars
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
             FROM pim_calendars
             WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
        )?;
        let mut rows = stmt.query(rusqlite::params![calendar_id, bool_to_sql(include_deleted)])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(map_calendar_row(row)?));
        }
        Ok(None)
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
             FROM pim_calendar_events
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
             FROM pim_calendar_events
             WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
        )?;
        let mut rows = stmt.query(rusqlite::params![event_id, bool_to_sql(include_deleted)])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(map_calendar_event_row(row)?));
        }
        Ok(None)
    }

    pub fn get_calendar_event_payload(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<calendar::CalendarEvent>> {
        if event_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let raw_json = conn
            .query_row(
                "SELECT raw_json
                 FROM pim_calendar_events
                 WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
                rusqlite::params![event_id, bool_to_sql(include_deleted)],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match raw_json {
            Some(raw) => Ok(Some(serde_json::from_str::<calendar::CalendarEvent>(&raw)?)),
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

fn open_read_connection(store: &PimStore) -> Result<Connection> {
    let conn = Connection::open(store.db_path())?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

fn map_contact_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredContact> {
    Ok(StoredContact {
        id: row.get(0)?,
        uid: row.get(1)?,
        name: row.get(2)?,
        size: row.get(3)?,
        create_time: row.get(4)?,
        modify_time: row.get(5)?,
        deleted: row.get::<_, i64>(6)? != 0,
        updated_at_ms: row.get(7)?,
    })
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
    use crate::api::calendar::{Calendar, CalendarEvent};
    use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};

    fn test_store() -> PimStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("account.db");
        Box::leak(Box::new(tmp));
        PimStore::new(db_path).unwrap()
    }

    fn contact_with_email(id: &str, name: &str, email: &str, modify_time: i64) -> Contact {
        Contact {
            metadata: ContactMetadata {
                id: id.to_string(),
                name: name.to_string(),
                uid: format!("uid-{id}"),
                size: 10,
                create_time: modify_time - 1,
                modify_time,
                contact_emails: vec![ContactEmail {
                    id: format!("email-{id}"),
                    email: email.to_string(),
                    name: name.to_string(),
                    kind: vec![],
                    defaults: None,
                    order: None,
                    contact_id: id.to_string(),
                    label_ids: vec![],
                    last_used_time: None,
                }],
                label_ids: vec![],
            },
            cards: vec![ContactCard {
                card_type: 0,
                data: "BEGIN:VCARD".to_string(),
                signature: None,
            }],
        }
    }

    fn calendar(id: &str, name: &str) -> Calendar {
        Calendar {
            id: id.to_string(),
            name: name.to_string(),
            description: "".to_string(),
            color: "#00AAFF".to_string(),
            display: 1,
            calendar_type: 0,
            flags: 0,
        }
    }

    fn calendar_event(
        id: &str,
        calendar_id: &str,
        start_time: i64,
        end_time: i64,
    ) -> CalendarEvent {
        CalendarEvent {
            id: id.to_string(),
            uid: format!("uid-{id}"),
            calendar_id: calendar_id.to_string(),
            shared_event_id: format!("shared-{id}"),
            create_time: start_time - 10,
            last_edit_time: start_time - 5,
            start_time,
            end_time,
            ..CalendarEvent::default()
        }
    }

    #[test]
    fn contact_queries_support_stable_paging_and_email_search() {
        let store = test_store();
        store
            .upsert_contact(&contact_with_email("c-1", "Alice", "alice@proton.me", 30))
            .unwrap();
        store
            .upsert_contact(&contact_with_email("c-2", "Bob", "bob@proton.me", 20))
            .unwrap();
        store
            .upsert_contact(&contact_with_email("c-3", "Carol", "carol@proton.me", 10))
            .unwrap();
        store.soft_delete_contact("c-3").unwrap();

        let first_page = store
            .list_contacts(
                false,
                QueryPage {
                    limit: 1,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].id, "c-1");

        let second_page = store
            .list_contacts(
                false,
                QueryPage {
                    limit: 1,
                    offset: 1,
                },
            )
            .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].id, "c-2");

        assert!(store.get_contact("c-3", false).unwrap().is_none());
        assert!(store.get_contact("c-3", true).unwrap().is_some());

        let search = store
            .search_contacts_by_email(
                "alice@",
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(search.len(), 1);
        assert_eq!(search[0].id, "c-1");
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
        assert_eq!(events_with_deleted[0].id, "evt-1");
        assert_eq!(events_with_deleted[1].id, "evt-2");
    }
}
