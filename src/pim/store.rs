use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::api::{calendar, contacts};

use super::schema;
use super::Result;

pub struct PimStore {
    db_path: PathBuf,
}

impl PimStore {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = open_sqlite_connection(&db_path)?;
        schema::migrate(&mut conn)?;

        Ok(Self { db_path })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn migrate(&self) -> Result<()> {
        let mut conn = self.open_connection()?;
        schema::migrate(&mut conn)
    }

    pub fn set_sync_state_text(&self, scope: &str, value: &str) -> Result<()> {
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO pim_sync_state (scope, value_text, value_int, updated_at_ms)
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
                "SELECT value_text FROM pim_sync_state WHERE scope = ?1",
                [scope],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_sync_state_int(&self, scope: &str, value: i64) -> Result<()> {
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO pim_sync_state (scope, value_text, value_int, updated_at_ms)
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
                "SELECT value_int FROM pim_sync_state WHERE scope = ?1",
                [scope],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn upsert_contact(&self, contact: &contacts::Contact) -> Result<()> {
        let contact_id = contact.metadata.id.trim();
        if contact_id.is_empty() {
            return Err(super::PimError::InvalidState(
                "cannot upsert contact with empty ID".to_string(),
            ));
        }

        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let raw_json = serde_json::to_string(contact)?;

        tx.execute(
            "INSERT INTO pim_contacts (
                id, uid, name, size, create_time, modify_time, raw_json, deleted, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
             ON CONFLICT(id) DO UPDATE SET
                uid = excluded.uid,
                name = excluded.name,
                size = excluded.size,
                create_time = excluded.create_time,
                modify_time = excluded.modify_time,
                raw_json = excluded.raw_json,
                deleted = 0,
                updated_at_ms = excluded.updated_at_ms",
            params![
                contact.metadata.id,
                contact.metadata.uid,
                contact.metadata.name,
                contact.metadata.size,
                contact.metadata.create_time,
                contact.metadata.modify_time,
                raw_json,
                epoch_millis() as i64,
            ],
        )?;

        tx.execute(
            "DELETE FROM pim_contact_cards WHERE contact_id = ?1",
            [contact_id],
        )?;
        for (index, card) in contact.cards.iter().enumerate() {
            tx.execute(
                "INSERT INTO pim_contact_cards (contact_id, card_index, card_type, data, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    contact_id,
                    index as i64,
                    card.card_type,
                    card.data,
                    card.signature,
                ],
            )?;
        }

        tx.execute(
            "DELETE FROM pim_contact_emails WHERE contact_id = ?1",
            [contact_id],
        )?;
        for email in &contact.metadata.contact_emails {
            if email.id.trim().is_empty() {
                return Err(super::PimError::InvalidState(format!(
                    "contact {} has email with empty ID",
                    contact_id
                )));
            }

            tx.execute(
                "INSERT INTO pim_contact_emails (
                    id, contact_id, email, name, kind_json, defaults_value, order_value,
                    label_ids_json, last_used_time, raw_json, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(id) DO UPDATE SET
                    contact_id = excluded.contact_id,
                    email = excluded.email,
                    name = excluded.name,
                    kind_json = excluded.kind_json,
                    defaults_value = excluded.defaults_value,
                    order_value = excluded.order_value,
                    label_ids_json = excluded.label_ids_json,
                    last_used_time = excluded.last_used_time,
                    raw_json = excluded.raw_json,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    email.id,
                    email.contact_id,
                    email.email,
                    email.name,
                    serde_json::to_string(&email.kind)?,
                    email.defaults,
                    email.order,
                    serde_json::to_string(&email.label_ids)?,
                    email.last_used_time,
                    serde_json::to_string(email)?,
                    epoch_millis() as i64
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn soft_delete_contact(&self, contact_id: &str) -> Result<()> {
        if contact_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute(
            "UPDATE pim_contacts SET deleted = 1, updated_at_ms = ?2 WHERE id = ?1",
            params![contact_id, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn hard_delete_contact(&self, contact_id: &str) -> Result<()> {
        if contact_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute("DELETE FROM pim_contacts WHERE id = ?1", [contact_id])?;
        Ok(())
    }

    pub fn upsert_calendar(&self, calendar: &calendar::Calendar) -> Result<()> {
        if calendar.id.trim().is_empty() {
            return Err(super::PimError::InvalidState(
                "cannot upsert calendar with empty ID".to_string(),
            ));
        }

        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO pim_calendars (
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
                serde_json::to_string(calendar)?,
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
            "UPDATE pim_calendars SET deleted = 1, updated_at_ms = ?2 WHERE id = ?1",
            params![calendar_id, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn hard_delete_calendar(&self, calendar_id: &str) -> Result<()> {
        if calendar_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute("DELETE FROM pim_calendars WHERE id = ?1", [calendar_id])?;
        Ok(())
    }

    pub fn upsert_calendar_member(&self, member: &calendar::CalendarMember) -> Result<()> {
        if member.id.trim().is_empty() {
            return Err(super::PimError::InvalidState(
                "cannot upsert calendar member with empty ID".to_string(),
            ));
        }
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO pim_calendar_members (
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
                serde_json::to_string(member)?,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_calendar_key(&self, key: &calendar::CalendarKey) -> Result<()> {
        if key.id.trim().is_empty() {
            return Err(super::PimError::InvalidState(
                "cannot upsert calendar key with empty ID".to_string(),
            ));
        }
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO pim_calendar_keys (
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
                serde_json::to_string(key)?,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_calendar_settings(&self, settings: &calendar::CalendarSettings) -> Result<()> {
        if settings.calendar_id.trim().is_empty() {
            return Err(super::PimError::InvalidState(
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
            "INSERT INTO pim_calendar_settings (
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
                serde_json::to_string(&settings.default_part_day_notifications)?,
                serde_json::to_string(&settings.default_full_day_notifications)?,
                serde_json::to_string(settings)?,
                epoch_millis() as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_calendar_event(&self, event: &calendar::CalendarEvent) -> Result<()> {
        if event.id.trim().is_empty() {
            return Err(super::PimError::InvalidState(
                "cannot upsert calendar event with empty ID".to_string(),
            ));
        }
        if event.calendar_id.trim().is_empty() {
            return Err(super::PimError::InvalidState(format!(
                "calendar event {} has empty CalendarID",
                event.id
            )));
        }

        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO pim_calendar_events (
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
                serde_json::to_string(&event.attendees)?,
                event.shared_key_packet,
                event.calendar_key_packet,
                serde_json::to_string(&event.shared_events)?,
                serde_json::to_string(&event.calendar_events)?,
                serde_json::to_string(&event.attendees_events)?,
                serde_json::to_string(&event.personal_events)?,
                serde_json::to_string(event)?,
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
            "UPDATE pim_calendar_events SET deleted = 1, updated_at_ms = ?2 WHERE id = ?1",
            params![event_id, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn hard_delete_calendar_event(&self, event_id: &str) -> Result<()> {
        if event_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute("DELETE FROM pim_calendar_events WHERE id = ?1", [event_id])?;
        Ok(())
    }

    fn open_connection(&self) -> Result<Connection> {
        open_sqlite_connection(&self.db_path)
    }
}

fn open_sqlite_connection(path: &Path) -> Result<Connection> {
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
    use crate::api::calendar::{
        Calendar, CalendarEvent, CalendarKey, CalendarMember, CalendarSettings,
    };
    use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};
    use tempfile::tempdir;

    fn test_store() -> PimStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("account.db");
        // Hold tmp by leaking for test lifetime. Keeps setup simple and stable.
        Box::leak(Box::new(tmp));
        PimStore::new(db_path).unwrap()
    }

    fn sample_contact() -> Contact {
        Contact {
            metadata: ContactMetadata {
                id: "contact-1".to_string(),
                name: "Alice".to_string(),
                uid: "uid-1".to_string(),
                size: 10,
                create_time: 1700000000,
                modify_time: 1700000001,
                contact_emails: vec![ContactEmail {
                    id: "email-1".to_string(),
                    email: "alice@proton.me".to_string(),
                    name: "Alice".to_string(),
                    kind: vec!["home".to_string()],
                    defaults: Some(1),
                    order: Some(1),
                    contact_id: "contact-1".to_string(),
                    label_ids: vec!["label-1".to_string()],
                    last_used_time: Some(1700000002),
                }],
                label_ids: vec!["label-1".to_string()],
            },
            cards: vec![ContactCard {
                card_type: 0,
                data: "BEGIN:VCARD".to_string(),
                signature: None,
            }],
        }
    }

    fn sample_calendar() -> Calendar {
        Calendar {
            id: "cal-1".to_string(),
            name: "Personal".to_string(),
            description: "Primary".to_string(),
            color: "#00AAFF".to_string(),
            display: 1,
            calendar_type: 0,
            flags: 0,
        }
    }

    fn sample_calendar_member() -> CalendarMember {
        CalendarMember {
            id: "member-1".to_string(),
            calendar_id: "cal-1".to_string(),
            email: "alice@proton.me".to_string(),
            color: "#00AAFF".to_string(),
            display: 1,
            permissions: 2,
        }
    }

    fn sample_calendar_key() -> CalendarKey {
        CalendarKey {
            id: "key-1".to_string(),
            calendar_id: "cal-1".to_string(),
            passphrase_id: "pp-1".to_string(),
            private_key: "private".to_string(),
            flags: 0,
        }
    }

    fn sample_calendar_settings() -> CalendarSettings {
        CalendarSettings {
            id: "settings-1".to_string(),
            calendar_id: "cal-1".to_string(),
            default_event_duration: 30,
            default_part_day_notifications: vec![],
            default_full_day_notifications: vec![],
        }
    }

    fn sample_calendar_event() -> CalendarEvent {
        CalendarEvent {
            id: "event-1".to_string(),
            uid: "uid-event-1".to_string(),
            calendar_id: "cal-1".to_string(),
            shared_event_id: "shared-1".to_string(),
            create_time: 1700000010,
            last_edit_time: 1700000011,
            start_time: 1700001000,
            start_timezone: "UTC".to_string(),
            end_time: 1700004600,
            end_timezone: "UTC".to_string(),
            full_day: 0,
            author: "alice@proton.me".to_string(),
            permissions: 2,
            attendees: vec![],
            shared_key_packet: "skp".to_string(),
            calendar_key_packet: "ckp".to_string(),
            shared_events: vec![],
            calendar_events: vec![],
            attendees_events: vec![],
            personal_events: vec![],
        }
    }

    #[test]
    fn initialization_migrates_schema_and_is_idempotent() {
        let store = test_store();
        store.migrate().unwrap();
        store.migrate().unwrap();

        let conn = store.open_connection().unwrap();
        let version = schema::current_version(&conn).unwrap();
        assert_eq!(version, schema::PIM_SCHEMA_VERSION);
    }

    #[test]
    fn upsert_contact_replaces_child_rows() {
        let store = test_store();
        let mut contact = sample_contact();
        store.upsert_contact(&contact).unwrap();

        contact.metadata.name = "Alice Updated".to_string();
        contact.cards.push(ContactCard {
            card_type: 1,
            data: "BEGIN:VCARD\nVERSION:4.0".to_string(),
            signature: Some("sig".to_string()),
        });
        contact.metadata.contact_emails = vec![ContactEmail {
            id: "email-2".to_string(),
            email: "alice+new@proton.me".to_string(),
            name: "Alice New".to_string(),
            kind: vec!["work".to_string()],
            defaults: Some(0),
            order: Some(2),
            contact_id: "contact-1".to_string(),
            label_ids: vec![],
            last_used_time: None,
        }];
        store.upsert_contact(&contact).unwrap();

        let conn = store.open_connection().unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM pim_contacts WHERE id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Alice Updated");

        let cards: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_contact_cards WHERE contact_id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cards, 2);

        let emails: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_contact_emails WHERE contact_id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(emails, 1);
    }

    #[test]
    fn hard_delete_contact_cascades_cards_and_emails() {
        let store = test_store();
        let contact = sample_contact();
        store.upsert_contact(&contact).unwrap();
        store.hard_delete_contact("contact-1").unwrap();

        let conn = store.open_connection().unwrap();
        let contacts_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_contacts", [], |row| row.get(0))
            .unwrap();
        let cards_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_contact_cards", [], |row| {
                row.get(0)
            })
            .unwrap();
        let emails_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_contact_emails", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(contacts_count, 0);
        assert_eq!(cards_count, 0);
        assert_eq!(emails_count, 0);
    }

    #[test]
    fn sync_state_roundtrip_text_and_int() {
        let store = test_store();

        store
            .set_sync_state_text("contacts.core_event_id", "event-42")
            .unwrap();
        store
            .set_sync_state_int("contacts.last_full_sync_ms", 1700009999)
            .unwrap();

        assert_eq!(
            store
                .get_sync_state_text("contacts.core_event_id")
                .unwrap()
                .as_deref(),
            Some("event-42")
        );
        assert_eq!(
            store
                .get_sync_state_int("contacts.last_full_sync_ms")
                .unwrap(),
            Some(1700009999)
        );
    }

    #[test]
    fn upsert_calendar_and_soft_delete_event() {
        let store = test_store();
        store.upsert_calendar(&sample_calendar()).unwrap();
        store
            .upsert_calendar_member(&sample_calendar_member())
            .unwrap();
        store.upsert_calendar_key(&sample_calendar_key()).unwrap();
        store
            .upsert_calendar_settings(&sample_calendar_settings())
            .unwrap();
        store
            .upsert_calendar_event(&sample_calendar_event())
            .unwrap();
        store.soft_delete_calendar_event("event-1").unwrap();

        let conn = store.open_connection().unwrap();
        let deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendar_events WHERE id = 'event-1'",
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
            .upsert_calendar_member(&sample_calendar_member())
            .unwrap();
        store.upsert_calendar_key(&sample_calendar_key()).unwrap();
        store
            .upsert_calendar_settings(&sample_calendar_settings())
            .unwrap();
        store
            .upsert_calendar_event(&sample_calendar_event())
            .unwrap();

        store.hard_delete_calendar("cal-1").unwrap();

        let conn = store.open_connection().unwrap();
        let calendars_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_calendars", [], |row| row.get(0))
            .unwrap();
        let members_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_calendar_members", [], |row| {
                row.get(0)
            })
            .unwrap();
        let keys_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_calendar_keys", [], |row| {
                row.get(0)
            })
            .unwrap();
        let settings_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_calendar_settings", [], |row| {
                row.get(0)
            })
            .unwrap();
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pim_calendar_events", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(calendars_count, 0);
        assert_eq!(members_count, 0);
        assert_eq!(keys_count, 0);
        assert_eq!(settings_count, 0);
        assert_eq!(events_count, 0);
    }
}
