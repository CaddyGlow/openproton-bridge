use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{ContactsStoreError, Result};
use crate::schema;
use crate::types::ContactUpsert;

pub struct ContactsStore {
    db_path: PathBuf,
}

impl ContactsStore {
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

    pub fn upsert_contact(&self, contact: &ContactUpsert) -> Result<()> {
        let contact_id = contact.id.trim();
        if contact_id.is_empty() {
            return Err(ContactsStoreError::InvalidState(
                "cannot upsert contact with empty ID".to_string(),
            ));
        }

        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO contacts (
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
                contact.id,
                contact.uid,
                contact.name,
                contact.size,
                contact.create_time,
                contact.modify_time,
                contact.raw_json,
                epoch_millis() as i64,
            ],
        )?;

        tx.execute(
            "DELETE FROM contact_cards WHERE contact_id = ?1",
            [contact_id],
        )?;
        for (index, card) in contact.cards.iter().enumerate() {
            tx.execute(
                "INSERT INTO contact_cards (contact_id, card_index, card_type, data, signature)
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
            "DELETE FROM contact_emails WHERE contact_id = ?1",
            [contact_id],
        )?;
        for email in &contact.emails {
            if email.id.trim().is_empty() {
                return Err(ContactsStoreError::InvalidState(format!(
                    "contact {} has email with empty ID",
                    contact_id
                )));
            }

            tx.execute(
                "INSERT INTO contact_emails (
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
                    email.kind_json,
                    email.defaults,
                    email.order,
                    email.label_ids_json,
                    email.last_used_time,
                    email.raw_json,
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
            "UPDATE contacts SET deleted = 1, updated_at_ms = ?2 WHERE id = ?1",
            params![contact_id, epoch_millis() as i64],
        )?;
        Ok(())
    }

    pub fn hard_delete_contact(&self, contact_id: &str) -> Result<()> {
        if contact_id.trim().is_empty() {
            return Ok(());
        }
        let conn = self.open_connection()?;
        conn.execute("DELETE FROM contacts WHERE id = ?1", [contact_id])?;
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
        match self.get_sync_state_int("contacts.last_full_sync_ms")? {
            Some(ms) if ms > 0 => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn count_contacts(&self) -> Result<i64> {
        let conn = self.open_connection()?;
        let count = conn.query_row(
            "SELECT COUNT(*) FROM contacts WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn list_active_contact_ids(&self) -> Result<Vec<String>> {
        let conn = self.open_connection()?;
        let mut stmt = conn.prepare("SELECT id FROM contacts WHERE deleted = 0")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
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
    use crate::types::{ContactCardUpsert, ContactEmailUpsert};
    use tempfile::tempdir;

    fn test_store() -> ContactsStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("contacts.db");
        Box::leak(Box::new(tmp));
        ContactsStore::new(db_path).unwrap()
    }

    fn sample_contact() -> ContactUpsert {
        ContactUpsert {
            id: "contact-1".to_string(),
            uid: "uid-1".to_string(),
            name: "Alice".to_string(),
            size: 10,
            create_time: 1700000000,
            modify_time: 1700000001,
            raw_json: r#"{"ID":"contact-1"}"#.to_string(),
            cards: vec![ContactCardUpsert {
                card_type: 0,
                data: "BEGIN:VCARD".to_string(),
                signature: None,
            }],
            emails: vec![ContactEmailUpsert {
                id: "email-1".to_string(),
                contact_id: "contact-1".to_string(),
                email: "alice@proton.me".to_string(),
                name: "Alice".to_string(),
                kind_json: r#"["home"]"#.to_string(),
                defaults: Some(1),
                order: Some(1),
                label_ids_json: r#"["label-1"]"#.to_string(),
                last_used_time: Some(1700000002),
                raw_json: r#"{"ID":"email-1"}"#.to_string(),
            }],
        }
    }

    #[test]
    fn upsert_contact_replaces_child_rows() {
        let store = test_store();
        let mut contact = sample_contact();
        store.upsert_contact(&contact).unwrap();

        contact.name = "Alice Updated".to_string();
        contact.cards.push(ContactCardUpsert {
            card_type: 1,
            data: "BEGIN:VCARD\nVERSION:4.0".to_string(),
            signature: Some("sig".to_string()),
        });
        contact.emails = vec![ContactEmailUpsert {
            id: "email-2".to_string(),
            contact_id: "contact-1".to_string(),
            email: "alice+new@proton.me".to_string(),
            name: "Alice New".to_string(),
            kind_json: r#"["work"]"#.to_string(),
            defaults: Some(0),
            order: Some(2),
            label_ids_json: "[]".to_string(),
            last_used_time: None,
            raw_json: r#"{"ID":"email-2"}"#.to_string(),
        }];
        store.upsert_contact(&contact).unwrap();

        let conn = store.open_connection().unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM contacts WHERE id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Alice Updated");

        let cards: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM contact_cards WHERE contact_id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cards, 2);

        let emails: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM contact_emails WHERE contact_id = 'contact-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(emails, 1);
    }

    #[test]
    fn hard_delete_contact_cascades_cards_and_emails() {
        let store = test_store();
        store.upsert_contact(&sample_contact()).unwrap();
        store.hard_delete_contact("contact-1").unwrap();

        let conn = store.open_connection().unwrap();
        let contacts_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |row| row.get(0))
            .unwrap();
        let cards_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM contact_cards", [], |row| row.get(0))
            .unwrap();
        let emails_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM contact_emails", [], |row| row.get(0))
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
    fn is_synced_and_count() {
        let store = test_store();
        assert!(!store.is_synced().unwrap());
        assert_eq!(store.count_contacts().unwrap(), 0);

        store.upsert_contact(&sample_contact()).unwrap();
        assert_eq!(store.count_contacts().unwrap(), 1);

        store
            .set_sync_state_int("contacts.last_full_sync_ms", 1700009999)
            .unwrap();
        assert!(store.is_synced().unwrap());
    }
}
