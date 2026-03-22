use rusqlite::Connection;

use crate::error::Result;
use crate::store::ContactsStore;
use crate::types::{QueryPage, StoredContact, MAX_PAGE_LIMIT};

impl ContactsStore {
    pub fn list_contacts(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>> {
        let conn = open_read_connection(self)?;
        let (limit, offset) = normalize_page(page);
        let mut stmt = conn.prepare(
            "SELECT id, uid, name, size, create_time, modify_time, deleted, updated_at_ms
             FROM contacts
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
             FROM contacts
             WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
        )?;
        let mut rows = stmt.query(rusqlite::params![contact_id, bool_to_sql(include_deleted)])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(map_contact_row(row)?));
        }
        Ok(None)
    }

    pub fn get_contact_raw_json(
        &self,
        contact_id: &str,
        include_deleted: bool,
    ) -> Result<Option<String>> {
        if contact_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = open_read_connection(self)?;
        let raw_json = conn
            .query_row(
                "SELECT raw_json
                 FROM contacts
                 WHERE id = ?1 AND (?2 = 1 OR deleted = 0)",
                rusqlite::params![contact_id, bool_to_sql(include_deleted)],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(raw_json)
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
             FROM contact_emails e
             INNER JOIN contacts c ON c.id = e.contact_id
             WHERE c.deleted = 0 AND e.email LIKE ?1 COLLATE NOCASE
             ORDER BY c.modify_time DESC, c.id ASC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(rusqlite::params![pattern, limit, offset], map_contact_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

use rusqlite::OptionalExtension;

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

fn open_read_connection(store: &ContactsStore) -> Result<Connection> {
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

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::types::{ContactCardUpsert, ContactEmailUpsert, ContactUpsert};

    fn test_store() -> ContactsStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("contacts.db");
        Box::leak(Box::new(tmp));
        ContactsStore::new(db_path).unwrap()
    }

    fn contact(id: &str, name: &str, email: &str, modify_time: i64) -> ContactUpsert {
        ContactUpsert {
            id: id.to_string(),
            uid: format!("uid-{id}"),
            name: name.to_string(),
            size: 10,
            create_time: modify_time - 1,
            modify_time,
            raw_json: format!(r#"{{"ID":"{id}"}}"#),
            cards: vec![ContactCardUpsert {
                card_type: 0,
                data: "BEGIN:VCARD".to_string(),
                signature: None,
            }],
            emails: vec![ContactEmailUpsert {
                id: format!("email-{id}"),
                contact_id: id.to_string(),
                email: email.to_string(),
                name: name.to_string(),
                kind_json: "[]".to_string(),
                defaults: None,
                order: None,
                label_ids_json: "[]".to_string(),
                last_used_time: None,
                raw_json: format!(r#"{{"ID":"email-{id}"}}"#),
            }],
        }
    }

    #[test]
    fn contact_queries_support_stable_paging_and_email_search() {
        let store = test_store();
        store
            .upsert_contact(&contact("c-1", "Alice", "alice@proton.me", 30))
            .unwrap();
        store
            .upsert_contact(&contact("c-2", "Bob", "bob@proton.me", 20))
            .unwrap();
        store
            .upsert_contact(&contact("c-3", "Carol", "carol@proton.me", 10))
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
    fn get_contact_raw_json_returns_stored_json() {
        let store = test_store();
        store
            .upsert_contact(&contact("c-1", "Alice", "alice@proton.me", 30))
            .unwrap();

        let raw = store.get_contact_raw_json("c-1", false).unwrap().unwrap();
        assert!(raw.contains("c-1"));
    }
}
