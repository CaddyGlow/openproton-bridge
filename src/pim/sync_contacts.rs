use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::api::client::ProtonClient;
use crate::api::contacts::{self, ContactsQuery};

use super::store::PimStore;
use super::{PimError, Result};

pub const DEFAULT_CONTACTS_PAGE_SIZE: i32 = 100;
pub const MAX_CONTACTS_PAGE_SIZE: i32 = 500;
const CONTACTS_LAST_FULL_SYNC_KEY: &str = "contacts.last_full_sync_ms";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapContactsSummary {
    pub page_size: i32,
    pub pages_fetched: usize,
    pub contacts_seen: usize,
    pub contacts_upserted: usize,
    pub contacts_soft_deleted: usize,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

pub async fn bootstrap_contacts(
    client: &ProtonClient,
    store: &PimStore,
    page_size: i32,
) -> Result<BootstrapContactsSummary> {
    let started_at_ms = epoch_millis();
    let page_size = normalize_page_size(page_size);
    let mut page = 0_i32;
    let mut fetched_total = 0_i64;
    let mut pages_fetched = 0_usize;
    let mut contacts_upserted = 0_usize;
    let mut seen_ids = HashSet::new();

    loop {
        let query = ContactsQuery {
            page: Some(page),
            page_size: Some(page_size),
        };

        let (contacts_page, total) =
            super::run_with_api_retry(|| contacts::get_contacts(client, &query))
                .await
                .map_err(|err| pim_api_error("contacts bootstrap: get_contacts", err))?;
        if contacts_page.is_empty() {
            break;
        }

        pages_fetched += 1;
        fetched_total += contacts_page.len() as i64;

        for item in contacts_page {
            if item.metadata.id.trim().is_empty() {
                continue;
            }
            let full =
                super::run_with_api_retry(|| contacts::get_contact(client, &item.metadata.id))
                    .await
                    .map_err(|err| pim_api_error("contacts bootstrap: get_contact", err))?;
            seen_ids.insert(full.metadata.id.clone());
            store.upsert_contact(&full)?;
            contacts_upserted += 1;
        }

        if fetched_total >= total {
            break;
        }
        page = page.saturating_add(1);
    }

    let mut soft_deleted = 0_usize;
    for contact_id in load_local_contact_ids(store.db_path())? {
        if !seen_ids.contains(&contact_id) {
            store.soft_delete_contact(&contact_id)?;
            soft_deleted += 1;
        }
    }

    let finished_at_ms = epoch_millis();
    store.set_sync_state_int(CONTACTS_LAST_FULL_SYNC_KEY, finished_at_ms as i64)?;

    Ok(BootstrapContactsSummary {
        page_size,
        pages_fetched,
        contacts_seen: seen_ids.len(),
        contacts_upserted,
        contacts_soft_deleted: soft_deleted,
        started_at_ms,
        finished_at_ms,
    })
}

fn load_local_contact_ids(db_path: &Path) -> Result<Vec<String>> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare("SELECT id FROM pim_contacts WHERE deleted = 0")?;
    let ids = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(ids)
}

fn normalize_page_size(page_size: i32) -> i32 {
    if page_size <= 0 {
        DEFAULT_CONTACTS_PAGE_SIZE
    } else {
        page_size.min(MAX_CONTACTS_PAGE_SIZE)
    }
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn pim_api_error(context: &str, err: crate::api::error::ApiError) -> PimError {
    PimError::InvalidState(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};
    use tempfile::tempdir;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_full_contact(id: &str, name: &str) -> Contact {
        Contact {
            metadata: ContactMetadata {
                id: id.to_string(),
                name: name.to_string(),
                uid: format!("uid-{id}"),
                size: 10,
                create_time: 1700000000,
                modify_time: 1700000001,
                contact_emails: vec![ContactEmail {
                    id: format!("email-{id}"),
                    email: format!("{id}@proton.me"),
                    name: name.to_string(),
                    kind: vec!["home".to_string()],
                    defaults: Some(1),
                    order: Some(1),
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

    fn full_contact_response(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "Code": 1000,
            "Contact": {
                "ID": id,
                "Name": name,
                "UID": format!("uid-{}", id),
                "Size": 10,
                "CreateTime": 1700000000,
                "ModifyTime": 1700000001,
                "ContactEmails": [{
                    "ID": format!("email-{}", id),
                    "Email": format!("{}@proton.me", id),
                    "Name": name,
                    "Kind": ["home"],
                    "ContactID": id,
                    "LabelIDs": []
                }],
                "Cards": [{
                    "Type": 0,
                    "Data": "BEGIN:VCARD",
                    "Signature": null
                }]
            }
        })
    }

    #[tokio::test]
    async fn bootstrap_contacts_paginates_and_upserts_full_contacts() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();
        let tmp = tempdir().unwrap();
        let store = PimStore::new(tmp.path().join("contacts.db")).unwrap();
        store
            .upsert_contact(&sample_full_contact("old-contact", "Old"))
            .unwrap();

        Mock::given(method("GET"))
            .and(path("/contacts/v4"))
            .and(query_param("Page", "0"))
            .and(query_param("PageSize", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 3,
                "Contacts": [
                    {
                        "ID": "contact-1",
                        "Name": "Alice",
                        "UID": "uid-contact-1",
                        "Size": 10,
                        "CreateTime": 1700000000,
                        "ModifyTime": 1700000001
                    },
                    {
                        "ID": "contact-2",
                        "Name": "Bob",
                        "UID": "uid-contact-2",
                        "Size": 11,
                        "CreateTime": 1700000010,
                        "ModifyTime": 1700000011
                    }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4"))
            .and(query_param("Page", "1"))
            .and(query_param("PageSize", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 3,
                "Contacts": [
                    {
                        "ID": "contact-3",
                        "Name": "Charlie",
                        "UID": "uid-contact-3",
                        "Size": 12,
                        "CreateTime": 1700000020,
                        "ModifyTime": 1700000021
                    }
                ]
            })))
            .mount(&server)
            .await;

        for (id, name) in [
            ("contact-1", "Alice"),
            ("contact-2", "Bob"),
            ("contact-3", "Charlie"),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/contacts/v4/{id}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(full_contact_response(id, name)),
                )
                .mount(&server)
                .await;
        }

        let summary = bootstrap_contacts(&client, &store, 2).await.unwrap();
        assert_eq!(summary.page_size, 2);
        assert_eq!(summary.pages_fetched, 2);
        assert_eq!(summary.contacts_seen, 3);
        assert_eq!(summary.contacts_upserted, 3);
        assert_eq!(summary.contacts_soft_deleted, 1);

        let conn = Connection::open(store.db_path()).unwrap();
        let active_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_contacts WHERE deleted = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let deleted_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_contacts WHERE deleted = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_count, 3);
        assert_eq!(deleted_count, 1);
    }

    #[tokio::test]
    async fn bootstrap_contacts_uses_default_page_size_and_sets_sync_state() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();
        let tmp = tempdir().unwrap();
        let store = PimStore::new(tmp.path().join("contacts.db")).unwrap();

        Mock::given(method("GET"))
            .and(path("/contacts/v4"))
            .and(query_param("Page", "0"))
            .and(query_param(
                "PageSize",
                DEFAULT_CONTACTS_PAGE_SIZE.to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Contacts": [{
                    "ID": "contact-1",
                    "Name": "Alice",
                    "UID": "uid-contact-1",
                    "Size": 10,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4/contact-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(full_contact_response("contact-1", "Alice")),
            )
            .mount(&server)
            .await;

        let summary = bootstrap_contacts(&client, &store, 0).await.unwrap();
        assert_eq!(summary.page_size, DEFAULT_CONTACTS_PAGE_SIZE);
        assert_eq!(summary.pages_fetched, 1);
        assert_eq!(summary.contacts_soft_deleted, 0);

        let sync_ms = store
            .get_sync_state_int(CONTACTS_LAST_FULL_SYNC_KEY)
            .unwrap()
            .unwrap();
        assert!(sync_ms > 0);
    }

    #[tokio::test]
    async fn bootstrap_contacts_retries_transient_rate_limit_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let list_calls = Arc::new(AtomicUsize::new(0));
        let list_calls_task = list_calls.clone();

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]);

                let (status, body) = if request.contains("GET /contacts/v4/contact-1 ") {
                    (
                        "200 OK",
                        full_contact_response("contact-1", "Alice").to_string(),
                    )
                } else if request.contains("GET /contacts/v4?") {
                    let call = list_calls_task.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        (
                            "429 Too Many Requests",
                            serde_json::json!({
                                "Code": 429,
                                "Error": "rate limit"
                            })
                            .to_string(),
                        )
                    } else {
                        (
                            "200 OK",
                            serde_json::json!({
                                "Code": 1000,
                                "Total": 1,
                                "Contacts": [{
                                    "ID": "contact-1",
                                    "Name": "Alice",
                                    "UID": "uid-contact-1",
                                    "Size": 10,
                                    "CreateTime": 1700000000,
                                    "ModifyTime": 1700000001
                                }]
                            })
                            .to_string(),
                        )
                    }
                } else {
                    panic!("unexpected request: {request}");
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: 0\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let tmp = tempdir().unwrap();
        let store = PimStore::new(tmp.path().join("contacts.db")).unwrap();

        let summary = bootstrap_contacts(&client, &store, 2).await.unwrap();
        assert_eq!(summary.contacts_upserted, 1);
        assert_eq!(summary.contacts_seen, 1);
        assert_eq!(list_calls.load(Ordering::SeqCst), 2);

        server.await.unwrap();
    }
}
