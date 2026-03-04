use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use openproton_bridge::imap::store::{GluonStore, MessageStore};
use serde_json::json;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn make_account_map(account_id: &str, storage_user_id: &str) -> HashMap<String, String> {
    HashMap::from([(account_id.to_string(), storage_user_id.to_string())])
}

#[tokio::test]
async fn be024_reads_fixture_message_blob_without_index() {
    let fixture = repo_root().join(
        "tests/fixtures/proton_profile_gluon_sanitized/backend/store/user-redacted/00000001.msg",
    );
    let expected = fs::read(&fixture).expect("read fixture blob");

    let temp = tempfile::tempdir().expect("tempdir");
    let account_store = temp
        .path()
        .join("backend")
        .join("store")
        .join("user-redacted");
    fs::create_dir_all(&account_store).expect("create account store");
    fs::copy(&fixture, account_store.join("00000001.msg")).expect("copy fixture blob");

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-redacted"),
    )
    .expect("create gluon store");

    let mailbox = "account-1::INBOX";
    assert_eq!(store.list_uids(mailbox).await.expect("list uids"), vec![1]);
    assert_eq!(
        store
            .get_rfc822(mailbox, 1)
            .await
            .expect("get rfc822 from fixture"),
        Some(expected)
    );

    let status = store.mailbox_status(mailbox).await.expect("status");
    assert_eq!(status.exists, 1);
    assert_eq!(status.next_uid, 2);
}

#[tokio::test]
async fn be024_reads_uid_maps_metadata_flags_and_snapshot_from_index() {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_store = temp.path().join("backend/store/user-42");
    let account_db = temp.path().join("backend/db/user-42.db");
    fs::create_dir_all(&account_store).expect("create account store dir");
    fs::create_dir_all(account_db.parent().expect("db parent")).expect("create db dir");

    let message = b"From: alice@example.invalid\r\nSubject: indexed\r\n\r\nbody".to_vec();
    fs::write(account_store.join("00000009.msg"), &message).expect("write message blob");

    let index_payload = json!({
        "version": 1,
        "next_blob_id": 10,
        "mailboxes": {
            "INBOX": {
                "uid_validity": 42,
                "next_uid": 10,
                "proton_to_uid": {"msg-9": 9},
                "uid_to_proton": {"9": "msg-9"},
                "metadata": {
                    "9": {
                        "ID": "msg-9",
                        "AddressID": "addr-1",
                        "LabelIDs": ["0"],
                        "Subject": "Indexed subject",
                        "Sender": {
                            "Name": "Alice",
                            "Address": "alice@proton.me"
                        },
                        "ToList": [],
                        "CCList": [],
                        "BCCList": [],
                        "Time": 1700000090,
                        "Size": 123,
                        "Unread": 0,
                        "NumAttachments": 0
                    }
                },
                "flags": {"9": ["\\Seen", "\\Flagged"]},
                "uid_order": [9],
                "mod_seq": 7,
                "uid_to_blob": {"9": "00000009.msg"}
            }
        }
    });
    let conn = rusqlite::Connection::open(&account_db).expect("open sqlite db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS openproton_mailbox_index (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            payload BLOB NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );",
    )
    .expect("create sqlite index table");
    conn.execute(
        "INSERT OR REPLACE INTO openproton_mailbox_index (id, payload, updated_at_ms)
         VALUES (1, ?1, ?2)",
        rusqlite::params![
            serde_json::to_vec_pretty(&index_payload).expect("serialize index"),
            1_700_000_000_000_i64
        ],
    )
    .expect("insert sqlite index row");

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-42", "user-42"),
    )
    .expect("create gluon store");

    let mailbox = "account-42::INBOX";
    assert_eq!(store.list_uids(mailbox).await.expect("list uids"), vec![9]);
    assert_eq!(
        store.get_uid(mailbox, "msg-9").await.expect("get uid"),
        Some(9)
    );
    assert_eq!(
        store
            .get_proton_id(mailbox, 9)
            .await
            .expect("get proton id"),
        Some("msg-9".to_string())
    );

    let meta = store
        .get_metadata(mailbox, 9)
        .await
        .expect("get metadata")
        .expect("metadata present");
    assert_eq!(meta.subject, "Indexed subject");

    let flags = store.get_flags(mailbox, 9).await.expect("get flags");
    assert_eq!(flags, vec!["\\Seen".to_string(), "\\Flagged".to_string()]);
    assert_eq!(
        store.get_rfc822(mailbox, 9).await.expect("get rfc822"),
        Some(message)
    );

    let status = store.mailbox_status(mailbox).await.expect("status");
    assert_eq!(status.uid_validity, 42);
    assert_eq!(status.next_uid, 10);
    assert_eq!(status.exists, 1);
    assert_eq!(status.unseen, 0);

    let snapshot = store.mailbox_snapshot(mailbox).await.expect("snapshot");
    assert_eq!(snapshot.exists, 1);
    assert_eq!(snapshot.mod_seq, 7);
}
