use std::collections::HashMap;

use openproton_bridge::api::types::{EmailAddress, MessageMetadata};
use openproton_bridge::imap::store::{GluonStore, MessageStore};

fn make_meta(id: &str, unread: i32, subject: &str) -> MessageMetadata {
    MessageMetadata {
        id: id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        subject: subject.to_string(),
        sender: EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        },
        to_list: vec![],
        cc_list: vec![],
        bcc_list: vec![],
        time: 1700000000,
        size: 128,
        unread,
        num_attachments: 0,
    }
}

fn make_account_map(account_id: &str, storage_user_id: &str) -> HashMap<String, String> {
    HashMap::from([(account_id.to_string(), storage_user_id.to_string())])
}

#[tokio::test]
async fn be034_gluon_store_persists_mailbox_index_to_sqlite_db() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mailbox = "account-1::INBOX";
    let storage_user_id = "user-1";

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", storage_user_id),
    )
    .expect("create store");

    let uid = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", 1, "subject-1"))
        .await
        .expect("store metadata");
    assert_eq!(uid, 1);

    let db_path = temp
        .path()
        .join("backend")
        .join("db")
        .join(format!("{storage_user_id}.db"));
    assert!(
        db_path.exists(),
        "expected sqlite db at {}",
        db_path.display()
    );

    let conn = rusqlite::Connection::open(&db_path).expect("open sqlite db");
    let row_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM openproton_mailbox_index WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("query sqlite index row count");
    assert_eq!(row_count, 1);
}

#[tokio::test]
async fn be034_gluon_store_reloads_from_sqlite_when_index_json_is_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mailbox = "account-1::INBOX";
    let storage_user_id = "user-1";

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", storage_user_id),
    )
    .expect("create store");

    let uid = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", 0, "subject-from-db"))
        .await
        .expect("store metadata");
    assert_eq!(uid, 1);

    let index_path = temp
        .path()
        .join("backend")
        .join("store")
        .join(storage_user_id)
        .join(".openproton-mailbox-index.json");
    assert!(index_path.exists(), "expected index json before delete");
    std::fs::remove_file(&index_path).expect("remove index json");
    assert!(!index_path.exists(), "index json should be removed");

    let reloaded = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", storage_user_id),
    )
    .expect("reload store");

    assert_eq!(reloaded.list_uids(mailbox).await.expect("list"), vec![1]);
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-1").await.expect("uid"),
        Some(1)
    );
    let metadata = reloaded
        .get_metadata(mailbox, 1)
        .await
        .expect("metadata")
        .expect("metadata exists");
    assert_eq!(metadata.subject, "subject-from-db");
}
