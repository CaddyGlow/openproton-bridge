use std::collections::HashMap;
use std::fs;

use openproton_bridge::api::types::{EmailAddress, MessageMetadata};
use openproton_bridge::imap::store::new_runtime_message_store;

fn make_meta(id: &str) -> MessageMetadata {
    MessageMetadata {
        id: id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        external_id: None,
        subject: format!("Subject {id}"),
        sender: EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        },
        to_list: vec![],
        cc_list: vec![],
        bcc_list: vec![],
        reply_tos: vec![],
        flags: 0,
        time: 1700000000,
        size: 1024,
        unread: 1,
        is_replied: 0,
        is_replied_all: 0,
        is_forwarded: 0,
        num_attachments: 0,
    }
}

#[tokio::test]
async fn be026_runtime_store_writes_gluon_layout_without_json_mailbox_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_map = HashMap::from([("account-1".to_string(), "user-1".to_string())]);
    let store = new_runtime_message_store(temp.path().to_path_buf(), account_map)
        .expect("create runtime message store");
    let mailbox = "account-1::INBOX";

    let uid = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1"))
        .await
        .expect("store metadata");
    assert_eq!(uid, 1);
    store
        .store_rfc822(mailbox, uid, b"From: alice\r\n\r\nhello".to_vec())
        .await
        .expect("store rfc822");

    let account_store_dir = temp.path().join("backend").join("store").join("user-1");
    let account_db_path = temp.path().join("backend").join("db").join("user-1.db");
    assert!(
        account_db_path.exists(),
        "runtime store must write sqlite mailbox index data"
    );
    assert!(
        account_store_dir.join("00000001.msg").exists(),
        "runtime store must write gluon message blobs"
    );
    let conn = rusqlite::Connection::open(&account_db_path).expect("open sqlite db");
    let row_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM openproton_mailboxes", [], |row| {
            row.get(0)
        })
        .expect("query sqlite mailbox row count");
    assert_eq!(row_count, 1);

    let root_json_files = fs::read_dir(temp.path())
        .expect("read runtime store root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    assert!(
        root_json_files.is_empty(),
        "runtime store root should not contain JSON mailbox files: {root_json_files:?}"
    );
}

fn is_cfg_test_guarded(source: &str, marker: &str) -> bool {
    let Some(index) = source.find(marker) else {
        return false;
    };
    let prefix = &source[..index];
    let mut lines = prefix.lines().rev();
    let previous_non_empty = lines.find(|line| !line.trim().is_empty());
    matches!(previous_non_empty, Some(line) if line.trim() == "#[cfg(test)]")
}

#[test]
fn be028_persistent_json_store_paths_are_test_only() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let store_src = fs::read_to_string(root.join("src/imap/store.rs")).expect("read store.rs");

    assert!(
        is_cfg_test_guarded(&store_src, "pub struct PersistentStore"),
        "PersistentStore must be cfg(test)-guarded in src/imap/store.rs"
    );
    assert!(
        is_cfg_test_guarded(&store_src, "impl PersistentStore"),
        "PersistentStore impl must be cfg(test)-guarded in src/imap/store.rs"
    );
    assert!(
        is_cfg_test_guarded(&store_src, "impl MessageStore for PersistentStore"),
        "MessageStore impl for PersistentStore must be cfg(test)-guarded in src/imap/store.rs"
    );

    let main_src = fs::read_to_string(root.join("src/main.rs")).expect("read main.rs");
    let grpc_src =
        fs::read_to_string(root.join("src/frontend/grpc/mod.rs")).expect("read grpc/mod.rs");
    assert!(
        !main_src.contains("PersistentStore"),
        "main runtime path must not reference PersistentStore"
    );
    assert!(
        !grpc_src.contains("PersistentStore"),
        "grpc runtime path must not reference PersistentStore"
    );
}
