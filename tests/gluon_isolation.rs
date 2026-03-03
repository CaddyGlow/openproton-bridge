use std::collections::HashMap;

use openproton_bridge::api::types::{EmailAddress, MessageMetadata};
use openproton_bridge::imap::gluon_lock::GluonLockManager;
use openproton_bridge::imap::store::{GluonStore, MessageStore};

fn make_meta(id: &str) -> MessageMetadata {
    MessageMetadata {
        id: id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        subject: format!("Subject {id}"),
        sender: EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        },
        to_list: vec![],
        cc_list: vec![],
        bcc_list: vec![],
        time: 1700000000,
        size: 100,
        unread: 1,
        num_attachments: 0,
    }
}

#[tokio::test]
async fn be030_lock_contention_is_scoped_per_account() {
    let temp = tempfile::tempdir().expect("tempdir");
    let lock_manager = GluonLockManager::new(temp.path().join(".gluon-locks")).expect("locks");
    let _account_a_lock = lock_manager
        .acquire_writer("user-a")
        .expect("lock account a");

    let account_map = HashMap::from([
        ("account-a".to_string(), "user-a".to_string()),
        ("account-b".to_string(), "user-b".to_string()),
    ]);
    let store = GluonStore::new(temp.path().to_path_buf(), account_map).expect("store");

    let err = store
        .store_metadata("account-a::INBOX", "a-1", make_meta("a-1"))
        .await
        .expect_err("account-a write should fail while lock is held");
    assert!(
        err.to_string().contains("failed to begin gluon txn"),
        "expected lock contention error path, got: {err}"
    );

    let uid_b = store
        .store_metadata("account-b::INBOX", "b-1", make_meta("b-1"))
        .await
        .expect("account-b write should proceed");
    assert_eq!(uid_b, 1);

    assert_eq!(
        store
            .get_uid("account-a::INBOX", "a-1")
            .await
            .expect("uid a lookup"),
        None,
        "failed write in account-a must not leak into account-b or partial state"
    );
    assert_eq!(
        store
            .get_uid("account-b::INBOX", "b-1")
            .await
            .expect("uid b lookup"),
        Some(1)
    );
}
