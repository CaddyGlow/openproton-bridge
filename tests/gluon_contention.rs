use std::collections::HashMap;

use openproton_bridge::api::types::{EmailAddress, MessageMetadata};
use openproton_bridge::imap::store::{GluonStore, MessageStore};

fn make_account_map(account_id: &str, storage_user_id: &str) -> HashMap<String, String> {
    HashMap::from([(account_id.to_string(), storage_user_id.to_string())])
}

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
        size: 100,
        unread: 1,
        is_replied: 0,
        is_replied_all: 0,
        is_forwarded: 0,
        num_attachments: 0,
    }
}

#[tokio::test]
async fn be030_cross_instance_same_account_writers_do_not_clobber_uid_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_map = make_account_map("account-1", "user-1");
    let mailbox = "account-1::INBOX";

    let store_a = GluonStore::new(temp.path().to_path_buf(), account_map.clone()).expect("store a");
    let store_b = GluonStore::new(temp.path().to_path_buf(), account_map).expect("store b");

    // Prime store B with an empty cached state, simulating a long-lived parallel worker.
    assert_eq!(
        store_b.list_uids(mailbox).await.expect("prime"),
        Vec::<u32>::new()
    );

    let uid1 = store_a
        .store_metadata(mailbox, "msg-1", make_meta("msg-1"))
        .await
        .expect("write via store a");
    assert_eq!(uid1, 1);

    let uid2 = store_b
        .store_metadata(mailbox, "msg-2", make_meta("msg-2"))
        .await
        .expect("write via store b");
    assert_eq!(uid2, 2, "second writer must observe latest uid state");

    let reloaded = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("reload");

    assert_eq!(
        reloaded
            .list_uids(mailbox)
            .await
            .expect("uids after writes"),
        vec![1, 2],
        "parallel writers must preserve both messages"
    );
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-1").await.expect("uid msg-1"),
        Some(1)
    );
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-2").await.expect("uid msg-2"),
        Some(2)
    );
}
