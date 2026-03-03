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
async fn be025_insert_update_delete_preserve_uid_continuity_across_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mailbox = "account-1::INBOX";

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("create store");

    let uid1 = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", 1, "first"))
        .await
        .expect("insert msg-1");
    let uid2 = store
        .store_metadata(mailbox, "msg-2", make_meta("msg-2", 1, "second"))
        .await
        .expect("insert msg-2");
    assert_eq!(uid1, 1);
    assert_eq!(uid2, 2);

    let uid2_again = store
        .store_metadata(mailbox, "msg-2", make_meta("msg-2", 0, "second-updated"))
        .await
        .expect("update msg-2");
    assert_eq!(uid2_again, uid2);

    store
        .store_rfc822(mailbox, uid2, b"From: second\r\n\r\nbody2".to_vec())
        .await
        .expect("store body for uid2");

    store
        .remove_message(mailbox, uid1)
        .await
        .expect("remove uid1");

    let uid3 = store
        .store_metadata(mailbox, "msg-3", make_meta("msg-3", 1, "third"))
        .await
        .expect("insert msg-3");
    assert_eq!(uid3, 3, "uid continuity must be monotonic and never reused");

    store
        .store_rfc822(mailbox, uid3, b"From: third\r\n\r\nbody3".to_vec())
        .await
        .expect("store body for uid3");

    assert_eq!(
        store.list_uids(mailbox).await.expect("list uids"),
        vec![2, 3]
    );

    let reloaded = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("reload store");

    assert_eq!(reloaded.list_uids(mailbox).await.expect("list"), vec![2, 3]);
    assert_eq!(reloaded.get_uid(mailbox, "msg-1").await.expect("uid"), None);
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-2").await.expect("uid"),
        Some(2)
    );
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-3").await.expect("uid"),
        Some(3)
    );

    let msg2 = reloaded
        .get_metadata(mailbox, 2)
        .await
        .expect("metadata")
        .expect("metadata exists");
    assert_eq!(msg2.subject, "second-updated");

    assert_eq!(
        reloaded
            .get_rfc822(mailbox, 2)
            .await
            .expect("rfc822 uid2")
            .is_some(),
        true
    );
    assert_eq!(
        reloaded
            .get_rfc822(mailbox, 3)
            .await
            .expect("rfc822 uid3")
            .is_some(),
        true
    );

    let status = reloaded.mailbox_status(mailbox).await.expect("status");
    assert_eq!(status.exists, 2);
    assert_eq!(status.next_uid, 4);
}

#[tokio::test]
async fn be025_flag_mutations_are_persisted_and_ordered() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mailbox = "account-2::INBOX";

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-2", "user-2"),
    )
    .expect("create store");

    let uid = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", 1, "flags"))
        .await
        .expect("insert msg-1");
    assert_eq!(uid, 1);

    store
        .set_flags(mailbox, uid, vec!["\\Seen".to_string()])
        .await
        .expect("set flags");
    store
        .add_flags(
            mailbox,
            uid,
            &[
                "\\Flagged".to_string(),
                "\\Seen".to_string(),
                "\\Flagged".to_string(),
            ],
        )
        .await
        .expect("add flags");
    store
        .remove_flags(mailbox, uid, &["\\Seen".to_string()])
        .await
        .expect("remove seen");

    let flags = store.get_flags(mailbox, uid).await.expect("get flags");
    assert_eq!(flags, vec!["\\Flagged".to_string()]);

    let snapshot_before = store
        .mailbox_snapshot(mailbox)
        .await
        .expect("snapshot before");
    assert!(snapshot_before.mod_seq > 0);

    let reloaded = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-2", "user-2"),
    )
    .expect("reload store");

    let flags_after = reloaded
        .get_flags(mailbox, uid)
        .await
        .expect("get flags after reload");
    assert_eq!(flags_after, vec!["\\Flagged".to_string()]);

    let status = reloaded.mailbox_status(mailbox).await.expect("status");
    assert_eq!(status.unseen, 1, "without \\Seen the message is unseen");

    let snapshot_after = reloaded
        .mailbox_snapshot(mailbox)
        .await
        .expect("snapshot after");
    assert!(snapshot_after.mod_seq >= snapshot_before.mod_seq);
}
