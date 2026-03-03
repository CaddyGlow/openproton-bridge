use std::collections::HashMap;
use std::fs;

use openproton_bridge::api::types::{EmailAddress, MessageMetadata};
use openproton_bridge::imap::store::new_runtime_message_store;

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
        size: 1024,
        unread: 1,
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
    assert!(
        account_store_dir
            .join(".openproton-mailbox-index.json")
            .exists(),
        "runtime store must write a gluon account index"
    );
    assert!(
        account_store_dir.join("00000001.msg").exists(),
        "runtime store must write gluon message blobs"
    );

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
