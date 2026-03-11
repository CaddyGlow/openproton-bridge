use std::collections::HashMap;
use std::fs;

use openproton_bridge::imap::store::{GluonStore, MessageStore};
use openproton_bridge::imap::ImapError;
use serde_json::json;

#[path = "gluon_db_support.rs"]
mod gluon_db_support;

fn make_account_map(account_id: &str, storage_user_id: &str) -> HashMap<String, String> {
    HashMap::from([(account_id.to_string(), storage_user_id.to_string())])
}

#[test]
fn be029_fails_startup_on_unrecoverable_pending_gluon_txn_artifact() {
    let temp = tempfile::tempdir().expect("tempdir");
    let txndir = temp
        .path()
        .join(".gluon-txn")
        .join("user-1")
        .join("txn-corrupt");
    fs::create_dir_all(&txndir).expect("create txn dir");

    let missing_target = temp.path().join("backend/db/user-1.db");
    let missing_staged = txndir.join("stage-0000.tmp");

    let journal = json!({
        "version": 1,
        "scope": "user-1",
        "entries": [
            {
                "target": missing_target,
                "staged": missing_staged,
                "applied": false
            }
        ]
    });
    fs::write(
        txndir.join("journal.json"),
        serde_json::to_vec_pretty(&journal).expect("serialize journal"),
    )
    .expect("write journal");

    let err = match GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    ) {
        Ok(_) => panic!("startup should fail for unrecoverable pending txn artifact"),
        Err(err) => err,
    };

    match err {
        ImapError::GluonCorruption { path, reason } => {
            assert!(
                path.ends_with(".gluon-txn"),
                "expected corruption path to point to txn root, got: {}",
                path.display()
            );
            assert!(
                reason.contains("recover pending gluon transactions"),
                "expected recovery failure reason, got: {reason}"
            );
        }
        other => panic!("expected GluonCorruption error, got: {other}"),
    }
}

#[tokio::test]
async fn be029_repairs_missing_blob_references_deterministically() {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_store = temp.path().join("backend/store/user-1");
    let account_db = temp.path().join("backend/db/user-1.db");
    fs::create_dir_all(&account_store).expect("create account store");
    fs::create_dir_all(account_db.parent().expect("db parent")).expect("create db dir");

    fs::write(
        account_store.join("00000001.msg"),
        b"From: one\r\n\r\nbody-1",
    )
    .expect("write blob 1");

    let index_payload = json!({
        "version": 1,
        "next_blob_id": 3,
        "mailboxes": {
            "INBOX": {
                "uid_validity": 123,
                "next_uid": 3,
                "proton_to_uid": {
                    "msg-1": 1,
                    "msg-2": 2
                },
                "uid_to_proton": {
                    "1": "msg-1",
                    "2": "msg-2"
                },
                "metadata": {
                    "1": {
                        "ID": "msg-1",
                        "AddressID": "addr-1",
                        "LabelIDs": ["0"],
                        "Subject": "first",
                        "Sender": {
                            "Name": "Alice",
                            "Address": "alice@proton.me"
                        },
                        "ToList": [],
                        "CCList": [],
                        "BCCList": [],
                        "Time": 1700000000,
                        "Size": 100,
                        "Unread": 1,
                        "NumAttachments": 0
                    },
                    "2": {
                        "ID": "msg-2",
                        "AddressID": "addr-1",
                        "LabelIDs": ["0"],
                        "Subject": "second",
                        "Sender": {
                            "Name": "Alice",
                            "Address": "alice@proton.me"
                        },
                        "ToList": [],
                        "CCList": [],
                        "BCCList": [],
                        "Time": 1700000001,
                        "Size": 101,
                        "Unread": 1,
                        "NumAttachments": 0
                    }
                },
                "flags": {
                    "1": ["\\Seen"],
                    "2": ["\\Flagged"]
                },
                "uid_order": [1, 2],
                "mod_seq": 7,
                "uid_to_blob": {
                    "1": "00000001.msg",
                    "2": "00000002.msg"
                }
            }
        }
    });
    gluon_db_support::write_legacy_index_payload(&account_db, &index_payload);

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("create gluon store");

    let mailbox = "account-1::INBOX";
    assert_eq!(
        store
            .list_uids(mailbox)
            .await
            .expect("list uids after repair"),
        vec![1],
        "missing blob uid entries must be pruned deterministically"
    );
    assert_eq!(
        store.get_uid(mailbox, "msg-2").await.expect("uid lookup"),
        None
    );
    assert_eq!(
        store
            .get_proton_id(mailbox, 2)
            .await
            .expect("proton id lookup"),
        None
    );
    assert_eq!(
        store.get_rfc822(mailbox, 2).await.expect("rfc822 lookup"),
        None
    );

    let status = store
        .mailbox_status(mailbox)
        .await
        .expect("status after repair");
    assert_eq!(status.exists, 1);
}
