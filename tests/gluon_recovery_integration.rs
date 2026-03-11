use std::collections::HashMap;
use std::fs;
use std::path::Path;

use openproton_bridge::imap::gluon_txn::{GluonTxnError, GluonTxnManager};
use openproton_bridge::imap::store::{GluonStore, MessageStore};
use openproton_bridge::imap::ImapError;
use serde_json::json;

#[path = "gluon_db_support.rs"]
mod gluon_db_support;

fn make_account_map(account_id: &str, storage_user_id: &str) -> HashMap<String, String> {
    HashMap::from([(account_id.to_string(), storage_user_id.to_string())])
}

fn read_sqlite_index_payload(db_path: &Path) -> serde_json::Value {
    gluon_db_support::read_legacy_index_payload(db_path)
}

fn build_sqlite_index_db_bytes(index_payload: &serde_json::Value) -> Vec<u8> {
    gluon_db_support::build_db_bytes_from_legacy_index_payload(index_payload)
}

#[tokio::test]
async fn be031_recovery_startup_replays_pending_txn_for_sqlite_index_and_blob() {
    let temp = tempfile::tempdir().expect("tempdir");

    let manager = GluonTxnManager::new(temp.path()).expect("txn manager");
    let mut txn = manager.begin("user-1").expect("begin txn");

    let index_payload = json!({
        "version": 1,
        "next_blob_id": 2,
        "mailboxes": {
            "INBOX": {
                "uid_validity": 123,
                "next_uid": 2,
                "proton_to_uid": { "msg-1": 1 },
                "uid_to_proton": { "1": "msg-1" },
                "metadata": {},
                "flags": {},
                "uid_order": [1],
                "mod_seq": 1,
                "uid_to_blob": { "1": "00000001.msg" }
            }
        }
    });

    txn.stage_write(
        "backend/db/user-1.db",
        build_sqlite_index_db_bytes(&index_payload),
    )
    .expect("stage sqlite index db");
    txn.stage_write(
        "backend/store/user-1/00000001.msg",
        b"From: recover\\r\\n\\r\\nbody",
    )
    .expect("stage blob");

    let err = txn.commit_with_injected_failure(1).unwrap_err();
    assert!(matches!(err, GluonTxnError::InjectedFailure { applied } if applied == 1));

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("startup recovery should succeed");

    let mailbox = "account-1::INBOX";
    assert_eq!(store.list_uids(mailbox).await.expect("list uids"), vec![1]);
    assert_eq!(
        store.get_uid(mailbox, "msg-1").await.expect("lookup uid"),
        Some(1)
    );
    assert_eq!(
        store
            .get_rfc822(mailbox, 1)
            .await
            .expect("read recovered blob")
            .expect("blob exists"),
        b"From: recover\\r\\n\\r\\nbody".to_vec()
    );

    assert_eq!(
        manager
            .pending_transaction_count("user-1")
            .expect("pending txns"),
        0,
        "startup should clear pending transaction journal"
    );
}

#[test]
fn be031_recovery_startup_fails_on_unrecoverable_pending_journal() {
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
        Ok(_) => panic!("startup should fail on unrecoverable txn journal"),
        Err(err) => err,
    };

    match err {
        ImapError::GluonCorruption { path, reason } => {
            assert!(path.ends_with(".gluon-txn"));
            assert!(
                reason.contains("recover pending gluon transactions"),
                "unexpected recovery failure reason: {reason}"
            );
        }
        other => panic!("expected GluonCorruption, got: {other}"),
    }
}

#[tokio::test]
async fn be031_recovery_flags_pending_txn_after_cache_move_and_recovers_after_rollback() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("cache-source");
    let target_root = temp.path().join("cache-target");
    let mailbox = "account-9::INBOX";

    let source_store =
        GluonStore::new(source_root.clone(), make_account_map("account-9", "user-9"))
            .expect("create source store");
    let uid1 = source_store
        .store_metadata(
            mailbox,
            "msg-1",
            openproton_bridge::api::types::MessageMetadata {
                id: "msg-1".to_string(),
                address_id: "addr-1".to_string(),
                label_ids: vec!["0".to_string()],
                external_id: None,
                subject: "seed".to_string(),
                sender: openproton_bridge::api::types::EmailAddress {
                    name: "Seed".to_string(),
                    address: "seed@proton.me".to_string(),
                },
                to_list: vec![],
                cc_list: vec![],
                bcc_list: vec![],
                reply_tos: vec![],
                flags: 0,
                time: 1_700_000_000,
                size: 100,
                unread: 1,
                is_replied: 0,
                is_replied_all: 0,
                is_forwarded: 0,
                num_attachments: 0,
            },
        )
        .await
        .expect("insert msg-1");
    assert_eq!(uid1, 1);
    source_store
        .store_rfc822(mailbox, uid1, b"From: seed\\r\\n\\r\\nbody-1".to_vec())
        .await
        .expect("store blob 1");

    let source_db_path = source_root.join("backend/db/user-9.db");
    let mut index = read_sqlite_index_payload(&source_db_path);
    let inbox = index
        .get_mut("mailboxes")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|mailboxes| mailboxes.get_mut("INBOX"))
        .expect("inbox index");

    inbox
        .get_mut("uid_order")
        .and_then(serde_json::Value::as_array_mut)
        .expect("uid_order")
        .push(json!(2));
    inbox
        .get_mut("proton_to_uid")
        .and_then(serde_json::Value::as_object_mut)
        .expect("proton_to_uid")
        .insert("msg-2".to_string(), json!(2));
    inbox
        .get_mut("uid_to_proton")
        .and_then(serde_json::Value::as_object_mut)
        .expect("uid_to_proton")
        .insert("2".to_string(), json!("msg-2"));
    inbox
        .get_mut("uid_to_blob")
        .and_then(serde_json::Value::as_object_mut)
        .expect("uid_to_blob")
        .insert("2".to_string(), json!("00000002.msg"));
    inbox
        .get_mut("next_uid")
        .expect("next_uid")
        .clone_from(&json!(3));

    let manager = GluonTxnManager::new(&source_root).expect("txn manager");
    let mut txn = manager.begin("user-9").expect("begin txn");
    txn.stage_write("backend/db/user-9.db", build_sqlite_index_db_bytes(&index))
        .expect("stage updated sqlite index db");
    txn.stage_write(
        "backend/store/user-9/00000002.msg",
        b"From: moved\\r\\n\\r\\nbody-2",
    )
    .expect("stage blob 2");
    let err = txn.commit_with_injected_failure(1).unwrap_err();
    assert!(matches!(err, GluonTxnError::InjectedFailure { applied } if applied == 1));

    fs::rename(&source_root, &target_root).expect("move cache root with pending txn");

    let moved_startup_err =
        match GluonStore::new(target_root.clone(), make_account_map("account-9", "user-9")) {
            Ok(_) => panic!("startup should fail when moved cache contains unresolved txn paths"),
            Err(err) => err,
        };
    match moved_startup_err {
        ImapError::GluonCorruption { reason, .. } => {
            assert!(
                reason.contains("neither staged nor target file exists"),
                "unexpected startup error after move with pending txn: {reason}"
            );
        }
        other => panic!("expected GluonCorruption after move with pending txn, got: {other}"),
    }

    fs::rename(&target_root, &source_root).expect("rollback cache move to original root");

    let recovered_store =
        GluonStore::new(source_root.clone(), make_account_map("account-9", "user-9"))
            .expect("startup should recover once original paths are restored");
    assert_eq!(
        recovered_store
            .list_uids(mailbox)
            .await
            .expect("list recovered uids"),
        vec![1, 2]
    );
    assert_eq!(
        recovered_store
            .get_rfc822(mailbox, 2)
            .await
            .expect("read recovered uid2")
            .expect("uid2 blob exists"),
        b"From: moved\\r\\n\\r\\nbody-2".to_vec()
    );

    fs::rename(&source_root, &target_root).expect("move clean cache root");
    let moved_clean_store =
        GluonStore::new(target_root.clone(), make_account_map("account-9", "user-9"))
            .expect("clean cache root should load after rollback recovery");
    assert_eq!(
        moved_clean_store
            .list_uids(mailbox)
            .await
            .expect("list moved clean uids"),
        vec![1, 2]
    );
    assert_eq!(
        GluonTxnManager::new(&target_root)
            .expect("txn manager target")
            .pending_transaction_count("user-9")
            .expect("pending after rollback recovery"),
        0
    );
}
