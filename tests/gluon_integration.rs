use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use openproton_bridge::api::types::{ApiMode, EmailAddress, MessageMetadata, Session};
use openproton_bridge::bridge::events::VaultCheckpointStore;
use openproton_bridge::bridge::types::{
    AccountId, CheckpointSyncState, EventCheckpoint, EventCheckpointStore,
};
use openproton_bridge::imap::store::{GluonStore, MessageStore};
use openproton_bridge::vault;
use rusqlite::OptionalExtension;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn make_account_map(account_id: &str, storage_user_id: &str) -> HashMap<String, String> {
    HashMap::from([(account_id.to_string(), storage_user_id.to_string())])
}

fn make_meta(id: &str, subject: &str, unread: i32) -> MessageMetadata {
    MessageMetadata {
        id: id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        external_id: None,
        subject: subject.to_string(),
        sender: EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        },
        to_list: vec![],
        cc_list: vec![],
        bcc_list: vec![],
        reply_tos: vec![],
        flags: 0,
        time: 1_700_000_000,
        size: 256,
        unread,
        is_replied: 0,
        is_replied_all: 0,
        is_forwarded: 0,
        num_attachments: 0,
    }
}

fn copy_dir_recursive(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create target dir");
    for entry in fs::read_dir(source).expect("read source dir") {
        let entry = entry.expect("read source dir entry");
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let kind = entry.file_type().expect("read source file type");
        if kind.is_dir() {
            copy_dir_recursive(&source_path, &target_path);
        } else if kind.is_file() {
            fs::copy(&source_path, &target_path).unwrap_or_else(|err| {
                panic!(
                    "copy {} -> {} failed: {err}",
                    source_path.display(),
                    target_path.display()
                )
            });
        }
    }
}

fn write_file_credential_store_config(dir: &Path) {
    fs::write(
        dir.join("credential_store.toml"),
        r#"backend = "file"
[file]
path = "vault.key"
"#,
    )
    .expect("write credential_store.toml");
}

fn load_index_payload_from_db(root: &Path, storage_user_id: &str) -> Value {
    let db_path = root
        .join("backend")
        .join("db")
        .join(format!("{storage_user_id}.db"));
    let conn = rusqlite::Connection::open(&db_path)
        .unwrap_or_else(|err| panic!("open sqlite db {} failed: {err}", db_path.display()));
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM openproton_mailbox_index WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("query sqlite index row")
        .expect("sqlite index row should exist");
    serde_json::from_slice(&payload).expect("parse sqlite index payload")
}

#[tokio::test]
async fn be031_startup_recovers_fixture_layout_without_mutating_sync_sidecars() {
    let fixture_root = repo_root().join("tests/fixtures/proton_profile_gluon_sanitized");
    let fixture_blob = fixture_root.join("backend/store/user-redacted/00000001.msg");
    let fixture_sync = fixture_root.join("sync-user-redacted");

    let temp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&fixture_root, temp.path());

    let expected_blob = fs::read(&fixture_blob).expect("read fixture blob");
    let expected_sync = fs::read(&fixture_sync).expect("read fixture sync sidecar");

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
            .expect("get fixture blob"),
        Some(expected_blob)
    );

    let synthesized_index = load_index_payload_from_db(temp.path(), "user-redacted");
    assert!(
        synthesized_index
            .get("mailboxes")
            .and_then(Value::as_object)
            .and_then(|mailboxes| mailboxes.get("INBOX"))
            .is_some(),
        "startup should synthesize sqlite index from discovered blobs"
    );
    assert_eq!(
        fs::read(temp.path().join("sync-user-redacted")).expect("read copied sync sidecar"),
        expected_sync,
        "startup parity must preserve sync sidecar payload"
    );
}

#[tokio::test]
async fn be031_sync_restart_preserves_uid_and_modseq_continuity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mailbox = "account-1::INBOX";

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("create store");

    let uid1 = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", "initial", 1))
        .await
        .expect("insert msg-1");
    assert_eq!(uid1, 1);
    store
        .store_rfc822(mailbox, uid1, b"From: alice\\r\\n\\r\\none".to_vec())
        .await
        .expect("store rfc822 uid1");

    let snapshot_before = store
        .mailbox_snapshot(mailbox)
        .await
        .expect("snapshot before");

    let same_uid = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", "updated", 0))
        .await
        .expect("update msg-1");
    assert_eq!(same_uid, uid1, "sync update must preserve UID mapping");
    store
        .set_flags(mailbox, uid1, vec!["\\Seen".to_string()])
        .await
        .expect("set seen flag");

    let uid2 = store
        .store_metadata(mailbox, "msg-2", make_meta("msg-2", "second", 1))
        .await
        .expect("insert msg-2");
    assert_eq!(uid2, 2);
    store
        .store_rfc822(mailbox, uid2, b"From: bob\\r\\n\\r\\ntwo".to_vec())
        .await
        .expect("store rfc822 uid2");

    let snapshot_after = store
        .mailbox_snapshot(mailbox)
        .await
        .expect("snapshot after");
    assert!(snapshot_after.mod_seq > snapshot_before.mod_seq);
    assert_eq!(snapshot_after.exists, 2);

    let reloaded = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("reload store");

    assert_eq!(
        reloaded.list_uids(mailbox).await.expect("list uids"),
        vec![1, 2]
    );
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-1").await.expect("uid msg-1"),
        Some(1)
    );
    assert_eq!(
        reloaded.get_uid(mailbox, "msg-2").await.expect("uid msg-2"),
        Some(2)
    );

    let updated = reloaded
        .get_metadata(mailbox, 1)
        .await
        .expect("metadata msg-1")
        .expect("metadata exists");
    assert_eq!(updated.subject, "updated");

    let status = reloaded.mailbox_status(mailbox).await.expect("status");
    assert_eq!(status.exists, 2);
    assert_eq!(status.next_uid, 3);
    assert_eq!(status.unseen, 1);

    let uid3 = reloaded
        .store_metadata(mailbox, "msg-3", make_meta("msg-3", "third", 1))
        .await
        .expect("insert msg-3 after restart");
    assert_eq!(uid3, 3);

    let reloaded_again = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-1", "user-1"),
    )
    .expect("reload store again");
    assert_eq!(
        reloaded_again
            .list_uids(mailbox)
            .await
            .expect("list final uids"),
        vec![1, 2, 3]
    );
}

#[tokio::test]
async fn be031_delete_removes_blob_and_keeps_restart_state_consistent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mailbox = "account-2::INBOX";

    let store = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-2", "user-2"),
    )
    .expect("create store");

    let uid1 = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", "first", 1))
        .await
        .expect("insert msg-1");
    let uid2 = store
        .store_metadata(mailbox, "msg-2", make_meta("msg-2", "second", 1))
        .await
        .expect("insert msg-2");
    store
        .store_rfc822(mailbox, uid1, b"From: one\\r\\n\\r\\nbody".to_vec())
        .await
        .expect("store uid1");
    store
        .store_rfc822(mailbox, uid2, b"From: two\\r\\n\\r\\nbody".to_vec())
        .await
        .expect("store uid2");

    let account_store = temp.path().join("backend/store/user-2");
    assert!(account_store.join("00000001.msg").exists());
    assert!(account_store.join("00000002.msg").exists());

    store
        .remove_message(mailbox, uid1)
        .await
        .expect("remove uid1");

    assert!(!account_store.join("00000001.msg").exists());
    assert!(account_store.join("00000002.msg").exists());
    assert_eq!(
        store.get_uid(mailbox, "msg-1").await.expect("uid msg-1"),
        None
    );

    let reloaded = GluonStore::new(
        temp.path().to_path_buf(),
        make_account_map("account-2", "user-2"),
    )
    .expect("reload store");

    assert_eq!(
        reloaded.list_uids(mailbox).await.expect("list uids"),
        vec![2]
    );
    assert_eq!(reloaded.get_rfc822(mailbox, 1).await.expect("blob 1"), None);
    assert!(reloaded
        .get_rfc822(mailbox, 2)
        .await
        .expect("blob 2")
        .is_some());

    let status = reloaded.mailbox_status(mailbox).await.expect("status");
    assert_eq!(status.exists, 1);
    assert_eq!(status.next_uid, 3);

    let index = load_index_payload_from_db(temp.path(), "user-2");
    let inbox = index
        .get("mailboxes")
        .and_then(Value::as_object)
        .and_then(|mailboxes| mailboxes.get("INBOX"))
        .expect("inbox entry in index");
    let uid_order = inbox
        .get("uid_order")
        .and_then(Value::as_array)
        .expect("uid_order array");
    assert_eq!(uid_order.len(), 1);
    assert_eq!(uid_order[0].as_u64(), Some(2));
}

#[tokio::test]
async fn be031_cache_move_keeps_store_readable_after_root_relocation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("cache-source");
    let target_root = temp.path().join("cache-target");
    let mailbox = "account-9::INBOX";

    fs::create_dir_all(&source_root).expect("create source root");

    let source_store =
        GluonStore::new(source_root.clone(), make_account_map("account-9", "user-9"))
            .expect("create source store");

    let uid = source_store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1", "before-move", 1))
        .await
        .expect("insert msg-1");
    source_store
        .store_rfc822(mailbox, uid, b"From: source\\r\\n\\r\\nbody".to_vec())
        .await
        .expect("store source blob");

    fs::rename(&source_root, &target_root).expect("move cache root");
    assert!(!source_root.exists(), "source root should be moved away");

    let target_store =
        GluonStore::new(target_root.clone(), make_account_map("account-9", "user-9"))
            .expect("create target store");

    assert_eq!(
        target_store
            .list_uids(mailbox)
            .await
            .expect("list after move"),
        vec![1]
    );
    assert_eq!(
        target_store
            .get_uid(mailbox, "msg-1")
            .await
            .expect("uid after move"),
        Some(1)
    );
    assert_eq!(
        target_store
            .get_rfc822(mailbox, 1)
            .await
            .expect("rfc822 after move")
            .expect("blob after move"),
        b"From: source\\r\\n\\r\\nbody".to_vec()
    );

    let uid2 = target_store
        .store_metadata(mailbox, "msg-2", make_meta("msg-2", "after-move", 1))
        .await
        .expect("insert msg-2 after move");
    assert_eq!(uid2, 2);
    assert!(
        target_root.join("backend/db/user-9.db").exists(),
        "moved root should keep sqlite cache writable"
    );
}

#[test]
fn be031_event_persists_checkpoints_across_restart_and_session_delete() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_file_credential_store_config(temp.path());

    let session = Session {
        uid: "uid-event".to_string(),
        access_token: "access-token".to_string(),
        refresh_token: "refresh-token".to_string(),
        email: "events@example.com".to_string(),
        display_name: "Events".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: Some("key-pass".to_string()),
        bridge_password: Some("bridge-pass".to_string()),
    };
    vault::save_session(&session, temp.path()).expect("save session");

    let account_id = AccountId(session.uid.clone());
    let checkpoint_1 = EventCheckpoint {
        last_event_id: "evt-1".to_string(),
        last_event_ts: Some(1_700_000_010),
        sync_state: Some(CheckpointSyncState::More),
    };

    let store = VaultCheckpointStore::new(temp.path().to_path_buf());
    store
        .save_checkpoint(&account_id, &checkpoint_1)
        .expect("save checkpoint 1");

    let restarted_store = VaultCheckpointStore::new(temp.path().to_path_buf());
    assert_eq!(
        restarted_store
            .load_checkpoint(&account_id)
            .expect("load checkpoint 1"),
        Some(checkpoint_1.clone())
    );

    let checkpoint_2 = EventCheckpoint {
        last_event_id: "evt-2".to_string(),
        last_event_ts: Some(1_700_000_020),
        sync_state: Some(CheckpointSyncState::RefreshResync),
    };
    restarted_store
        .save_checkpoint(&account_id, &checkpoint_2)
        .expect("save checkpoint 2");

    assert_eq!(
        VaultCheckpointStore::new(temp.path().to_path_buf())
            .load_checkpoint(&account_id)
            .expect("load checkpoint 2"),
        Some(checkpoint_2)
    );

    vault::save_split_mode_by_account_id(temp.path(), &session.uid, true).expect("save split mode");
    assert_eq!(
        vault::load_split_mode_by_account_id(temp.path(), &session.uid).expect("load split mode"),
        Some(true)
    );

    vault::remove_session_by_email(temp.path(), &session.email).expect("remove session");
    assert_eq!(
        VaultCheckpointStore::new(temp.path().to_path_buf())
            .load_checkpoint(&account_id)
            .expect("load checkpoint after delete"),
        None,
        "event checkpoint should disappear after account deletion"
    );
}
