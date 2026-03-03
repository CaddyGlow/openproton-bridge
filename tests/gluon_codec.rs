use std::fs;
use std::path::{Path, PathBuf};

use openproton_bridge::imap::gluon_codec::{
    decode_file, detect_family, encode, write_file, GluonCodecError, GluonFileFamily,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_fixture_json(path: &Path) -> Value {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("failed to parse fixture {} as JSON: {err}", path.display()))
}

fn manifest_fixture_entries() -> Vec<(PathBuf, GluonFileFamily, Option<String>)> {
    let root = repo_root();
    let manifest_path = root.join("tests/fixtures/gluon_manifest.json");
    let manifest = read_fixture_json(&manifest_path);
    let users = manifest
        .get("users")
        .and_then(Value::as_array)
        .expect("manifest users[] is required");

    let mut entries = Vec::new();

    for user in users {
        let user_obj = user.as_object().expect("users[] entries must be objects");
        let expected_email = user_obj
            .get("expected_email")
            .and_then(Value::as_str)
            .expect("users[].expected_email is required")
            .to_string();

        let sync = user_obj
            .get("sync_state")
            .and_then(Value::as_object)
            .expect("users[].sync_state must be an object");
        let stable_sync = sync
            .get("stable_path")
            .and_then(Value::as_str)
            .expect("users[].sync_state.stable_path is required");
        let tmp_sync = sync
            .get("tmp_path")
            .and_then(Value::as_str)
            .expect("users[].sync_state.tmp_path is required");

        entries.push((
            root.join(stable_sync),
            GluonFileFamily::ImapSyncStateStable,
            Some(expected_email.clone()),
        ));
        entries.push((
            root.join(tmp_sync),
            GluonFileFamily::ImapSyncStateTmp,
            Some(expected_email.clone()),
        ));

        let storage = user_obj
            .get("storage")
            .and_then(Value::as_object)
            .expect("users[].storage must be an object");

        let primary_db = storage
            .get("primary_db")
            .and_then(Value::as_str)
            .expect("users[].storage.primary_db is required");
        let wal = storage
            .get("wal")
            .and_then(Value::as_str)
            .expect("users[].storage.wal is required");
        let shm = storage
            .get("shm")
            .and_then(Value::as_str)
            .expect("users[].storage.shm is required");

        entries.push((
            root.join(primary_db),
            GluonFileFamily::SqlitePrimaryDb,
            None,
        ));
        entries.push((root.join(wal), GluonFileFamily::SqliteWalSidecar, None));
        entries.push((root.join(shm), GluonFileFamily::SqliteShmSidecar, None));

        for deferred in user_obj
            .get("deferred_delete")
            .and_then(Value::as_array)
            .expect("users[].deferred_delete[] is required")
        {
            let rel = deferred
                .as_str()
                .expect("users[].deferred_delete[] entries must be strings");
            entries.push((root.join(rel), GluonFileFamily::DeferredDeletePool, None));
        }

        let mailboxes = user_obj
            .get("mailboxes")
            .and_then(Value::as_array)
            .expect("users[].mailboxes[] is required");
        for mailbox in mailboxes {
            let mailbox_obj = mailbox
                .as_object()
                .expect("users[].mailboxes[] entries must be objects");
            let message_paths = mailbox_obj
                .get("message_paths")
                .and_then(Value::as_array)
                .expect("users[].mailboxes[].message_paths[] is required");
            for message_path in message_paths {
                let rel = message_path
                    .as_str()
                    .expect("users[].mailboxes[].message_paths[] entries must be strings");
                entries.push((root.join(rel), GluonFileFamily::MessageStoreBlob, None));
            }
        }
    }

    entries
}

#[test]
fn be021_decodes_required_file_families_from_be018_manifest() {
    let entries = manifest_fixture_entries();
    assert!(
        !entries.is_empty(),
        "manifest fixture entries must not be empty"
    );

    for (path, expected_family, expected_email) in entries {
        assert!(path.exists(), "fixture path must exist: {}", path.display());

        let detected = detect_family(&path)
            .unwrap_or_else(|| panic!("expected family detection for {}", path.display()));
        assert_eq!(detected, expected_family);

        let decoded = decode_file(&path)
            .unwrap_or_else(|err| panic!("decode failed for {}: {err}", path.display()));
        assert_eq!(decoded.family(), expected_family);

        if matches!(
            expected_family,
            GluonFileFamily::ImapSyncStateStable | GluonFileFamily::ImapSyncStateTmp
        ) {
            let sync = decoded
                .sync_state_json()
                .expect("sync files must decode as JSON");
            let user = sync
                .get("user")
                .and_then(Value::as_str)
                .expect("sync JSON must contain user");
            assert_eq!(Some(user), expected_email.as_deref());
        }
    }
}

#[test]
fn be021_roundtrip_encoding_preserves_fixture_bytes() {
    for (path, _, _) in manifest_fixture_entries() {
        let original = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
        let decoded = decode_file(&path)
            .unwrap_or_else(|err| panic!("decode failed for {}: {err}", path.display()));

        assert_eq!(
            encode(&decoded),
            original,
            "roundtrip mismatch for {}",
            path.display()
        );
    }
}

#[test]
fn be021_rejects_unsupported_family_paths() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("not-a-gluon-family.bin");
    fs::write(&path, b"fixture-bytes").expect("write unsupported fixture");

    let err = decode_file(&path).unwrap_err();
    assert!(matches!(err, GluonCodecError::UnsupportedFamily(p) if p == path));
}

#[test]
fn be021_writer_rejects_path_family_mismatch() {
    let entries = manifest_fixture_entries();
    let message_path = entries
        .iter()
        .find(|(_, family, _)| *family == GluonFileFamily::MessageStoreBlob)
        .map(|(path, _, _)| path.clone())
        .expect("manifest should include a message store blob");

    let decoded = decode_file(&message_path).expect("decode message blob");

    let tmp = tempfile::tempdir().expect("tempdir");
    let mismatch_path = tmp.path().join("backend/db/user-redacted.db");
    fs::create_dir_all(mismatch_path.parent().expect("mismatch parent")).expect("create parent");

    let err = write_file(&mismatch_path, &decoded).unwrap_err();
    assert!(matches!(
        err,
        GluonCodecError::PathFamilyMismatch {
            expected: GluonFileFamily::SqlitePrimaryDb,
            actual: GluonFileFamily::MessageStoreBlob,
            ..
        }
    ));
}
