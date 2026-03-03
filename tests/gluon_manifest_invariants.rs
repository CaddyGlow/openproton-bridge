use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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

fn read_json_object(path: &Path) -> serde_json::Map<String, Value> {
    read_fixture_json(path)
        .as_object()
        .unwrap_or_else(|| panic!("expected JSON object at {}", path.display()))
        .clone()
}

fn required_str<'a>(obj: &'a serde_json::Map<String, Value>, field: &str) -> &'a str {
    obj.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected string field '{field}'"))
}

#[test]
fn be018_gluon_manifest_enforces_user_and_mailbox_invariants() {
    let root = repo_root();
    let manifest_path = root.join("tests/fixtures/gluon_manifest.json");
    assert!(
        manifest_path.exists(),
        "missing BE-018 fixture manifest: {}",
        manifest_path.display()
    );

    let manifest = read_fixture_json(&manifest_path);
    let manifest_obj = manifest
        .as_object()
        .expect("BE-018 fixture manifest must be a JSON object");

    assert_eq!(required_str(manifest_obj, "ticket"), "BE-018");
    assert_eq!(
        required_str(manifest_obj, "fixture_name"),
        "proton_profile_gluon_sanitized"
    );

    let fixture_root_rel = required_str(manifest_obj, "fixture_root");
    let fixture_root = root.join(fixture_root_rel);
    assert!(
        fixture_root.exists(),
        "fixture_root does not exist: {}",
        fixture_root.display()
    );

    let users = manifest_obj
        .get("users")
        .and_then(Value::as_array)
        .expect("manifest must define users[]");
    assert!(!users.is_empty(), "users[] must not be empty");

    let mut user_ids = BTreeSet::new();
    let mut all_message_paths = BTreeSet::new();

    for user in users {
        let user_obj = user
            .as_object()
            .expect("users[] entries must be JSON objects");
        let user_id = required_str(user_obj, "user_id");
        assert!(!user_id.is_empty(), "users[].user_id must not be empty");
        assert!(
            user_ids.insert(user_id.to_owned()),
            "users[].user_id must be unique"
        );

        let expected_email = required_str(user_obj, "expected_email");
        assert!(
            expected_email.ends_with(".invalid"),
            "expected_email should remain sanitized"
        );

        let sync = user_obj
            .get("sync_state")
            .and_then(Value::as_object)
            .expect("users[].sync_state must be an object");
        let stable_sync_rel = required_str(sync, "stable_path");
        let tmp_sync_rel = required_str(sync, "tmp_path");

        let stable_sync_abs = root.join(stable_sync_rel);
        let tmp_sync_abs = root.join(tmp_sync_rel);
        assert!(
            stable_sync_abs.exists(),
            "stable sync state file is missing: {}",
            stable_sync_abs.display()
        );
        assert!(
            tmp_sync_abs.exists(),
            "temporary sync state file is missing: {}",
            tmp_sync_abs.display()
        );

        let stable_sync = read_json_object(&stable_sync_abs);
        let tmp_sync = read_json_object(&tmp_sync_abs);
        assert_eq!(
            stable_sync.get("user").and_then(Value::as_str),
            Some(expected_email),
            "stable sync user must match users[].expected_email"
        );
        assert_eq!(
            tmp_sync.get("user").and_then(Value::as_str),
            Some(expected_email),
            "tmp sync user must match users[].expected_email"
        );

        let storage = user_obj
            .get("storage")
            .and_then(Value::as_object)
            .expect("users[].storage must be an object");

        let store_dir_rel = required_str(storage, "store_dir");
        let primary_db_rel = required_str(storage, "primary_db");
        let wal_rel = required_str(storage, "wal");
        let shm_rel = required_str(storage, "shm");

        let store_dir_abs = root.join(store_dir_rel);
        let primary_db_abs = root.join(primary_db_rel);
        let wal_abs = root.join(wal_rel);
        let shm_abs = root.join(shm_rel);

        assert!(
            store_dir_abs.is_dir(),
            "users[].storage.store_dir must be an existing directory: {}",
            store_dir_abs.display()
        );
        assert!(
            primary_db_abs.is_file(),
            "missing primary db file: {}",
            primary_db_abs.display()
        );
        assert!(wal_abs.is_file(), "missing wal file: {}", wal_abs.display());
        assert!(shm_abs.is_file(), "missing shm file: {}", shm_abs.display());

        let expected_db_name = format!("{user_id}.db");
        assert_eq!(
            primary_db_abs.file_name().and_then(|n| n.to_str()),
            Some(expected_db_name.as_str()),
            "users[].storage.primary_db must match users[].user_id naming"
        );

        let deferred_delete = user_obj
            .get("deferred_delete")
            .and_then(Value::as_array)
            .expect("users[].deferred_delete must be an array");
        assert!(
            !deferred_delete.is_empty(),
            "users[].deferred_delete must list at least one fixture path"
        );
        for entry in deferred_delete {
            let rel = entry
                .as_str()
                .expect("users[].deferred_delete[] entries must be strings");
            let abs = root.join(rel);
            assert!(
                abs.is_file(),
                "missing deferred_delete artifact: {}",
                abs.display()
            );
            let name = abs.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            assert!(
                name.starts_with(&format!("{user_id}.db.")),
                "deferred_delete artifact should include <user_id>.db.<suffix>: {name}"
            );
        }

        let mailboxes = user_obj
            .get("mailboxes")
            .and_then(Value::as_array)
            .expect("users[].mailboxes must be an array");
        assert!(
            !mailboxes.is_empty(),
            "users[].mailboxes must include at least one mailbox invariant"
        );

        for mailbox in mailboxes {
            let mailbox_obj = mailbox
                .as_object()
                .expect("users[].mailboxes[] entries must be objects");
            let mailbox_id = required_str(mailbox_obj, "mailbox_id");
            assert!(
                !mailbox_id.is_empty(),
                "users[].mailboxes[].mailbox_id must not be empty"
            );

            let message_paths = mailbox_obj
                .get("message_paths")
                .and_then(Value::as_array)
                .expect("users[].mailboxes[].message_paths must be an array");
            assert!(
                !message_paths.is_empty(),
                "users[].mailboxes[].message_paths must not be empty"
            );

            let expected_count = mailbox_obj
                .get("expected_message_count")
                .and_then(Value::as_u64)
                .expect("users[].mailboxes[].expected_message_count is required")
                as usize;
            assert_eq!(
                expected_count,
                message_paths.len(),
                "expected_message_count must equal number of declared message_paths"
            );

            for path in message_paths {
                let rel = path
                    .as_str()
                    .expect("users[].mailboxes[].message_paths[] entries must be strings");
                let abs = root.join(rel);
                assert!(
                    abs.is_file(),
                    "declared message path is missing: {}",
                    abs.display()
                );
                assert!(
                    abs.starts_with(&store_dir_abs),
                    "message path must be inside users[].storage.store_dir: {}",
                    abs.display()
                );
                assert!(
                    all_message_paths.insert(rel.to_owned()),
                    "message path appears more than once across mailbox invariants: {rel}"
                );

                let body = fs::read_to_string(&abs).unwrap_or_else(|err| {
                    panic!("failed to read message fixture {}: {err}", abs.display())
                });
                assert!(
                    body.contains(&format!("From: {expected_email}")),
                    "message fixture should contain sanitized From header"
                );
                assert!(
                    body.contains(&format!("To: {expected_email}")),
                    "message fixture should contain sanitized To header"
                );
            }
        }
    }

    assert!(
        !all_message_paths.is_empty(),
        "manifest must declare at least one message path across all mailboxes"
    );
}
