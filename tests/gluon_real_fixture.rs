use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, SchemaFamily,
    SchemaProbe, StoreBootstrap,
};

const REAL_ARCHIVE_ENV: &str = "OPENPROTON_REAL_GLUON_ARCHIVE";
const REAL_PROFILE_ENV: &str = "OPENPROTON_REAL_GLUON_PROFILE";
const ARCHIVE_GLUON_SUBTREE: &str =
    "Users/rick/Library/Application Support/protonmail/bridge-v3/gluon";
const PROFILE_GLUON_SUBTREE: &str = "gluon";

struct ResolvedGluonRoot {
    root: PathBuf,
    _temp: Option<tempfile::TempDir>,
}

fn extract_real_archive_fixture(archive_path: &Path, output_root: &Path) {
    let status = Command::new("tar")
        .arg("-xf")
        .arg(archive_path)
        .arg("-C")
        .arg(output_root)
        .arg(ARCHIVE_GLUON_SUBTREE)
        .status()
        .unwrap_or_else(|err| panic!("failed to extract {}: {err}", archive_path.display()));
    assert!(
        status.success(),
        "tar extraction failed for {} with status {status}",
        archive_path.display()
    );
}

fn find_upstream_storage_user_ids(gluon_root: &Path) -> Vec<String> {
    let db_dir = gluon_root.join("backend").join("db");
    let mut ids = Vec::new();

    for entry in fs::read_dir(&db_dir)
        .unwrap_or_else(|err| panic!("failed to read db dir {}: {err}", db_dir.display()))
    {
        let entry = entry.expect("read db entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("db") {
            continue;
        }

        let probe = SchemaProbe::inspect(&path)
            .unwrap_or_else(|err| panic!("failed to inspect {}: {err}", path.display()));
        if probe.family != SchemaFamily::UpstreamCore {
            continue;
        }

        let storage_user_id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_else(|| panic!("invalid storage user id path {}", path.display()));
        ids.push(storage_user_id.to_string());
    }

    ids.sort();
    ids
}

fn resolve_real_gluon_root() -> Option<ResolvedGluonRoot> {
    if let Some(profile_path) = env::var_os(REAL_PROFILE_ENV).map(PathBuf::from) {
        let root = profile_path.join(PROFILE_GLUON_SUBTREE);
        return Some(ResolvedGluonRoot { root, _temp: None });
    }

    let archive_path = env::var_os(REAL_ARCHIVE_ENV).map(PathBuf::from)?;
    let temp = tempfile::tempdir().expect("tempdir");
    extract_real_archive_fixture(&archive_path, temp.path());
    Some(ResolvedGluonRoot {
        root: temp.path().join(ARCHIVE_GLUON_SUBTREE),
        _temp: Some(temp),
    })
}

#[test]
fn be029_open_read_only_accepts_real_archive_fixture() {
    let Some(resolved) = resolve_real_gluon_root() else {
        eprintln!(
            "skipping be029 real archive parity test; set {REAL_PROFILE_ENV} or {REAL_ARCHIVE_ENV}"
        );
        return;
    };
    let gluon_root = resolved.root;
    assert!(
        gluon_root.exists(),
        "archive did not contain expected Gluon subtree: {}",
        gluon_root.display()
    );

    let storage_user_ids = find_upstream_storage_user_ids(&gluon_root);
    assert!(
        !storage_user_ids.is_empty(),
        "archive did not contain any upstream-compatible account DBs under {}",
        gluon_root.display()
    );

    for (index, storage_user_id) in storage_user_ids.iter().enumerate() {
        let bootstrap = StoreBootstrap::new(
            CacheLayout::new(&gluon_root),
            CompatibilityTarget::default(),
            vec![AccountBootstrap::new(
                format!("real-account-{index}"),
                storage_user_id,
                GluonKey::try_from_slice(&[0x29; 32]).expect("fixture key"),
            )],
        );
        let store = CompatibleStore::open_read_only(bootstrap).unwrap_or_else(|err| {
            panic!("failed to open real fixture store {storage_user_id}: {err}")
        });

        let probe = store
            .schema_probe(storage_user_id)
            .unwrap_or_else(|err| panic!("failed to probe {storage_user_id}: {err}"));
        assert_eq!(
            probe.family,
            SchemaFamily::UpstreamCore,
            "expected real archive fixture to expose an upstream-compatible DB for {storage_user_id}"
        );
        assert!(
            !probe.mailbox_message_tables().is_empty(),
            "expected mailbox_message tables in real archive fixture for {storage_user_id}"
        );

        let mailboxes = store
            .list_upstream_mailboxes(storage_user_id)
            .unwrap_or_else(|err| panic!("failed to list mailboxes for {storage_user_id}: {err}"));
        assert!(
            !mailboxes.is_empty(),
            "expected at least one mailbox in real archive fixture for {storage_user_id}"
        );
        let deleted = store
            .list_deleted_subscriptions(storage_user_id)
            .unwrap_or_else(|err| {
                panic!("failed to list deleted subscriptions for {storage_user_id}: {err}")
            });
        let mut total_messages = 0usize;
        let mut total_snapshot_messages = 0usize;
        let mut total_existing_blobs = 0usize;

        for mailbox in &mailboxes {
            let listed = store
                .list_upstream_mailbox_messages(storage_user_id, mailbox.internal_id)
                .unwrap_or_else(|err| {
                    panic!(
                        "failed to list messages for {} mailbox {}: {err}",
                        storage_user_id, mailbox.name
                    )
                });
            let snapshot = store
                .mailbox_snapshot(storage_user_id, mailbox.internal_id)
                .unwrap_or_else(|err| {
                    panic!(
                        "failed to read snapshot for {} mailbox {}: {err}",
                        storage_user_id, mailbox.name
                    )
                });

            assert_eq!(
                snapshot.mailbox.internal_id, mailbox.internal_id,
                "snapshot mailbox id should match listed mailbox for {storage_user_id}"
            );
            assert_eq!(
                snapshot.message_count,
                listed.len(),
                "snapshot/listed message counts should match for {} mailbox {}",
                storage_user_id,
                mailbox.name
            );
            assert!(
                snapshot.next_uid >= 1,
                "next uid should be initialized for {} mailbox {}",
                storage_user_id,
                mailbox.name
            );

            total_messages += listed.len();
            total_snapshot_messages += snapshot.messages.len();
            total_existing_blobs += snapshot
                .messages
                .iter()
                .filter(|msg| msg.blob_exists)
                .count();
        }
        assert!(
            total_messages > 0,
            "expected real archive fixture to contain mapped upstream messages for {storage_user_id}"
        );
        assert_eq!(
            total_snapshot_messages, total_messages,
            "snapshot and listing totals should match for {storage_user_id}"
        );
        assert!(
            total_existing_blobs > 0,
            "expected at least one real blob path in archive fixture for {storage_user_id}"
        );
        assert!(
            deleted.len() <= mailboxes.len(),
            "deleted subscription count should stay bounded for {storage_user_id}"
        );
    }
}
