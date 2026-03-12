use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, SchemaFamily,
    SchemaProbe, StoreBootstrap,
};

const REAL_ARCHIVE_ENV: &str = "OPENPROTON_REAL_GLUON_ARCHIVE";
const ARCHIVE_GLUON_SUBTREE: &str =
    "Users/rick/Library/Application Support/protonmail/bridge-v3/gluon";

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

#[test]
fn be029_open_read_only_accepts_real_archive_fixture() {
    let Some(archive_path) = env::var_os(REAL_ARCHIVE_ENV).map(PathBuf::from) else {
        eprintln!("skipping be029 real archive parity test; {REAL_ARCHIVE_ENV} is not set");
        return;
    };
    assert!(
        archive_path.exists(),
        "configured archive path does not exist: {}",
        archive_path.display()
    );

    let temp = tempfile::tempdir().expect("tempdir");
    extract_real_archive_fixture(&archive_path, temp.path());

    let gluon_root = temp.path().join(ARCHIVE_GLUON_SUBTREE);
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

        let mailboxes = store
            .list_upstream_mailboxes(storage_user_id)
            .unwrap_or_else(|err| panic!("failed to list mailboxes for {storage_user_id}: {err}"));
        assert!(
            !mailboxes.is_empty(),
            "expected at least one mailbox in real archive fixture for {storage_user_id}"
        );

        let total_messages: usize = mailboxes
            .iter()
            .map(|mailbox| {
                store
                    .list_upstream_mailbox_messages(storage_user_id, mailbox.internal_id)
                    .unwrap_or_else(|err| {
                        panic!(
                            "failed to list messages for {} mailbox {}: {err}",
                            storage_user_id, mailbox.name
                        )
                    })
                    .len()
            })
            .sum();
        assert!(
            total_messages > 0,
            "expected real archive fixture to contain mapped upstream messages for {storage_user_id}"
        );
    }
}
