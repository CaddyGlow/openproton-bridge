use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, SchemaFamily,
    SchemaProbe, StoreBootstrap,
};
use openproton_bridge::vault;
use rusqlite::Connection;

const REAL_ARCHIVE_ENV: &str = "OPENPROTON_REAL_GLUON_ARCHIVE";
const REAL_PROFILE_ENV: &str = "OPENPROTON_REAL_GLUON_PROFILE";
const REAL_VAULT_KEY_ENV: &str = "OPENPROTON_REAL_VAULT_KEY";
const REAL_VAULT_KEY_ALIAS_ENV: &str = "OPENPROTON_REAL_GLUON_KEY";
const ARCHIVE_PROFILE_SUBTREE: &str = "Users/rick/Library/Application Support/protonmail/bridge-v3";
const PROFILE_GLUON_SUBTREE: &str = "gluon";
const VAULT_FILE: &str = "vault.enc";
const KEY_FILE: &str = "vault.key";

struct ResolvedProfileRoot {
    root: PathBuf,
    _temp: Option<tempfile::TempDir>,
}

fn extract_real_archive_fixture(archive_path: &Path, output_root: &Path) {
    for archive_member in [
        format!("{ARCHIVE_PROFILE_SUBTREE}/gluon"),
        format!("{ARCHIVE_PROFILE_SUBTREE}/{VAULT_FILE}"),
    ] {
        let status = Command::new("tar")
            .arg("-xf")
            .arg(archive_path)
            .arg("-C")
            .arg(output_root)
            .arg(&archive_member)
            .status()
            .unwrap_or_else(|err| {
                panic!(
                    "failed to extract {archive_member} from {}: {err}",
                    archive_path.display()
                )
            });
        assert!(
            status.success(),
            "tar extraction failed for {} member {} with status {status}",
            archive_path.display(),
            archive_member
        );
    }
}

fn resolve_real_profile_root() -> Option<ResolvedProfileRoot> {
    if let Some(profile_path) = env::var_os(REAL_PROFILE_ENV).map(PathBuf::from) {
        return Some(ResolvedProfileRoot {
            root: profile_path,
            _temp: None,
        });
    }

    let archive_path = env::var_os(REAL_ARCHIVE_ENV).map(PathBuf::from)?;
    let temp = tempfile::tempdir().expect("tempdir");
    extract_real_archive_fixture(&archive_path, temp.path());
    Some(ResolvedProfileRoot {
        root: temp.path().join(ARCHIVE_PROFILE_SUBTREE),
        _temp: Some(temp),
    })
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

fn assert_upstream_db_contract(gluon_root: &Path, storage_user_id: &str) {
    let db_path = gluon_root
        .join("backend")
        .join("db")
        .join(format!("{storage_user_id}.db"));
    let conn = Connection::open(&db_path)
        .unwrap_or_else(|err| panic!("failed to open upstream db {}: {err}", db_path.display()));
    let version = conn
        .query_row(
            "SELECT version FROM gluon_version WHERE id = 0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|err| {
            panic!(
                "failed to read gluon_version from {}: {err}",
                db_path.display()
            )
        });
    assert!(
        version >= 1,
        "expected nonzero upstream gluon_version in {}",
        db_path.display()
    );

    let connector_rows = conn
        .query_row(
            "SELECT COUNT(*) FROM connector_settings WHERE id = 0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|err| {
            panic!(
                "failed to read connector_settings from {}: {err}",
                db_path.display()
            )
        });
    assert_eq!(
        connector_rows,
        1,
        "expected connector_settings bootstrap row in {}",
        db_path.display()
    );
}

fn resolve_real_vault_key() -> Option<[u8; 32]> {
    let encoded = env::var(REAL_VAULT_KEY_ENV)
        .ok()
        .or_else(|| env::var(REAL_VAULT_KEY_ALIAS_ENV).ok())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .unwrap_or_else(|err| panic!("failed to decode real vault key as base64: {err}"));
    let key: [u8; 32] = raw
        .try_into()
        .unwrap_or_else(|_| panic!("real vault key must decode to exactly 32 bytes"));
    Some(key)
}

fn load_real_bootstrap(profile_root: &Path, vault_key: &[u8; 32]) -> vault::GluonStoreBootstrap {
    fs::write(profile_root.join(KEY_FILE), vault_key).unwrap_or_else(|err| {
        panic!(
            "failed to write {}: {err}",
            profile_root.join(KEY_FILE).display()
        )
    });
    vault::load_gluon_store_bootstrap(profile_root, &[]).unwrap_or_else(|err| {
        panic!(
            "failed to load real Gluon bootstrap from {}: {err}",
            profile_root.display()
        )
    })
}

fn build_store(gluon_root: &Path, account: &vault::GluonAccountBootstrap) -> CompatibleStore {
    CompatibleStore::open_read_only(StoreBootstrap::new(
        CacheLayout::new(gluon_root),
        CompatibilityTarget::default(),
        vec![AccountBootstrap::new(
            account.account_id.clone(),
            account.storage_user_id.clone(),
            GluonKey::try_from_slice(&account.gluon_key).expect("real Gluon key"),
        )],
    ))
    .unwrap_or_else(|err| {
        panic!(
            "failed to open real fixture store for {} / {}: {err}",
            account.account_id, account.storage_user_id
        )
    })
}

#[test]
fn be029_open_read_only_accepts_real_archive_fixture() {
    let Some(resolved) = resolve_real_profile_root() else {
        eprintln!(
            "skipping be029 real archive parity test; set {REAL_PROFILE_ENV} or {REAL_ARCHIVE_ENV}"
        );
        return;
    };
    let profile_root = resolved.root;
    let gluon_root = profile_root.join(PROFILE_GLUON_SUBTREE);
    assert!(
        gluon_root.exists(),
        "fixture does not contain expected Gluon subtree: {}",
        gluon_root.display()
    );
    assert!(
        profile_root.join(VAULT_FILE).exists(),
        "fixture does not contain expected vault file: {}",
        profile_root.join(VAULT_FILE).display()
    );

    let storage_user_ids = find_upstream_storage_user_ids(&gluon_root);
    assert!(
        !storage_user_ids.is_empty(),
        "fixture did not contain any upstream-compatible account DBs under {}",
        gluon_root.display()
    );

    for (index, storage_user_id) in storage_user_ids.iter().enumerate() {
        assert_upstream_db_contract(&gluon_root, storage_user_id);

        let bootstrap = StoreBootstrap::new(
            CacheLayout::new(&gluon_root),
            CompatibilityTarget::default(),
            vec![AccountBootstrap::new(
                format!("real-account-{index}"),
                storage_user_id,
                GluonKey::try_from_slice(&[0x29; 32]).expect("fallback fixture key"),
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
            "expected real fixture to expose an upstream-compatible DB for {storage_user_id}"
        );
        assert!(
            !probe.mailbox_message_tables().is_empty(),
            "expected mailbox_message tables in real fixture for {storage_user_id}"
        );

        let mailboxes = store
            .list_upstream_mailboxes(storage_user_id)
            .unwrap_or_else(|err| panic!("failed to list mailboxes for {storage_user_id}: {err}"));
        assert!(
            !mailboxes.is_empty(),
            "expected at least one mailbox in real fixture for {storage_user_id}"
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
            "expected real fixture to contain mapped upstream messages for {storage_user_id}"
        );
        assert_eq!(
            total_snapshot_messages, total_messages,
            "snapshot and listing totals should match for {storage_user_id}"
        );
        assert!(
            total_existing_blobs > 0,
            "expected at least one real blob path in fixture for {storage_user_id}"
        );
        assert!(
            deleted.len() <= mailboxes.len(),
            "deleted subscription count should stay bounded for {storage_user_id}"
        );
    }

    if let Some(vault_key) = resolve_real_vault_key() {
        let bootstrap = load_real_bootstrap(&profile_root, &vault_key);
        assert!(
            !bootstrap.accounts.is_empty(),
            "expected decrypted vault bootstrap to expose at least one account"
        );

        let mut decoded_blob_count = 0usize;
        for account in &bootstrap.accounts {
            let store = build_store(&gluon_root, account);
            let account_paths = store
                .account_paths(&account.storage_user_id)
                .unwrap_or_else(|err| {
                    panic!(
                        "failed to resolve account paths for {} / {}: {err}",
                        account.account_id, account.storage_user_id
                    )
                });
            let Ok(entries) = fs::read_dir(account_paths.store_dir()) else {
                continue;
            };

            for entry in entries {
                let entry = entry.expect("read account store blob entry");
                let blob_path = entry.path();
                if !blob_path.is_file() {
                    continue;
                }

                let internal_message_id = entry.file_name();
                let internal_message_id = internal_message_id
                    .to_str()
                    .unwrap_or_else(|| panic!("invalid blob file name {}", blob_path.display()));
                let encoded = fs::read(&blob_path).unwrap_or_else(|err| {
                    panic!("failed to read blob {}: {err}", blob_path.display())
                });
                if !encoded.starts_with(b"GLUON-CACHE") {
                    continue;
                }

                let blob = store
                    .read_message_blob(&account.storage_user_id, internal_message_id)
                    .unwrap_or_else(|err| {
                        panic!(
                            "failed to decode blob {} for {} / {}: {err}",
                            blob_path.display(),
                            account.account_id,
                            account.storage_user_id
                        )
                    });
                assert!(
                    !blob.is_empty(),
                    "decoded blob should not be empty for {}",
                    blob_path.display()
                );
                decoded_blob_count += 1;
                break;
            }
        }

        assert!(
            decoded_blob_count > 0,
            "expected vault-derived Gluon keys to decode at least one real encrypted blob"
        );
    }
}
