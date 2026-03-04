use std::fs;
use std::path::{Path, PathBuf};

use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::vault;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn copy_dir_recursive(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap_or_else(|err| {
        panic!(
            "failed to create target directory {}: {err}",
            target.display()
        )
    });

    for entry in fs::read_dir(source)
        .unwrap_or_else(|err| panic!("failed to read directory {}: {err}", source.display()))
    {
        let entry = entry.unwrap_or_else(|err| panic!("failed to read directory entry: {err}"));
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());

        if source_path.is_dir() {
            copy_dir_recursive(&source_path, &target_path);
        } else {
            fs::copy(&source_path, &target_path).unwrap_or_else(|err| {
                panic!(
                    "failed to copy {} -> {}: {err}",
                    source_path.display(),
                    target_path.display()
                )
            });
        }
    }
}

fn load_vault_json(dir: &Path) -> Value {
    let value = vault::load_vault_msgpack_value(dir)
        .unwrap_or_else(|err| panic!("failed to load vault msgpack value: {err}"));
    serde_json::to_value(value).expect("failed to serialize msgpack value to json")
}

fn fixture_session_template() -> Session {
    Session {
        uid: "uid-alpha".to_string(),
        access_token: String::new(),
        refresh_token: "refresh-alpha".to_string(),
        email: "alpha@proton.me".to_string(),
        display_name: "Alpha Display".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"alpha-key-pass",
        )),
        bridge_password: Some("alpha-bridge-pass".to_string()),
    }
}

#[test]
fn parity_store_interop_loads_proton_profile_fixture() {
    let fixture_root = repo_root().join("tests/fixtures/proton_profile_golden");
    let temp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&fixture_root, temp.path());

    let default_session = vault::load_session(temp.path()).expect("load default session");
    assert_eq!(default_session.uid, "uid-beta");
    assert_eq!(default_session.email, "beta@proton.me");
    assert_eq!(default_session.display_name, "Beta Display");
    assert_eq!(
        default_session.bridge_password.as_deref(),
        Some("beta-bridge-pass")
    );

    let secondary_session =
        vault::load_session_by_email(temp.path(), "alpha@proton.me").expect("load alpha session");
    assert_eq!(secondary_session.uid, "uid-alpha");
    assert_eq!(secondary_session.api_mode, ApiMode::Bridge);
    assert_eq!(
        secondary_session.bridge_password.as_deref(),
        Some("alpha-bridge-pass")
    );
}

#[test]
fn parity_store_interop_roundtrip_preserves_metadata_fields() {
    let fixture_root = repo_root().join("tests/fixtures/proton_profile_golden");
    let temp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&fixture_root, temp.path());

    let before = load_vault_json(temp.path());
    let expected_cookies = before["Cookies"].clone();
    let expected_migrated = before["Migrated"].clone();
    let expected_password_archive = before["Settings"]["PasswordArchive"].clone();
    let expected_feature_flag_sticky_key = before["FeatureFlagStickyKey"].clone();

    let existing = vault::load_session_by_email(temp.path(), "alpha@proton.me")
        .expect("load existing fixture session");
    vault::save_session(&existing, temp.path()).expect("first fixture roundtrip save");

    let after_first = load_vault_json(temp.path());
    assert_eq!(after_first["Cookies"], expected_cookies);
    assert_eq!(after_first["Migrated"], expected_migrated);
    assert_eq!(
        after_first["Settings"]["PasswordArchive"],
        expected_password_archive
    );
    assert_eq!(
        after_first["FeatureFlagStickyKey"],
        expected_feature_flag_sticky_key
    );

    let cert_block_after_first = after_first["Certs"]["Bridge"].clone();

    let mut updated = fixture_session_template();
    updated.display_name = "Alpha Display Updated".to_string();
    vault::save_session(&updated, temp.path()).expect("second fixture roundtrip save");

    let after_second = load_vault_json(temp.path());
    assert_eq!(after_second["Cookies"], expected_cookies);
    assert_eq!(after_second["Migrated"], expected_migrated);
    assert_eq!(
        after_second["Settings"]["PasswordArchive"],
        expected_password_archive
    );
    assert_eq!(
        after_second["FeatureFlagStickyKey"],
        expected_feature_flag_sticky_key
    );
    assert_eq!(after_second["Certs"]["Bridge"], cert_block_after_first);

    let loaded =
        vault::load_session_by_email(temp.path(), "alpha@proton.me").expect("load updated user");
    assert_eq!(loaded.display_name, "Alpha Display Updated");
}
