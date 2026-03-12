use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn family_ids_from_compat_target(root: &Path) -> BTreeSet<String> {
    let target_path = root.join("tests/fixtures/gluon_compatibility_target.json");
    let target = read_fixture_json(&target_path);
    target
        .get("required_file_families")
        .and_then(Value::as_array)
        .expect("compatibility target must define required_file_families[]")
        .iter()
        .map(|entry| {
            entry
                .get("family_id")
                .and_then(Value::as_str)
                .expect("required_file_families[] entries must include family_id")
                .to_owned()
        })
        .collect()
}

#[test]
fn be017_fixture_capture_contract_matches_be016_families() {
    let root = repo_root();
    let tool_path = root.join("scripts/capture_gluon_fixture.py");
    assert!(
        tool_path.exists(),
        "missing BE-017 fixture capture tool: {}",
        tool_path.display()
    );

    let help = Command::new("python3")
        .arg(&tool_path)
        .arg("--help")
        .output()
        .unwrap_or_else(|err| panic!("failed to run fixture capture tool --help: {err}"));
    let help_text = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    assert!(
        help.status.success(),
        "fixture capture tool --help failed:\n{}",
        help_text
    );
    for flag in [
        "--source-profile",
        "--output-dir",
        "--manifest-out",
        "--fixture-name",
        "--dry-run",
    ] {
        assert!(
            help_text.contains(flag),
            "fixture capture tool --help must mention {flag}"
        );
    }

    let manifest_path = root.join("tests/fixtures/gluon_fixture_manifest.json");
    assert!(
        manifest_path.exists(),
        "missing BE-017 fixture manifest: {}",
        manifest_path.display()
    );
    let manifest = read_fixture_json(&manifest_path);

    let ticket = manifest
        .get("ticket")
        .and_then(Value::as_str)
        .expect("fixture manifest must define ticket");
    assert_eq!(ticket, "BE-017");

    let compat_target_path = manifest
        .get("compatibility_target_fixture")
        .and_then(Value::as_str)
        .expect("fixture manifest must define compatibility_target_fixture");
    assert_eq!(
        compat_target_path,
        "tests/fixtures/gluon_compatibility_target.json"
    );

    let sanitization = manifest
        .get("sanitization")
        .and_then(Value::as_object)
        .expect("fixture manifest must define sanitization object");
    let redacted_patterns = sanitization
        .get("redacted_patterns")
        .and_then(Value::as_array)
        .expect("fixture manifest sanitization.redacted_patterns[] is required");
    assert!(
        !redacted_patterns.is_empty(),
        "sanitization.redacted_patterns[] must not be empty"
    );

    let captured_families = manifest
        .get("captured_families")
        .and_then(Value::as_array)
        .expect("fixture manifest must define captured_families[]");
    assert!(
        !captured_families.is_empty(),
        "captured_families[] must not be empty"
    );

    let mut manifest_family_ids = BTreeSet::new();
    for family in captured_families {
        let family_id = family
            .get("family_id")
            .and_then(Value::as_str)
            .expect("captured_families[] entries must define family_id");
        manifest_family_ids.insert(family_id.to_owned());

        let paths = family
            .get("paths")
            .and_then(Value::as_array)
            .expect("captured_families[] entries must define paths[]");
        assert!(
            !paths.is_empty(),
            "captured_families[{family_id}] paths[] must not be empty"
        );
        for path in paths {
            let rel = path
                .as_str()
                .expect("captured_families[].paths[] entries must be strings");
            let abs = root.join(rel);
            assert!(
                abs.exists(),
                "fixture manifest declares missing path: {}",
                abs.display()
            );
        }
    }

    let be016_families = family_ids_from_compat_target(&root);
    assert_eq!(
        manifest_family_ids, be016_families,
        "BE-017 fixture manifest must cover every BE-016 required family"
    );
}

#[test]
fn be029_fixture_manifest_documents_sanitized_sqlite_limitations() {
    let root = repo_root();
    let manifest_path = root.join("tests/fixtures/gluon_fixture_manifest.json");
    let manifest = read_fixture_json(&manifest_path);

    let unsupported_cases = manifest
        .get("unsupported_cases")
        .and_then(Value::as_array)
        .expect("fixture manifest must define unsupported_cases[]");
    assert!(
        unsupported_cases.iter().any(|entry| {
            entry
                .as_str()
                .map(|text| text.contains("CompatibleStore") && text.contains("placeholder"))
                .unwrap_or(false)
        }),
        "fixture manifest must document placeholder sqlite artifacts as non-openable by CompatibleStore"
    );

    let primary_db =
        root.join("tests/fixtures/proton_profile_gluon_sanitized/backend/db/user-redacted.db");
    let deferred_delete = root.join(
        "tests/fixtures/proton_profile_gluon_sanitized/backend/db/deferred_delete/user-redacted.db.1700000000",
    );
    let primary_db_bytes = fs::read(&primary_db).expect("read sanitized primary db fixture");
    let deferred_delete_bytes =
        fs::read(&deferred_delete).expect("read sanitized deferred delete fixture");

    assert!(
        primary_db_bytes.starts_with(b"sqlite-placeholder:"),
        "sanitized primary db fixture should remain an explicit placeholder artifact"
    );
    assert!(
        deferred_delete_bytes.starts_with(b"deferred-delete-placeholder:"),
        "sanitized deferred delete fixture should remain an explicit placeholder artifact"
    );
}
