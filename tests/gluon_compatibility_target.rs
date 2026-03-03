use std::fs;
use std::collections::HashSet;
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

fn assert_iso_date(date: &str, field: &str) {
    assert_eq!(
        date.len(),
        10,
        "{field} should be YYYY-MM-DD, got {date}"
    );
    let bytes = date.as_bytes();
    assert_eq!(bytes[4], b'-', "{field} should use YYYY-MM-DD");
    assert_eq!(bytes[7], b'-', "{field} should use YYYY-MM-DD");
}

fn assert_full_sha(sha: &str, field: &str) {
    assert_eq!(sha.len(), 40, "{field} should be a full 40-char SHA");
    assert!(
        sha.chars().all(|c| c.is_ascii_hexdigit()),
        "{field} should contain only hex characters"
    );
}

#[test]
fn gluon_compatibility_target_is_frozen_and_documented() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/gluon_compatibility_target.json");
    let plan_path = root.join("docs/GLUON_FULL_SUPPORT_EXECUTION_PLAN.md");
    let ledger_path = root.join("docs/BACKEND_PARITY_LEDGER.md");

    assert!(
        fixture_path.exists(),
        "missing BE-016 fixture: {}",
        fixture_path.display()
    );

    let fixture = read_fixture_json(&fixture_path);

    let ticket = fixture
        .get("ticket")
        .and_then(Value::as_str)
        .expect("fixture must define 'ticket' as a string");
    assert_eq!(ticket, "BE-016");

    let frozen_on = fixture
        .get("frozen_on")
        .and_then(Value::as_str)
        .expect("fixture must define 'frozen_on' as YYYY-MM-DD");
    assert_iso_date(frozen_on, "frozen_on");

    let upstream = fixture
        .get("upstream")
        .and_then(Value::as_object)
        .expect("fixture must define 'upstream' object");

    let proton_bridge = upstream
        .get("proton_bridge")
        .and_then(Value::as_object)
        .expect("fixture must define upstream.proton_bridge object");
    let bridge_commit = proton_bridge
        .get("commit")
        .and_then(Value::as_str)
        .expect("fixture must define upstream.proton_bridge.commit");
    assert_full_sha(bridge_commit, "upstream.proton_bridge.commit");

    let gluon = upstream
        .get("gluon")
        .and_then(Value::as_object)
        .expect("fixture must define upstream.gluon object");
    let gluon_commit = gluon
        .get("commit")
        .and_then(Value::as_str)
        .expect("fixture must define upstream.gluon.commit");
    assert_full_sha(gluon_commit, "upstream.gluon.commit");

    let families = fixture
        .get("required_file_families")
        .and_then(Value::as_array)
        .expect("fixture must define required_file_families[]");
    assert!(
        families.len() >= 5,
        "required_file_families should include at least 5 families"
    );
    let family_ids: HashSet<String> = families
        .iter()
        .filter_map(|entry| entry.get("family_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    assert!(
        !family_ids.is_empty(),
        "required_file_families entries must define family_id"
    );

    let matrix = fixture
        .get("compatibility_matrix")
        .and_then(Value::as_array)
        .expect("fixture must define compatibility_matrix[]");
    assert!(
        !matrix.is_empty(),
        "compatibility_matrix must include at least one entry"
    );
    let matrix_ids: HashSet<String> = matrix
        .iter()
        .filter_map(|entry| entry.get("family_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(
        family_ids, matrix_ids,
        "compatibility_matrix must cover every required_file_families family_id"
    );

    let plan = fs::read_to_string(&plan_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", plan_path.display()));
    let ledger = fs::read_to_string(&ledger_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", ledger_path.display()));

    assert!(
        plan.contains("## BE-016 Frozen Gluon Compatibility Target"),
        "execution plan must include BE-016 frozen target section"
    );
    assert!(
        plan.contains("tests/fixtures/gluon_compatibility_target.json"),
        "execution plan must reference the BE-016 fixture path"
    );
    assert!(
        plan.contains(bridge_commit),
        "execution plan must contain pinned proton-bridge commit from fixture"
    );
    assert!(
        plan.contains(gluon_commit),
        "execution plan must contain pinned gluon commit from fixture"
    );

    assert!(
        ledger.contains("## Gluon Compatibility Freeze (BE-016)"),
        "backend parity ledger must track BE-016 freeze status"
    );
    assert!(
        ledger.contains("tests/fixtures/gluon_compatibility_target.json"),
        "backend parity ledger must reference BE-016 fixture path"
    );
}
