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

#[test]
fn golden_fixture_defines_required_scenarios() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    assert!(
        fixture_path.exists(),
        "missing parity golden fixture: {}",
        fixture_path.display()
    );
    let fixture = read_fixture_json(&fixture_path);
    assert_eq!(
        fixture.get("version").and_then(Value::as_i64),
        Some(1),
        "fixture version must be pinned to 1"
    );

    let scenarios = fixture
        .get("scenarios")
        .and_then(Value::as_array)
        .expect("fixture must define scenarios[]");
    assert!(!scenarios.is_empty(), "scenarios[] must not be empty");

    let mut scenario_ids = BTreeSet::new();
    for (idx, scenario) in scenarios.iter().enumerate() {
        let id = scenario
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("scenarios[{idx}].id must be a string"));
        assert!(!id.trim().is_empty(), "scenarios[{idx}].id cannot be empty");
        scenario_ids.insert(id.to_string());

        let milestones = scenario
            .get("required_milestones")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("scenarios[{idx}].required_milestones must be an array"));
        assert!(
            !milestones.is_empty(),
            "scenarios[{idx}].required_milestones must not be empty"
        );

        for (midx, milestone) in milestones.iter().enumerate() {
            let name = milestone
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("scenarios[{idx}].required_milestones[{midx}].name"));
            assert!(
                !name.trim().is_empty(),
                "milestone name must not be empty for scenario {id}"
            );
            let any_of = milestone
                .get("any_of")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("milestone any_of must be array for {id}.{name}"));
            assert!(!any_of.is_empty(), "milestone any_of must not be empty");
            for pattern in any_of {
                assert!(
                    pattern.as_str().is_some_and(|s| !s.is_empty()),
                    "milestone pattern must be a non-empty string for {id}.{name}"
                );
            }
        }
    }

    let required = BTreeSet::from([
        "first_login".to_string(),
        "existing_account_startup".to_string(),
        "repair_flow".to_string(),
        "interrupted_sync".to_string(),
        "auth_lifecycle".to_string(),
        "grpc_transition_lifecycle".to_string(),
        "feedback_logout_lifecycle".to_string(),
        "event_loop_recovery".to_string(),
        "second_factor_prompts".to_string(),
        "sync_job_lifecycle".to_string(),
    ]);
    assert_eq!(
        scenario_ids, required,
        "fixture must include exactly the required parity scenarios"
    );
}

#[test]
fn log_validator_help_mentions_required_flags() {
    let root = repo_root();
    let tool_path = root.join("scripts/validate_parity_logs.py");
    assert!(
        tool_path.exists(),
        "missing parity log validator script: {}",
        tool_path.display()
    );

    let help = Command::new("python3")
        .arg(&tool_path)
        .arg("--help")
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator --help: {err}"));
    let help_text = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    assert!(
        help.status.success(),
        "validator --help failed:\n{help_text}"
    );

    for flag in ["--fixture", "--scenario", "--log", "--report-json"] {
        assert!(
            help_text.contains(flag),
            "validator --help must mention {flag}"
        );
    }
}

#[test]
fn log_validator_passes_when_milestones_are_in_order() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("ordered.log");
    let report_path = tmp.path().join("ordered-report.json");

    fs::write(
        &log_path,
        [
            "INFO account sync started",
            "INFO account_id=uid-1 account_email=user@proton.me running startup bounded resync",
            "DEBUG account_id=uid-1 account_email=user@proton.me total_applied=12 completed refresh resync",
            "INFO account sync finished",
        ]
        .join("\n"),
    )
    .expect("write ordered log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("first_login")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected validator success, got stderr:\n{stderr}"
    );

    let report = read_fixture_json(&report_path);
    assert_eq!(report.get("passed").and_then(Value::as_bool), Some(true));
    assert_eq!(
        report
            .get("missing_milestones")
            .and_then(Value::as_array)
            .expect("missing_milestones array")
            .len(),
        0
    );
    assert_eq!(
        report
            .get("out_of_order_milestones")
            .and_then(Value::as_array)
            .expect("out_of_order_milestones array")
            .len(),
        0
    );
    assert_eq!(
        report
            .get("field_mismatch_milestones")
            .and_then(Value::as_array)
            .expect("field_mismatch_milestones array")
            .len(),
        0
    );
}

#[test]
fn log_validator_reports_missing_and_out_of_order_milestones() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("mismatch.log");
    let report_path = tmp.path().join("mismatch-report.json");

    fs::write(
        &log_path,
        [
            "INFO account sync started",
            "DEBUG account_id=uid-1 account_email=user@proton.me total_applied=7 completed refresh resync",
            "INFO account_id=uid-1 account_email=user@proton.me running startup bounded resync",
        ]
        .join("\n"),
    )
    .expect("write mismatch log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("first_login")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    assert!(
        !output.status.success(),
        "validator should fail for mismatch log"
    );

    let report = read_fixture_json(&report_path);
    assert_eq!(report.get("passed").and_then(Value::as_bool), Some(false));

    let missing = report
        .get("missing_milestones")
        .and_then(Value::as_array)
        .expect("missing_milestones array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(missing, vec!["sync_finished"]);

    let out_of_order = report
        .get("out_of_order_milestones")
        .and_then(Value::as_array)
        .expect("out_of_order_milestones array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(out_of_order, vec!["resync_completed"]);

    let field_mismatch = report
        .get("field_mismatch_milestones")
        .and_then(Value::as_array)
        .expect("field_mismatch_milestones array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(field_mismatch.is_empty());
}

#[test]
fn log_validator_reports_field_mismatch_for_required_fields() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("field-mismatch.log");
    let report_path = tmp.path().join("field-mismatch-report.json");

    fs::write(
        &log_path,
        [
            "INFO account sync started",
            "INFO running startup bounded resync",
            "DEBUG completed refresh resync",
            "INFO account sync finished",
        ]
        .join("\n"),
    )
    .expect("write field mismatch log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("first_login")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    assert!(
        !output.status.success(),
        "validator should fail for field mismatch log"
    );

    let report = read_fixture_json(&report_path);
    let field_mismatch = report
        .get("field_mismatch_milestones")
        .and_then(Value::as_array)
        .expect("field_mismatch_milestones array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        field_mismatch,
        vec!["startup_resync_started", "resync_completed"]
    );
}

#[test]
fn log_validator_passes_grpc_transition_lifecycle() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("grpc-transition.log");
    let report_path = tmp.path().join("grpc-transition-report.json");

    fs::write(
        &log_path,
        [
            "INFO pkg=grpc/bridge transition=trigger_repair repair requested",
            "INFO pkg=grpc/sync transition=trigger_repair refreshing grpc sync workers for transition",
            "INFO pkg=grpc/bridge transition=trigger_repair repair transition completed",
            "INFO pkg=grpc/bridge transition=trigger_reset reset requested",
            "INFO pkg=grpc/sync transition=trigger_reset refreshing grpc sync workers for transition",
            "INFO pkg=grpc/bridge transition=trigger_reset reset transition completed",
        ]
        .join("\n"),
    )
    .expect("write grpc transition log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("grpc_transition_lifecycle")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected validator success, got stderr:\n{stderr}"
    );

    let report = read_fixture_json(&report_path);
    assert_eq!(report.get("passed").and_then(Value::as_bool), Some(true));
}

#[test]
fn log_validator_passes_second_factor_prompts() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("second-factor.log");
    let report_path = tmp.path().join("second-factor-report.json");

    fs::write(
        &log_path,
        [
            "INFO pkg=bridge/login user_id=uid-1 Requesting TOTP",
            "INFO pkg=bridge/login user_id=uid-1 username=user@proton.me Requesting mailbox password",
        ]
        .join("\n"),
    )
    .expect("write second factor log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("second_factor_prompts")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected validator success, got stderr:\n{stderr}"
    );

    let report = read_fixture_json(&report_path);
    assert_eq!(report.get("passed").and_then(Value::as_bool), Some(true));
}

#[test]
fn log_validator_passes_sync_job_lifecycle() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("sync-job.log");
    let report_path = tmp.path().join("sync-job-report.json");

    fs::write(
        &log_path,
        [
            "INFO user_id=uid-1 start=1700000000 duration=0ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=0 Sync triggered",
            "INFO user_id=uid-1 start=1700000000 duration=1ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=1 Beginning user sync",
            "INFO user_id=uid-1 start=1700000000 duration=2ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=2 Syncing labels",
            "INFO user_id=uid-1 start=1700000000 duration=3ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=3 Synced labels",
            "INFO user_id=uid-1 start=1700000000 duration=4ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=4 Syncing messages",
            "INFO user_id=uid-1 start=1700000000 duration=5ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=5 Synced messages",
            "INFO user_id=uid-1 start=1700000000 duration=6ms account_id=uid-1 account_email=user@proton.me start_unix=1700000000 duration_ms=6 Finished user sync",
        ]
        .join("\n"),
    )
    .expect("write sync job log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("sync_job_lifecycle")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected validator success, got stderr:\n{stderr}"
    );

    let report = read_fixture_json(&report_path);
    assert_eq!(report.get("passed").and_then(Value::as_bool), Some(true));
}

#[test]
fn log_validator_reports_sync_job_lifecycle_field_mismatch() {
    let root = repo_root();
    let fixture_path = root.join("tests/fixtures/parity_golden_logs.json");
    let tool_path = root.join("scripts/validate_parity_logs.py");
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("sync-job-field-mismatch.log");
    let report_path = tmp.path().join("sync-job-field-mismatch-report.json");

    fs::write(
        &log_path,
        [
            "INFO Sync triggered",
            "INFO Beginning user sync",
            "INFO Syncing labels",
            "INFO Synced labels",
            "INFO Syncing messages",
            "INFO Messages are already synced, skipping",
            "INFO Finished user sync",
        ]
        .join("\n"),
    )
    .expect("write sync job mismatch log");

    let output = Command::new("python3")
        .arg(&tool_path)
        .arg("--fixture")
        .arg(&fixture_path)
        .arg("--scenario")
        .arg("sync_job_lifecycle")
        .arg("--log")
        .arg(&log_path)
        .arg("--report-json")
        .arg(&report_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run parity validator: {err}"));

    assert!(
        !output.status.success(),
        "validator should fail for sync job field mismatch log"
    );

    let report = read_fixture_json(&report_path);
    let field_mismatch = report
        .get("field_mismatch_milestones")
        .and_then(Value::as_array)
        .expect("field_mismatch_milestones array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        field_mismatch,
        vec![
            "sync_triggered",
            "sync_beginning",
            "syncing_labels",
            "synced_labels",
            "syncing_messages",
            "message_sync_completed_or_skipped",
            "sync_finished",
        ]
    );
}
