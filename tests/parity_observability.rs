use std::path::{Path, PathBuf};

use openproton_bridge::api::client::redact_sensitive_for_log;
use openproton_bridge::observability::{create_session_log, generate_support_log_bundle};
use openproton_bridge::paths::RuntimePaths;

#[test]
fn parity_observability_runtime_paths_include_session_and_crash_dirs() {
    let runtime = RuntimePaths::from_bases(
        PathBuf::from("/cfg"),
        PathBuf::from("/data"),
        PathBuf::from("/cache"),
    );

    assert_eq!(
        runtime.logs_dir(),
        Path::new("/data/protonmail/bridge-v3/logs")
    );
    assert_eq!(
        runtime.session_logs_dir(),
        Path::new("/data/protonmail/bridge-v3/logs/sessions")
    );
    assert_eq!(
        runtime.crash_reports_dir(),
        Path::new("/data/protonmail/bridge-v3/logs/crash_reports")
    );
    assert_eq!(
        runtime.support_bundles_dir(),
        Path::new("/data/protonmail/bridge-v3/logs/support")
    );
}

#[test]
fn parity_observability_sensitive_values_are_redacted_by_default() {
    assert_eq!(redact_sensitive_for_log(""), "<redacted>");
    assert_eq!(redact_sensitive_for_log("abc"), "<redacted>");
    assert_eq!(
        redact_sensitive_for_log("Bearer super-secret-token"),
        "Be…en"
    );
    assert_eq!(redact_sensitive_for_log(" access-token-value "), "ac…ue");
}

#[test]
fn parity_observability_session_logs_are_created_and_pruned() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = RuntimePaths::resolve(Some(tmp.path())).unwrap();

    for _ in 0..25 {
        let _ = create_session_log(&runtime).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    let count = std::fs::read_dir(runtime.session_logs_dir())
        .unwrap()
        .filter_map(Result::ok)
        .count();
    assert!(
        count <= 20,
        "session log rotation/prune should retain at most 20 files"
    );
}

#[test]
fn parity_observability_support_bundle_collects_diagnostics() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = RuntimePaths::resolve(Some(tmp.path())).unwrap();
    let _ = create_session_log(&runtime).unwrap();
    std::fs::create_dir_all(runtime.crash_reports_dir()).unwrap();
    std::fs::write(
        runtime.crash_reports_dir().join("panic-sample.log"),
        "panic=sample",
    )
    .unwrap();

    let bundle = generate_support_log_bundle(&runtime, "mailbox-state diagnostics").unwrap();
    assert!(bundle.exists());
    assert!(bundle
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".tar.gz")));
}
