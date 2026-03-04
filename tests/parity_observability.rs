use std::path::{Path, PathBuf};

use openproton_bridge::api::client::redact_sensitive_for_log;
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
