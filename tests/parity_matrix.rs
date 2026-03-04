use base64::Engine as _;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_json(relative: &str) -> Value {
    let path = repo_path(relative);
    let bytes = fs::read(path).expect("fixture file should be readable");
    serde_json::from_slice::<Value>(&bytes).expect("fixture JSON should parse")
}

#[test]
fn parity_matrix_manifest_references_existing_fixtures() {
    let manifest = read_json("tests/parity/fixtures/manifest.json");
    let object = manifest
        .as_object()
        .expect("manifest must be a top-level JSON object");

    for key in [
        "vault_samples",
        "event_payloads",
        "grpc_login_payloads",
        "tls_handshakes",
    ] {
        assert!(
            object.contains_key(key),
            "manifest missing required section: {key}"
        );
    }

    for section in object.values() {
        let section_map = section
            .as_object()
            .expect("manifest sections must be JSON objects");
        for path_value in section_map.values() {
            let path_str = path_value
                .as_str()
                .expect("manifest fixture entries must be string paths");
            assert!(
                repo_path(path_str).exists(),
                "fixture path from manifest should exist: {path_str}"
            );
        }
    }
}

#[test]
fn parity_matrix_event_fixtures_cover_single_and_array_shapes() {
    let single = read_json("tests/parity/fixtures/events_single_object.json");
    assert!(
        single.get("Event").and_then(Value::as_object).is_some(),
        "single event fixture must contain Event object"
    );
    assert!(
        single
            .get("Event")
            .and_then(|event| event.get("Messages"))
            .and_then(Value::as_array)
            .is_some(),
        "single event fixture must contain Event.Messages array"
    );

    let array = read_json("tests/parity/fixtures/events_array.json");
    let events = array
        .get("Events")
        .and_then(Value::as_array)
        .expect("events array fixture must contain Events array");
    assert!(!events.is_empty(), "Events array fixture must not be empty");
    assert!(
        events.iter().all(|event| event.get("ID").is_some()),
        "each event entry should have ID"
    );
}

#[test]
fn parity_matrix_grpc_login_fixtures_cover_base64_and_two_password_flow() {
    let base64_login = read_json("tests/parity/fixtures/grpc_login_base64.json");
    let encoded = base64_login
        .get("password")
        .and_then(Value::as_str)
        .expect("base64 login fixture should include password string");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("password field should be valid base64");
    let expected = base64_login
        .get("expected_decoded_password")
        .and_then(Value::as_str)
        .expect("base64 login fixture should include expected decoded password");
    assert_eq!(
        String::from_utf8(decoded).expect("decoded base64 password should be utf-8"),
        expected
    );

    let two_passwords = read_json("tests/parity/fixtures/grpc_login_two_passwords.json");
    assert_eq!(
        two_passwords
            .get("password_mode")
            .and_then(Value::as_i64)
            .expect("two-password fixture should include password_mode"),
        2
    );
    let flow = two_passwords
        .get("expected_flow")
        .and_then(Value::as_array)
        .expect("two-password fixture should include expected_flow array");
    assert!(
        flow.iter()
            .any(|entry| entry.as_str() == Some("login2passwords")),
        "two-password flow should include login2passwords stage"
    );
}

#[test]
fn parity_matrix_tls_transcripts_include_starttls_markers() {
    let imap = fs::read_to_string(repo_path(
        "tests/parity/fixtures/imap_starttls_transcript.txt",
    ))
    .expect("imap transcript should be readable");
    assert!(
        imap.contains("STARTTLS"),
        "imap transcript should contain STARTTLS"
    );
    assert!(
        imap.contains("<tls-handshake>"),
        "imap transcript should include handshake marker"
    );

    let smtp = fs::read_to_string(repo_path(
        "tests/parity/fixtures/smtp_starttls_transcript.txt",
    ))
    .expect("smtp transcript should be readable");
    assert!(
        smtp.contains("STARTTLS"),
        "smtp transcript should contain STARTTLS"
    );
    assert!(
        smtp.contains("<tls-handshake>"),
        "smtp transcript should include handshake marker"
    );
}
