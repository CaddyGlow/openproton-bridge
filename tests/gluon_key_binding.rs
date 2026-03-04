use std::collections::HashMap;

use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::vault::{self, VaultError};

fn fixture_session(uid: &str, email: &str) -> Session {
    Session {
        uid: uid.to_string(),
        access_token: String::new(),
        refresh_token: format!("refresh-{uid}"),
        email: email.to_string(),
        display_name: format!("Display {uid}"),
        api_mode: ApiMode::Bridge,
        key_passphrase: None,
        bridge_password: Some(format!("bridge-{uid}")),
    }
}

#[test]
fn be020_rejects_missing_or_invalid_gluon_key_during_bootstrap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let session = fixture_session("uid-alpha", "alpha@proton.me");
    vault::save_session(&session, tmp.path()).expect("save session");

    vault::set_gluon_key_by_account_id(tmp.path(), &session.uid, Vec::new())
        .expect("set empty gluon key");

    let missing_err =
        vault::load_gluon_store_bootstrap(tmp.path(), std::slice::from_ref(&session.uid))
            .unwrap_err();
    assert!(matches!(missing_err, VaultError::MissingGluonKey(account) if account == session.uid));

    vault::set_gluon_key_by_account_id(tmp.path(), &session.uid, vec![7u8; 7])
        .expect("set invalid gluon key");

    let invalid_err =
        vault::load_gluon_store_bootstrap(tmp.path(), std::slice::from_ref(&session.uid))
            .unwrap_err();
    assert!(matches!(
        invalid_err,
        VaultError::InvalidGluonKeyLength { account_id, length }
        if account_id == session.uid && length == 7
    ));
}

#[test]
fn be020_rejects_mismatched_gluon_id_bindings_across_accounts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let session_a = fixture_session("uid-a", "a@proton.me");
    let session_b = fixture_session("uid-b", "b@proton.me");
    vault::save_session(&session_a, tmp.path()).expect("save session a");
    vault::save_session(&session_b, tmp.path()).expect("save session b");

    vault::save_gluon_id_bindings_by_account_id(
        tmp.path(),
        &session_a.uid,
        HashMap::from([(String::from("addr-shared"), String::from("gluon-a"))]),
    )
    .expect("save session a bindings");
    vault::save_gluon_id_bindings_by_account_id(
        tmp.path(),
        &session_b.uid,
        HashMap::from([(String::from("addr-shared"), String::from("gluon-b"))]),
    )
    .expect("save session b bindings");

    let err = vault::load_gluon_store_bootstrap(
        tmp.path(),
        &[session_a.uid.clone(), session_b.uid.clone()],
    )
    .unwrap_err();

    assert!(matches!(
        err,
        VaultError::MismatchedGluonIdBinding {
            address_id,
            expected,
            actual
        } if address_id == "addr-shared" && expected == "gluon-a" && actual == "gluon-b"
    ));
}

#[test]
fn be020_loads_valid_gluon_bootstrap_bindings_for_accounts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let session = fixture_session("uid-alpha", "alpha@proton.me");
    vault::save_session(&session, tmp.path()).expect("save session");
    vault::save_gluon_dir(tmp.path(), "fixture-gluon").expect("save gluon dir");
    vault::set_gluon_key_by_account_id(tmp.path(), &session.uid, vec![9u8; 32])
        .expect("save gluon key");
    vault::save_gluon_id_bindings_by_account_id(
        tmp.path(),
        &session.uid,
        HashMap::from([(String::from("addr-alpha"), String::from("gluon-alpha"))]),
    )
    .expect("save bindings");

    let bootstrap =
        vault::load_gluon_store_bootstrap(tmp.path(), std::slice::from_ref(&session.uid))
            .expect("bootstrap");

    if cfg!(target_os = "linux") {
        assert_eq!(bootstrap.gluon_dir, "fixture-gluon");
    } else {
        assert_eq!(
            bootstrap.gluon_dir,
            tmp.path().join("fixture-gluon").display().to_string()
        );
    }
    assert_eq!(bootstrap.accounts.len(), 1);
    assert_eq!(bootstrap.accounts[0].account_id, session.uid);
    assert_eq!(bootstrap.accounts[0].storage_user_id, "gluon-alpha");
    assert_eq!(bootstrap.accounts[0].gluon_key, [9u8; 32]);
    assert_eq!(
        bootstrap.accounts[0]
            .gluon_ids
            .get("addr-alpha")
            .map(String::as_str),
        Some("gluon-alpha")
    );
}
