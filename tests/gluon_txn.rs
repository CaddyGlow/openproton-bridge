use std::fs;

use openproton_bridge::imap::gluon_txn::{GluonTxnError, GluonTxnManager};

#[test]
fn be023_atomic_commit_writes_all_staged_targets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manager = GluonTxnManager::new(temp.path()).expect("txn manager");
    let mut txn = manager.begin("user-commit").expect("begin txn");

    txn.stage_write("backend/db/user-commit.db", b"db-new")
        .expect("stage db");
    txn.stage_write("sync-user-commit", br#"{"cursor":"new"}"#)
        .expect("stage sync");
    txn.commit().expect("commit");

    assert_eq!(
        fs::read(temp.path().join("backend/db/user-commit.db")).expect("read db"),
        b"db-new"
    );
    assert_eq!(
        fs::read(temp.path().join("sync-user-commit")).expect("read sync"),
        br#"{"cursor":"new"}"#
    );

    assert_eq!(
        manager
            .pending_transaction_count("user-commit")
            .expect("pending count"),
        0
    );
}

#[test]
fn be023_recovery_replays_interrupted_commit_from_journal() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(temp.path().join("backend/db")).expect("create db dir");
    fs::write(temp.path().join("backend/db/user-recover.db"), b"old-db").expect("seed db");
    fs::write(
        temp.path().join("sync-user-recover"),
        br#"{"cursor":"old"}"#,
    )
    .expect("seed sync");

    let manager = GluonTxnManager::new(temp.path()).expect("txn manager");
    let mut txn = manager.begin("user-recover").expect("begin txn");

    txn.stage_write("backend/db/user-recover.db", b"new-db")
        .expect("stage db");
    txn.stage_write("sync-user-recover", br#"{"cursor":"new"}"#)
        .expect("stage sync");

    let err = txn.commit_with_injected_failure(1).unwrap_err();
    assert!(matches!(err, GluonTxnError::InjectedFailure { applied } if applied == 1));

    assert_eq!(
        fs::read(temp.path().join("backend/db/user-recover.db")).expect("read db"),
        b"new-db"
    );
    assert_eq!(
        fs::read(temp.path().join("sync-user-recover")).expect("read sync"),
        br#"{"cursor":"old"}"#
    );

    let report = manager.recover_pending("user-recover").expect("recover");
    assert_eq!(report.transactions_recovered, 1);
    assert_eq!(report.operations_recovered, 1);
    assert_eq!(
        fs::read(temp.path().join("backend/db/user-recover.db")).expect("read recovered db"),
        b"new-db"
    );
    assert_eq!(
        fs::read(temp.path().join("sync-user-recover")).expect("read recovered sync"),
        br#"{"cursor":"new"}"#
    );
    assert_eq!(
        manager
            .pending_transaction_count("user-recover")
            .expect("pending count"),
        0
    );
}

#[test]
fn be023_dropping_uncommitted_transaction_discards_staged_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manager = GluonTxnManager::new(temp.path()).expect("txn manager");

    {
        let mut txn = manager.begin("user-abort").expect("begin txn");
        txn.stage_write("backend/db/user-abort.db", b"aborted")
            .expect("stage db");
    }

    assert!(!temp.path().join("backend/db/user-abort.db").exists());
    assert_eq!(
        manager
            .pending_transaction_count("user-abort")
            .expect("pending count"),
        0
    );
}
