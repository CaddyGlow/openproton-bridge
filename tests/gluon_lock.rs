use openproton_bridge::imap::gluon_lock::{GluonLockError, GluonLockManager};

#[test]
fn be022_blocks_second_writer_for_same_scope() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manager_a = GluonLockManager::with_holder_id(temp.path(), "lane-c-a").expect("manager a");
    let manager_b = GluonLockManager::with_holder_id(temp.path(), "lane-c-b").expect("manager b");

    let _lock_a = manager_a
        .acquire_writer("user-123")
        .expect("first writer lock");
    let err = manager_b.acquire_writer("user-123").unwrap_err();

    assert!(matches!(
        err,
        GluonLockError::Busy {
            scope,
            holder,
            ..
        } if scope == "user-123" && holder.contains("lane-c-a")
    ));
}

#[test]
fn be022_reacquire_after_release_succeeds() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manager = GluonLockManager::new(temp.path()).expect("manager");

    {
        let _first = manager
            .acquire_writer("user-456")
            .expect("first writer lock");
    }

    let _second = manager
        .acquire_writer("user-456")
        .expect("writer lock after release");
}

#[test]
fn be022_allows_parallel_writers_for_distinct_scopes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manager = GluonLockManager::new(temp.path()).expect("manager");

    let _user_a = manager.acquire_writer("user-a").expect("user-a lock");
    let _user_b = manager.acquire_writer("user-b").expect("user-b lock");
}

#[test]
fn be022_rejects_invalid_scope_inputs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manager = GluonLockManager::new(temp.path()).expect("manager");

    let err = manager.acquire_writer("../escape").unwrap_err();
    assert!(matches!(err, GluonLockError::InvalidScope(scope) if scope == "../escape"));
}
