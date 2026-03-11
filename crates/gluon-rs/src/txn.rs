use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    error::Result,
    layout::CacheLayout,
};
use uuid::Uuid;

const TXN_DIR_NAME: &str = ".gluon-txn";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnPaths {
    scope: String,
    root: PathBuf,
}

impl TxnPaths {
    pub fn new(layout: &CacheLayout, scope: impl Into<String>) -> Result<Self> {
        let scope = scope.into();
        let _ = layout.account_paths(scope.clone())?;

        Ok(Self {
            scope,
            root: layout.root().to_path_buf(),
        })
    }

    pub fn journal_dir(&self) -> PathBuf {
        self.root.join(TXN_DIR_NAME)
    }

    pub fn pending_journal_path(&self) -> PathBuf {
        self.journal_dir().join(format!("{}.json", self.scope))
    }

    pub fn lock_path(&self) -> PathBuf {
        self.root
            .join(".gluon-locks")
            .join(format!("{}.lock", self.scope))
    }
}

#[derive(Debug, Clone)]
pub struct DeferredDeleteManager {
    db_dir: PathBuf,
}

impl DeferredDeleteManager {
    pub fn new(db_dir: impl AsRef<Path>) -> Result<Self> {
        let db_dir = db_dir.as_ref().to_path_buf();
        fs::create_dir_all(&db_dir)?;
        Ok(Self { db_dir })
    }

    pub fn deferred_delete_dir(&self) -> PathBuf {
        self.db_dir.join("deferred_delete")
    }

    pub fn delete_db_files(&self, user_id: &str) -> Result<usize> {
        fs::create_dir_all(self.deferred_delete_dir())?;
        let mut moved = 0usize;
        for file in [
            self.db_dir.join(format!("{user_id}.db")),
            self.db_dir.join(format!("{user_id}.db-wal")),
            self.db_dir.join(format!("{user_id}.db-shm")),
        ] {
            if !file.exists() {
                continue;
            }
            let target = self.deferred_delete_dir().join(Uuid::new_v4().to_string());
            fs::rename(file, target)?;
            moved += 1;
        }

        Ok(moved)
    }

    pub fn cleanup_deferred_delete_dir(&self) -> Result<()> {
        match fs::remove_dir_all(self.deferred_delete_dir()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use crate::layout::CacheLayout;

    use super::{DeferredDeleteManager, TxnPaths};

    #[test]
    fn resolves_expected_journal_paths() {
        let layout = CacheLayout::new("/tmp/gluon");
        let txn = TxnPaths::new(&layout, "user-1").expect("txn");

        assert_eq!(txn.journal_dir(), Path::new("/tmp/gluon/.gluon-txn"));
        assert_eq!(
            txn.pending_journal_path(),
            Path::new("/tmp/gluon/.gluon-txn/user-1.json")
        );
        assert_eq!(txn.lock_path(), Path::new("/tmp/gluon/.gluon-locks/user-1.lock"));
    }

    #[test]
    fn moves_database_files_to_deferred_delete_pool() {
        let temp = tempdir().expect("tempdir");
        let db_dir = temp.path().join("backend/db");
        std::fs::create_dir_all(&db_dir).expect("db dir");
        std::fs::write(db_dir.join("user-1.db"), b"db").expect("db");
        std::fs::write(db_dir.join("user-1.db-wal"), b"wal").expect("wal");
        std::fs::write(db_dir.join("user-1.db-shm"), b"shm").expect("shm");

        let manager = DeferredDeleteManager::new(&db_dir).expect("manager");
        let moved = manager.delete_db_files("user-1").expect("move");
        assert_eq!(moved, 3);
        assert!(!db_dir.join("user-1.db").exists());
        assert!(!db_dir.join("user-1.db-wal").exists());
        assert!(!db_dir.join("user-1.db-shm").exists());
        assert_eq!(
            std::fs::read_dir(manager.deferred_delete_dir())
                .expect("read deferred")
                .count(),
            3
        );
    }

    #[test]
    fn cleans_up_deferred_delete_pool() {
        let temp = tempdir().expect("tempdir");
        let db_dir = temp.path().join("backend/db");
        let manager = DeferredDeleteManager::new(&db_dir).expect("manager");
        std::fs::create_dir_all(manager.deferred_delete_dir()).expect("deferred dir");
        std::fs::write(manager.deferred_delete_dir().join("stale-1"), b"a").expect("file");
        std::fs::write(manager.deferred_delete_dir().join("stale-2"), b"b").expect("file");

        manager
            .cleanup_deferred_delete_dir()
            .expect("cleanup deferred delete");
        assert!(!manager.deferred_delete_dir().exists());
    }

    #[test]
    fn only_moves_exact_account_database_files() {
        let temp = tempdir().expect("tempdir");
        let db_dir = temp.path().join("backend/db");
        std::fs::create_dir_all(&db_dir).expect("db dir");
        std::fs::write(db_dir.join("user-1.db"), b"db").expect("db");
        std::fs::write(db_dir.join("user-1.db-wal"), b"wal").expect("wal");
        std::fs::write(db_dir.join("user-10.db"), b"other-db").expect("other db");
        std::fs::write(db_dir.join("user-100.db-shm"), b"other-shm").expect("other shm");

        let manager = DeferredDeleteManager::new(&db_dir).expect("manager");
        let moved = manager.delete_db_files("user-1").expect("move");

        assert_eq!(moved, 2);
        assert!(!db_dir.join("user-1.db").exists());
        assert!(!db_dir.join("user-1.db-wal").exists());
        assert!(db_dir.join("user-10.db").exists());
        assert!(db_dir.join("user-100.db-shm").exists());
    }
}
