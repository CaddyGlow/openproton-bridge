use std::path::{Path, PathBuf};

use crate::error::{GluonError, Result};

pub const BACKEND_DIR: &str = "backend";
pub const DB_DIR: &str = "db";
pub const STORE_DIR: &str = "store";
pub const DEFERRED_DELETE_DIR: &str = "deferred_delete";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheLayout {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPaths {
    storage_user_id: String,
    root: PathBuf,
}

impl CacheLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn backend_dir(&self) -> PathBuf {
        self.root.join(BACKEND_DIR)
    }

    pub fn db_dir(&self) -> PathBuf {
        self.backend_dir().join(DB_DIR)
    }

    pub fn store_dir(&self) -> PathBuf {
        self.backend_dir().join(STORE_DIR)
    }

    pub fn deferred_delete_dir(&self) -> PathBuf {
        self.db_dir().join(DEFERRED_DELETE_DIR)
    }

    pub fn account_paths(&self, storage_user_id: impl Into<String>) -> Result<AccountPaths> {
        let storage_user_id = storage_user_id.into();
        validate_component(&storage_user_id)?;

        Ok(AccountPaths {
            root: self.root.clone(),
            storage_user_id,
        })
    }

    pub fn ensure_base_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(self.store_dir())?;
        std::fs::create_dir_all(self.db_dir())?;
        std::fs::create_dir_all(self.deferred_delete_dir())?;
        Ok(())
    }
}

impl AccountPaths {
    pub fn storage_user_id(&self) -> &str {
        &self.storage_user_id
    }

    pub fn store_dir(&self) -> PathBuf {
        self.root
            .join(BACKEND_DIR)
            .join(STORE_DIR)
            .join(&self.storage_user_id)
    }

    pub fn primary_db_path(&self) -> PathBuf {
        self.root
            .join(BACKEND_DIR)
            .join(DB_DIR)
            .join(format!("{}.db", self.storage_user_id))
    }

    pub fn wal_path(&self) -> PathBuf {
        self.root
            .join(BACKEND_DIR)
            .join(DB_DIR)
            .join(format!("{}.db-wal", self.storage_user_id))
    }

    pub fn shm_path(&self) -> PathBuf {
        self.root
            .join(BACKEND_DIR)
            .join(DB_DIR)
            .join(format!("{}.db-shm", self.storage_user_id))
    }

    pub fn deferred_delete_dir(&self) -> PathBuf {
        self.root
            .join(BACKEND_DIR)
            .join(DB_DIR)
            .join(DEFERRED_DELETE_DIR)
    }

    pub fn blob_path(&self, internal_message_id: &str) -> Result<PathBuf> {
        validate_component(internal_message_id)?;
        Ok(self.store_dir().join(internal_message_id))
    }
}

fn validate_component(component: &str) -> Result<()> {
    let invalid = component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\');
    if invalid {
        return Err(GluonError::InvalidPathComponent {
            component: component.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::CacheLayout;

    #[test]
    fn resolves_upstream_layout_paths() {
        let layout = CacheLayout::new("/tmp/gluon-cache");
        let account = layout.account_paths("user-42").expect("account paths");

        assert_eq!(layout.store_dir(), Path::new("/tmp/gluon-cache/backend/store"));
        assert_eq!(layout.db_dir(), Path::new("/tmp/gluon-cache/backend/db"));
        assert_eq!(
            account.store_dir(),
            Path::new("/tmp/gluon-cache/backend/store/user-42")
        );
        assert_eq!(
            account.primary_db_path(),
            Path::new("/tmp/gluon-cache/backend/db/user-42.db")
        );
        assert_eq!(
            account.wal_path(),
            Path::new("/tmp/gluon-cache/backend/db/user-42.db-wal")
        );
        assert_eq!(
            account.shm_path(),
            Path::new("/tmp/gluon-cache/backend/db/user-42.db-shm")
        );
    }
}
