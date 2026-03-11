use std::path::PathBuf;

use crate::{error::Result, layout::CacheLayout};

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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::layout::CacheLayout;

    use super::TxnPaths;

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
}
