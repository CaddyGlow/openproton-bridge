use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::imap::gluon_lock::{GluonLockError, GluonLockManager, GluonWriterLock};

const TXN_ROOT_DIR: &str = ".gluon-txn";
const LOCK_ROOT_DIR: &str = ".gluon-locks";
const JOURNAL_FILE: &str = "journal.json";
const COMMIT_MARKER_FILE: &str = "commit.marker";
const JOURNAL_VERSION: u32 = 1;

static NEXT_TXN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum GluonTxnError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("lock error: {0}")]
    Lock(#[from] GluonLockError),
    #[error("invalid transaction target path: {0}")]
    InvalidTargetPath(PathBuf),
    #[error("transaction is already closed")]
    TransactionClosed,
    #[error("recovery failed because neither staged nor target file exists (target: {target}, staged: {staged})")]
    MissingStageAndTarget { target: PathBuf, staged: PathBuf },
    #[error("injected failure after {applied} operations")]
    InjectedFailure { applied: usize },
}

pub type Result<T> = std::result::Result<T, GluonTxnError>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryReport {
    pub transactions_recovered: usize,
    pub operations_recovered: usize,
}

#[derive(Debug, Clone)]
pub struct GluonTxnManager {
    root: PathBuf,
    txn_root: PathBuf,
    lock_manager: GluonLockManager,
}

impl GluonTxnManager {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let lock_root = root.join(LOCK_ROOT_DIR);
        let lock_manager = GluonLockManager::new(&lock_root)?;
        let txn_root = root.join(TXN_ROOT_DIR);
        fs::create_dir_all(&txn_root)?;

        Ok(Self {
            root,
            txn_root,
            lock_manager,
        })
    }

    pub fn begin(&self, scope: &str) -> Result<GluonTxn> {
        let writer_lock = self.lock_manager.acquire_writer(scope)?;
        let scope_dir = self.txn_root.join(scope);
        fs::create_dir_all(&scope_dir)?;

        let txn_dir = scope_dir.join(make_txn_id());
        fs::create_dir_all(&txn_dir)?;
        let journal_path = txn_dir.join(JOURNAL_FILE);
        let marker_path = txn_dir.join(COMMIT_MARKER_FILE);

        Ok(GluonTxn {
            root: self.root.clone(),
            txn_dir,
            scope: scope.to_string(),
            journal_path,
            marker_path,
            entries: Vec::new(),
            writer_lock: Some(writer_lock),
            finished: false,
        })
    }

    pub fn pending_transaction_count(&self, scope: &str) -> Result<usize> {
        let scope_dir = self.txn_root.join(scope);
        Ok(count_pending_transactions(&scope_dir)?)
    }

    pub fn recover_pending(&self, scope: &str) -> Result<RecoveryReport> {
        let _writer_lock = self.lock_manager.acquire_writer(scope)?;
        self.recover_scope_locked(scope)
    }

    pub fn recover_pending_all(&self) -> Result<RecoveryReport> {
        if !self.txn_root.exists() {
            return Ok(RecoveryReport::default());
        }

        let mut total = RecoveryReport::default();
        for entry in fs::read_dir(&self.txn_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let scope = match entry.file_name().into_string() {
                Ok(scope) => scope,
                Err(_) => continue,
            };

            let report = self.recover_pending(&scope)?;
            total.transactions_recovered += report.transactions_recovered;
            total.operations_recovered += report.operations_recovered;
        }

        Ok(total)
    }

    fn recover_scope_locked(&self, scope: &str) -> Result<RecoveryReport> {
        let scope_dir = self.txn_root.join(scope);
        if !scope_dir.exists() {
            return Ok(RecoveryReport::default());
        }

        let mut report = RecoveryReport::default();

        for entry in fs::read_dir(&scope_dir)? {
            let entry = entry?;
            let txn_dir = entry.path();
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let journal_path = txn_dir.join(JOURNAL_FILE);
            let marker_path = txn_dir.join(COMMIT_MARKER_FILE);

            if !journal_path.exists() && !marker_path.exists() {
                let _ = fs::remove_dir_all(&txn_dir);
                continue;
            }
            if !journal_path.exists() {
                return Err(GluonTxnError::MissingStageAndTarget {
                    target: marker_path,
                    staged: journal_path,
                });
            }

            let mut journal = read_journal(&journal_path)?;
            let mut recovered_ops = 0usize;

            for index in 0..journal.entries.len() {
                if journal.entries[index].applied {
                    continue;
                }

                let target = journal.entries[index].target.clone();
                let staged = journal.entries[index].staged.clone();

                if staged.exists() {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::rename(&staged, &target)?;
                    journal.entries[index].applied = true;
                    write_journal(&journal_path, &journal)?;
                    recovered_ops += 1;
                    continue;
                }

                if target.exists() {
                    journal.entries[index].applied = true;
                    write_journal(&journal_path, &journal)?;
                    recovered_ops += 1;
                    continue;
                }

                return Err(GluonTxnError::MissingStageAndTarget { target, staged });
            }

            fs::remove_dir_all(&txn_dir)?;
            report.transactions_recovered += 1;
            report.operations_recovered += recovered_ops;
        }

        if dir_is_empty(&scope_dir)? {
            let _ = fs::remove_dir(&scope_dir);
        }

        Ok(report)
    }
}

#[derive(Debug)]
pub struct GluonTxn {
    root: PathBuf,
    txn_dir: PathBuf,
    scope: String,
    journal_path: PathBuf,
    marker_path: PathBuf,
    entries: Vec<TxnEntry>,
    writer_lock: Option<GluonWriterLock>,
    finished: bool,
}

impl GluonTxn {
    pub fn stage_write(&mut self, target: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Result<()> {
        self.ensure_open()?;

        let target = resolve_target(&self.root, target.as_ref())?;
        let staged_path = self
            .txn_dir
            .join(format!("stage-{:04}.tmp", self.entries.len()));
        fs::write(&staged_path, bytes.as_ref())?;

        self.entries.push(TxnEntry {
            target,
            staged: staged_path,
            applied: false,
        });
        Ok(())
    }

    pub fn commit(&mut self) -> Result<()> {
        self.commit_internal(None)
    }

    pub fn commit_with_injected_failure(&mut self, fail_after_operations: usize) -> Result<()> {
        self.commit_internal(Some(fail_after_operations))
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    fn ensure_open(&self) -> Result<()> {
        if self.finished {
            return Err(GluonTxnError::TransactionClosed);
        }
        Ok(())
    }

    fn commit_internal(&mut self, fail_after_operations: Option<usize>) -> Result<()> {
        self.ensure_open()?;

        if self.entries.is_empty() {
            self.finish_and_cleanup()?;
            return Ok(());
        }

        let mut journal = TxnJournal {
            version: JOURNAL_VERSION,
            scope: self.scope.clone(),
            entries: self.entries.clone(),
        };

        write_journal(&self.journal_path, &journal)?;
        fs::write(&self.marker_path, b"committing")?;

        let mut applied = 0usize;
        for index in 0..journal.entries.len() {
            if journal.entries[index].applied {
                continue;
            }

            let target = journal.entries[index].target.clone();
            let staged = journal.entries[index].staged.clone();
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(&staged, &target)?;

            journal.entries[index].applied = true;
            applied += 1;
            write_journal(&self.journal_path, &journal)?;

            if fail_after_operations.is_some_and(|limit| applied == limit) {
                self.entries = journal.entries;
                self.finished = true;
                self.writer_lock.take();
                return Err(GluonTxnError::InjectedFailure { applied });
            }
        }

        self.entries = journal.entries;
        self.finish_and_cleanup()?;
        Ok(())
    }

    fn finish_and_cleanup(&mut self) -> Result<()> {
        if self.txn_dir.exists() {
            fs::remove_dir_all(&self.txn_dir)?;
        }

        if let Some(scope_dir) = self.txn_dir.parent() {
            if dir_is_empty(scope_dir)? {
                let _ = fs::remove_dir(scope_dir);
            }
        }

        self.finished = true;
        self.writer_lock.take();
        Ok(())
    }
}

impl Drop for GluonTxn {
    fn drop(&mut self) {
        if self.finished {
            return;
        }

        if self.journal_path.exists() || self.marker_path.exists() {
            return;
        }

        let _ = fs::remove_dir_all(&self.txn_dir);
        if let Some(scope_dir) = self.txn_dir.parent() {
            if dir_is_empty(scope_dir).unwrap_or(false) {
                let _ = fs::remove_dir(scope_dir);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxnJournal {
    version: u32,
    scope: String,
    entries: Vec<TxnEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxnEntry {
    target: PathBuf,
    staged: PathBuf,
    applied: bool,
}

fn write_journal(path: &Path, journal: &TxnJournal) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec(journal)?;
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, payload)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn read_journal(path: &Path) -> Result<TxnJournal> {
    let payload = fs::read(path)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn resolve_target(root: &Path, target: &Path) -> Result<PathBuf> {
    if target.as_os_str().is_empty() {
        return Err(GluonTxnError::InvalidTargetPath(target.to_path_buf()));
    }
    if target.is_absolute() {
        return Ok(target.to_path_buf());
    }

    for component in target.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(GluonTxnError::InvalidTargetPath(target.to_path_buf()));
        }
    }

    Ok(root.join(target))
}

fn count_pending_transactions(scope_dir: &Path) -> std::io::Result<usize> {
    if !scope_dir.exists() {
        return Ok(0);
    }

    let mut count = 0usize;
    for entry in fs::read_dir(scope_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if path.join(JOURNAL_FILE).exists() || path.join(COMMIT_MARKER_FILE).exists() {
            count += 1;
        }
    }

    Ok(count)
}

fn dir_is_empty(path: &Path) -> std::io::Result<bool> {
    if !path.exists() {
        return Ok(true);
    }
    Ok(fs::read_dir(path)?.next().is_none())
}

fn make_txn_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NEXT_TXN_ID.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{}-{sequence}", std::process::id())
}
