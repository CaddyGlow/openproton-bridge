use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GluonLockError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid lock scope: {0}")]
    InvalidScope(String),
    #[error("writer lock for scope {scope} is already held (path: {path}, holder: {holder})")]
    Busy {
        scope: String,
        path: PathBuf,
        holder: String,
    },
}

pub type Result<T> = std::result::Result<T, GluonLockError>;

#[derive(Debug, Clone)]
pub struct GluonLockManager {
    lock_root: PathBuf,
    holder_id: String,
}

impl GluonLockManager {
    pub fn new(lock_root: impl AsRef<Path>) -> Result<Self> {
        Self::with_holder_id(lock_root, default_holder_id())
    }

    pub fn with_holder_id(
        lock_root: impl AsRef<Path>,
        holder_id: impl Into<String>,
    ) -> Result<Self> {
        let holder_id = holder_id.into();
        if holder_id.trim().is_empty() {
            return Err(GluonLockError::InvalidScope(String::from("holder_id")));
        }

        let lock_root = lock_root.as_ref().to_path_buf();
        fs::create_dir_all(&lock_root)?;

        Ok(Self {
            lock_root,
            holder_id,
        })
    }

    pub fn lock_path_for(&self, scope: &str) -> Result<PathBuf> {
        validate_scope(scope)?;
        Ok(self
            .lock_root
            .join(format!("gluon-{}.lock", encode_scope(scope))))
    }

    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    pub fn acquire_writer(&self, scope: &str) -> Result<GluonWriterLock> {
        let lock_path = self.lock_path_for(scope)?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)?;

        match file.try_lock_exclusive() {
            Ok(()) => {
                write_lock_metadata(&mut file, scope, &self.holder_id)?;
                Ok(GluonWriterLock {
                    _file: file,
                    path: lock_path,
                    scope: scope.to_string(),
                })
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                let holder = read_lock_metadata(&mut file)
                    .ok()
                    .map(|raw| raw.trim().to_string())
                    .filter(|raw| !raw.is_empty())
                    .unwrap_or_else(|| String::from("unknown holder"));
                Err(GluonLockError::Busy {
                    scope: scope.to_string(),
                    path: lock_path,
                    holder,
                })
            }
            Err(err) => Err(GluonLockError::Io(err)),
        }
    }
}

#[derive(Debug)]
pub struct GluonWriterLock {
    _file: File,
    path: PathBuf,
    scope: String,
}

impl GluonWriterLock {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }
}

impl Drop for GluonWriterLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

fn validate_scope(scope: &str) -> Result<()> {
    let invalid = scope.is_empty()
        || scope == "."
        || scope == ".."
        || scope.contains('/')
        || scope.contains('\\')
        || scope.as_bytes().contains(&0);
    if invalid {
        return Err(GluonLockError::InvalidScope(scope.to_string()));
    }
    Ok(())
}

fn encode_scope(scope: &str) -> String {
    let mut encoded = String::with_capacity(scope.len() * 2);
    for byte in scope.as_bytes() {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn default_holder_id() -> String {
    format!(
        "pid={} version={}",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    )
}

fn write_lock_metadata(file: &mut File, scope: &str, holder: &str) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "scope={scope}")?;
    writeln!(file, "holder={holder}")?;
    writeln!(file, "pid={}", std::process::id())?;
    file.flush()
}

fn read_lock_metadata(file: &mut File) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    if let Some(holder_line) = contents.lines().find(|line| line.starts_with("holder=")) {
        return Ok(holder_line.trim_start_matches("holder=").to_string());
    }
    Ok(contents)
}
