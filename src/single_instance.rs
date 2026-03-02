use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use fs2::FileExt;

use crate::paths::RuntimePaths;

const BRIDGE_LOCK_FILE: &str = "bridge-v3.lock";

#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

pub fn acquire_bridge_instance_lock(runtime_paths: &RuntimePaths) -> anyhow::Result<InstanceLock> {
    let lock_path = runtime_paths.cache_dir().join(BRIDGE_LOCK_FILE);
    acquire_lock(&lock_path)
}

fn acquire_lock(lock_path: &Path) -> anyhow::Result<InstanceLock> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create lock directory {}", parent.display()))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .with_context(|| format!("failed to open lock file {}", lock_path.display()))?;

    match file.try_lock_exclusive() {
        Ok(()) => {
            write_lock_metadata(&mut file)
                .with_context(|| format!("failed to write lock file {}", lock_path.display()))?;
            Ok(InstanceLock {
                _file: file,
                path: lock_path.to_path_buf(),
            })
        }
        Err(err) if err.kind() == ErrorKind::WouldBlock => {
            let holder = read_lock_metadata(&mut file)
                .ok()
                .map(|raw| raw.trim().to_string())
                .filter(|raw| !raw.is_empty())
                .unwrap_or_else(|| "unknown holder".to_string());
            anyhow::bail!(
                "another bridge instance is already running (lock file: {}, holder: {})",
                lock_path.display(),
                holder
            );
        }
        Err(err) => Err(err).with_context(|| format!("failed to lock {}", lock_path.display())),
    }
}

fn write_lock_metadata(file: &mut File) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "pid={}", std::process::id())?;
    writeln!(file, "version={}", env!("CARGO_PKG_VERSION"))?;
    file.flush()
}

fn read_lock_metadata(file: &mut File) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_attempt_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("bridge-v3.lock");

        let first = acquire_lock(&lock_path).unwrap();
        let second = acquire_lock(&lock_path).unwrap_err();

        assert!(second.to_string().contains("already running"));
        assert_eq!(first.path(), lock_path.as_path());
    }
}
