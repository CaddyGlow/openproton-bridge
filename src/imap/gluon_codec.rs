use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GluonFileFamily {
    MessageStoreBlob,
    SqlitePrimaryDb,
    SqliteWalSidecar,
    SqliteShmSidecar,
    DeferredDeletePool,
    ImapSyncStateStable,
    ImapSyncStateTmp,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GluonDecodedFile {
    MessageStoreBlob(Vec<u8>),
    SqlitePrimaryDb(Vec<u8>),
    SqliteWalSidecar(Vec<u8>),
    SqliteShmSidecar(Vec<u8>),
    DeferredDeletePool(Vec<u8>),
    ImapSyncStateStable { bytes: Vec<u8>, json: Value },
    ImapSyncStateTmp { bytes: Vec<u8>, json: Value },
}

impl GluonDecodedFile {
    pub fn family(&self) -> GluonFileFamily {
        match self {
            Self::MessageStoreBlob(_) => GluonFileFamily::MessageStoreBlob,
            Self::SqlitePrimaryDb(_) => GluonFileFamily::SqlitePrimaryDb,
            Self::SqliteWalSidecar(_) => GluonFileFamily::SqliteWalSidecar,
            Self::SqliteShmSidecar(_) => GluonFileFamily::SqliteShmSidecar,
            Self::DeferredDeletePool(_) => GluonFileFamily::DeferredDeletePool,
            Self::ImapSyncStateStable { .. } => GluonFileFamily::ImapSyncStateStable,
            Self::ImapSyncStateTmp { .. } => GluonFileFamily::ImapSyncStateTmp,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::MessageStoreBlob(bytes)
            | Self::SqlitePrimaryDb(bytes)
            | Self::SqliteWalSidecar(bytes)
            | Self::SqliteShmSidecar(bytes)
            | Self::DeferredDeletePool(bytes) => bytes,
            Self::ImapSyncStateStable { bytes, .. } | Self::ImapSyncStateTmp { bytes, .. } => bytes,
        }
    }

    pub fn sync_state_json(&self) -> Option<&Value> {
        match self {
            Self::ImapSyncStateStable { json, .. } | Self::ImapSyncStateTmp { json, .. } => {
                Some(json)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum GluonCodecError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported Gluon file family for path: {0}")]
    UnsupportedFamily(PathBuf),
    #[error("invalid sync state JSON for path {path}: {source}")]
    InvalidSyncStateJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("path family mismatch for {path}: expected {expected:?}, got {actual:?}")]
    PathFamilyMismatch {
        path: PathBuf,
        expected: GluonFileFamily,
        actual: GluonFileFamily,
    },
}

pub type Result<T> = std::result::Result<T, GluonCodecError>;

pub fn detect_family(path: &Path) -> Option<GluonFileFamily> {
    let file_name = path.file_name().and_then(|name| name.to_str())?;
    if file_name.starts_with("sync-") {
        if file_name.ends_with(".tmp") {
            return Some(GluonFileFamily::ImapSyncStateTmp);
        }
        return Some(GluonFileFamily::ImapSyncStateStable);
    }

    let normalized = normalize_path(path);

    if normalized.contains("/backend/db/deferred_delete/") {
        return Some(GluonFileFamily::DeferredDeletePool);
    }

    if normalized.contains("/backend/store/") {
        return Some(GluonFileFamily::MessageStoreBlob);
    }

    if normalized.contains("/backend/db/") {
        if normalized.ends_with(".db-wal") {
            return Some(GluonFileFamily::SqliteWalSidecar);
        }
        if normalized.ends_with(".db-shm") {
            return Some(GluonFileFamily::SqliteShmSidecar);
        }
        if normalized.ends_with(".db") {
            return Some(GluonFileFamily::SqlitePrimaryDb);
        }
    }

    None
}

pub fn decode_file(path: &Path) -> Result<GluonDecodedFile> {
    let bytes = fs::read(path)?;
    decode_bytes(path, &bytes)
}

pub fn decode_bytes(path: &Path, bytes: &[u8]) -> Result<GluonDecodedFile> {
    let family =
        detect_family(path).ok_or_else(|| GluonCodecError::UnsupportedFamily(path.into()))?;

    let decoded = match family {
        GluonFileFamily::MessageStoreBlob => GluonDecodedFile::MessageStoreBlob(bytes.to_vec()),
        GluonFileFamily::SqlitePrimaryDb => GluonDecodedFile::SqlitePrimaryDb(bytes.to_vec()),
        GluonFileFamily::SqliteWalSidecar => GluonDecodedFile::SqliteWalSidecar(bytes.to_vec()),
        GluonFileFamily::SqliteShmSidecar => GluonDecodedFile::SqliteShmSidecar(bytes.to_vec()),
        GluonFileFamily::DeferredDeletePool => GluonDecodedFile::DeferredDeletePool(bytes.to_vec()),
        GluonFileFamily::ImapSyncStateStable => {
            let json = serde_json::from_slice(bytes).map_err(|source| {
                GluonCodecError::InvalidSyncStateJson {
                    path: path.into(),
                    source,
                }
            })?;
            GluonDecodedFile::ImapSyncStateStable {
                bytes: bytes.to_vec(),
                json,
            }
        }
        GluonFileFamily::ImapSyncStateTmp => {
            let json = serde_json::from_slice(bytes).map_err(|source| {
                GluonCodecError::InvalidSyncStateJson {
                    path: path.into(),
                    source,
                }
            })?;
            GluonDecodedFile::ImapSyncStateTmp {
                bytes: bytes.to_vec(),
                json,
            }
        }
    };

    Ok(decoded)
}

pub fn encode(decoded: &GluonDecodedFile) -> Vec<u8> {
    decoded.bytes().to_vec()
}

pub fn write_file(path: &Path, decoded: &GluonDecodedFile) -> Result<()> {
    let expected =
        detect_family(path).ok_or_else(|| GluonCodecError::UnsupportedFamily(path.into()))?;
    let actual = decoded.family();
    if expected != actual {
        return Err(GluonCodecError::PathFamilyMismatch {
            path: path.into(),
            expected,
            actual,
        });
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, encode(decoded))?;
    Ok(())
}

fn normalize_path(path: &Path) -> String {
    format!("/{}", path.to_string_lossy().replace('\\', "/"))
}
