use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GluonCoreError {
    #[error("invalid path component: {component}")]
    InvalidPathComponent { component: String },

    #[error("unknown storage user id: {storage_user_id}")]
    UnknownStorageUserId { storage_user_id: String },

    #[error("duplicate account id in bootstrap: {account_id}")]
    DuplicateAccountId { account_id: String },

    #[error("duplicate storage user id in bootstrap: {storage_user_id}")]
    DuplicateStorageUserId { storage_user_id: String },

    #[error("invalid gluon key length {length}; expected 32 bytes")]
    InvalidKeyLength { length: usize },

    #[error("cryptography error")]
    Crypto,

    #[error("invalid blob: {reason}")]
    InvalidBlob { reason: String },

    #[error("cache root does not exist: {path}")]
    MissingCacheRoot { path: PathBuf },

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GluonCoreError>;

impl From<aes_gcm::Error> for GluonCoreError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::Crypto
    }
}
