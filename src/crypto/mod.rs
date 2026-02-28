pub mod decrypt;
pub mod encrypt;
pub mod keys;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("PGP error: {0}")]
    Pgp(#[from] anyhow::Error),

    #[error("no active key found")]
    NoActiveKey,

    #[error("failed to unlock key: {0}")]
    UnlockFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("session key error: {0}")]
    SessionKeyError(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
