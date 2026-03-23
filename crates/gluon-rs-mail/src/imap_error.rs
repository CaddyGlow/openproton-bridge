use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImapError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("mailbox not found: {0}")]
    MailboxNotFound(String),
    #[error("message not found: uid {0}")]
    MessageNotFound(u32),
    #[error("gluon artifact corruption detected at {path}: {reason}")]
    GluonCorruption { path: PathBuf, reason: String },
}

pub type ImapResult<T> = std::result::Result<T, ImapError>;
