pub mod convert;
pub mod gluon_codec;
pub mod gluon_connector;
pub mod gluon_lock;
pub mod gluon_mailbox_mutation;
pub mod gluon_mailbox_view;
pub mod gluon_txn;
pub mod mailbox;
pub mod mailbox_catalog;
pub mod rfc822;

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImapError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("API error: {0}")]
    Api(#[from] crate::api::error::ApiError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
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

impl From<gluon_rs_mail::ImapError> for ImapError {
    fn from(e: gluon_rs_mail::ImapError) -> Self {
        match e {
            gluon_rs_mail::ImapError::Io(io) => ImapError::Io(io),
            gluon_rs_mail::ImapError::Tls(msg) => ImapError::Tls(msg),
            gluon_rs_mail::ImapError::Upstream(msg) => ImapError::Protocol(msg),
            gluon_rs_mail::ImapError::Protocol(msg) => ImapError::Protocol(msg),
            gluon_rs_mail::ImapError::AuthFailed => ImapError::AuthFailed,
            gluon_rs_mail::ImapError::MailboxNotFound(name) => ImapError::MailboxNotFound(name),
            gluon_rs_mail::ImapError::MessageNotFound(uid) => ImapError::MessageNotFound(uid),
            gluon_rs_mail::ImapError::GluonCorruption { path, reason } => {
                ImapError::GluonCorruption { path, reason }
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, ImapError>;
