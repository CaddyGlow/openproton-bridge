pub mod command;
pub mod gluon_codec;
pub mod mailbox;
pub mod response;
pub mod rfc822;
pub mod server;
pub mod session;
pub mod store;

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
}

pub type Result<T> = std::result::Result<T, ImapError>;
