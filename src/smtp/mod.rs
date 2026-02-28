pub mod send;
pub mod server;
pub mod session;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmtpError {
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
    #[error("invalid sender: {0}")]
    InvalidSender(String),
    #[error("no recipients specified")]
    NoRecipients,
    #[error("message parse error: {0}")]
    MessageParse(String),
}

pub type Result<T> = std::result::Result<T, SmtpError>;
