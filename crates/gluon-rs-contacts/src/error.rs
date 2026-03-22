use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContactsStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, ContactsStoreError>;
