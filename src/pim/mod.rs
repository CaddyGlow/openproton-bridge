pub mod incremental;
pub mod schema;
pub mod store;
pub mod sync_calendar;
pub mod sync_contacts;
pub mod types;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PimError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, PimError>;
