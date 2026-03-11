use thiserror::Error;

#[derive(Debug, Error)]
pub enum GluonError {
    #[error(transparent)]
    Core(#[from] gluon_rs_core::GluonCoreError),

    #[error("sqlite database is missing required table: {table}")]
    MissingRequiredTable { table: String },

    #[error("schema is not upstream-compatible: {family}")]
    IncompatibleSchema { family: String },

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, GluonError>;
