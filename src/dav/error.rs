use std::io;

#[derive(Debug, thiserror::Error)]
pub enum DavError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("invalid http request: {0}")]
    InvalidRequest(&'static str),
    #[error("backend error: {0}")]
    Backend(String),
}

impl DavError {
    pub fn status_line(&self) -> &'static str {
        match self {
            Self::Io(_) => "500 Internal Server Error",
            Self::Tls(_) => "500 Internal Server Error",
            Self::InvalidRequest(_) => "400 Bad Request",
            Self::Backend(_) => "500 Internal Server Error",
        }
    }
}

pub type Result<T> = std::result::Result<T, DavError>;
