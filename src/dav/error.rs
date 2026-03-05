use std::io;

#[derive(Debug, thiserror::Error)]
pub enum DavError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid http request: {0}")]
    InvalidRequest(&'static str),
}

impl DavError {
    pub fn status_line(&self) -> &'static str {
        match self {
            Self::Io(_) => "500 Internal Server Error",
            Self::InvalidRequest(_) => "400 Bad Request",
        }
    }
}

pub type Result<T> = std::result::Result<T, DavError>;
