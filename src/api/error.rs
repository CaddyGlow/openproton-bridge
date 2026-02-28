use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("API error {code}: {message}")]
    Api { code: i64, message: String },

    #[error("SRP error: {0}")]
    Srp(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("2FA required")]
    TwoFactorRequired,

    #[error("Not logged in")]
    NotLoggedIn,

    #[error("Session expired")]
    SessionExpired,
}

pub type Result<T> = std::result::Result<T, ApiError>;

pub fn is_auth_error(err: &ApiError) -> bool {
    match err {
        ApiError::SessionExpired | ApiError::Auth(_) | ApiError::TwoFactorRequired => true,
        ApiError::Api { code, message } => {
            *code == 401
                || *code == 10013
                || message.to_ascii_lowercase().contains("token")
                || message.to_ascii_lowercase().contains("auth")
        }
        _ => false,
    }
}
