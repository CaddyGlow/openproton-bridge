pub mod incremental;
pub mod query;
pub mod schema;
pub mod store;
pub mod sync_calendar;
pub mod sync_contacts;
pub mod types;

use std::future::Future;
use std::time::Duration;

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

const MAX_TRANSIENT_API_ATTEMPTS: usize = 3;
const BASE_RETRY_DELAY_MS: u64 = 200;
const RATE_LIMIT_RETRY_DELAY_MS: u64 = 750;

pub(crate) async fn run_with_api_retry<T, F, Fut>(mut op: F) -> crate::api::error::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = crate::api::error::Result<T>>,
{
    let mut last_error = None;
    for attempt in 0..MAX_TRANSIENT_API_ATTEMPTS {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt + 1 < MAX_TRANSIENT_API_ATTEMPTS && is_transient_api_error(&err) {
                    tokio::time::sleep(retry_delay_for_error(&err, attempt)).await;
                    last_error = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        crate::api::error::ApiError::Auth("exhausted transient PIM API retries".to_string())
    }))
}

fn is_transient_api_error(err: &crate::api::error::ApiError) -> bool {
    match err {
        crate::api::error::ApiError::Http(http) => http.is_timeout() || http.is_connect(),
        crate::api::error::ApiError::Api { code, .. } => {
            matches!(*code, 408 | 429 | 500 | 502 | 503 | 504)
        }
        _ => false,
    }
}

fn retry_delay_for_error(err: &crate::api::error::ApiError, attempt: usize) -> Duration {
    let exponential_ms = BASE_RETRY_DELAY_MS.saturating_mul(1 << attempt.min(4));
    if matches!(err, crate::api::error::ApiError::Api { code: 429, .. }) {
        Duration::from_millis(RATE_LIMIT_RETRY_DELAY_MS.max(exponential_ms))
    } else {
        Duration::from_millis(exponential_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::{is_transient_api_error, retry_delay_for_error};
    use crate::api::error::ApiError;
    use std::time::Duration;

    #[test]
    fn transient_api_error_helper_matches_expected_codes() {
        assert!(is_transient_api_error(&ApiError::Api {
            code: 429,
            message: "rate limit".to_string(),
            details: None,
        }));
        assert!(is_transient_api_error(&ApiError::Api {
            code: 503,
            message: "unavailable".to_string(),
            details: None,
        }));
        assert!(!is_transient_api_error(&ApiError::Api {
            code: 400,
            message: "bad request".to_string(),
            details: None,
        }));
    }

    #[test]
    fn retry_delay_prefers_rate_limit_floor() {
        let delay = retry_delay_for_error(
            &ApiError::Api {
                code: 429,
                message: "rate limit".to_string(),
                details: None,
            },
            0,
        );
        assert!(delay >= Duration::from_millis(750));
    }
}
