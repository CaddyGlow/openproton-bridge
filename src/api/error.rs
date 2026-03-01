use thiserror::Error;

use super::types::HumanVerificationDetails;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("API error {code}: {message}")]
    Api {
        code: i64,
        message: String,
        details: Option<serde_json::Value>,
    },

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
        ApiError::Api { code, message, .. } => {
            *code == 401
                || *code == 10013
                || message.to_ascii_lowercase().contains("token")
                || message.to_ascii_lowercase().contains("auth")
        }
        _ => false,
    }
}

pub fn human_verification_details(err: &ApiError) -> Option<HumanVerificationDetails> {
    let ApiError::Api { code, .. } = err else {
        return None;
    };

    if *code != 9001 {
        return None;
    }

    any_human_verification_details(err)
}

pub fn any_human_verification_details(err: &ApiError) -> Option<HumanVerificationDetails> {
    let ApiError::Api {
        details: Some(details),
        ..
    } = err
    else {
        return None;
    };

    let parsed: HumanVerificationDetails = serde_json::from_value(details.clone()).ok()?;
    parsed.is_usable().then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_verification_details_parses_valid_payload() {
        let err = ApiError::Api {
            code: 9001,
            message: "Human verification required".to_string(),
            details: Some(serde_json::json!({
                "HumanVerificationMethods": ["captcha"],
                "HumanVerificationToken": "token-123"
            })),
        };
        let hv = human_verification_details(&err).expect("expected HV details");
        assert_eq!(hv.human_verification_methods, vec!["captcha"]);
        assert_eq!(hv.human_verification_token, "token-123");
    }

    #[test]
    fn human_verification_details_rejects_non_hv_errors() {
        let err = ApiError::Api {
            code: 8002,
            message: "Invalid credentials".to_string(),
            details: Some(serde_json::json!({
                "HumanVerificationMethods": ["captcha"],
                "HumanVerificationToken": "token-123"
            })),
        };
        assert!(human_verification_details(&err).is_none());
    }

    #[test]
    fn any_human_verification_details_parses_details_for_non_9001_code() {
        let err = ApiError::Api {
            code: 12087,
            message: "CAPTCHA validation failed".to_string(),
            details: Some(serde_json::json!({
                "HumanVerificationMethods": ["captcha"],
                "HumanVerificationToken": "token-456"
            })),
        };
        let hv = any_human_verification_details(&err).expect("expected HV details");
        assert_eq!(hv.human_verification_methods, vec!["captcha"]);
        assert_eq!(hv.human_verification_token, "token-456");
    }
}
