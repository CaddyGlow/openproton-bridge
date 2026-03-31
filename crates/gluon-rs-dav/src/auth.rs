use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::types::AuthContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavAuthError {
    MissingAuthorization,
    InvalidAuthorization,
    InvalidCredentials,
}

/// Trait for resolving DAV authentication.
///
/// Implemented by the main crate to map bridge passwords to account sessions.
pub trait DavAuthenticator: Send + Sync {
    fn resolve_login(&self, username: &str, password: &str) -> Option<AuthContext>;
}

pub fn resolve_basic_auth(
    headers: &HashMap<String, String>,
    authenticator: &dyn DavAuthenticator,
) -> std::result::Result<AuthContext, DavAuthError> {
    let Some(authorization) = headers.get("authorization") else {
        tracing::trace!(
            header_present = false,
            "dav auth check: missing authorization header"
        );
        return Err(DavAuthError::MissingAuthorization);
    };
    tracing::trace!(
        header_present = true,
        header_len = authorization.len(),
        has_basic_prefix =
            authorization.starts_with("Basic ") || authorization.starts_with("basic "),
        "dav auth check: authorization header received"
    );

    let encoded = match authorization
        .strip_prefix("Basic ")
        .or_else(|| authorization.strip_prefix("basic "))
    {
        Some(value) => value.trim(),
        None => {
            tracing::trace!("dav auth check: authorization header is not Basic");
            return Err(DavAuthError::InvalidAuthorization);
        }
    };
    tracing::trace!(
        encoded_len = encoded.len(),
        "dav auth check: extracted basic payload"
    );

    let decoded = match BASE64_STANDARD.decode(encoded.as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            tracing::trace!("dav auth check: invalid base64 in authorization header");
            return Err(DavAuthError::InvalidAuthorization);
        }
    };
    let decoded = match String::from_utf8(decoded) {
        Ok(value) => value,
        Err(_) => {
            tracing::trace!("dav auth check: decoded authorization is not utf-8");
            return Err(DavAuthError::InvalidAuthorization);
        }
    };
    let Some((username, password)) = decoded.split_once(':') else {
        tracing::trace!(
            "dav auth check: decoded authorization missing username:password separator"
        );
        return Err(DavAuthError::InvalidAuthorization);
    };
    tracing::trace!(
        username = username,
        password_len = password.len(),
        "dav auth check: parsed basic credentials"
    );

    let context = authenticator
        .resolve_login(username, password)
        .ok_or(DavAuthError::InvalidCredentials);
    match &context {
        Ok(resolved) => tracing::trace!(
            username = username,
            account_id = resolved.account_id,
            "dav auth check: credentials resolved"
        ),
        Err(_) => tracing::trace!(
            username = username,
            "dav auth check: credentials did not match any active account"
        ),
    }
    context
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;

    use crate::types::AuthContext;

    use super::{resolve_basic_auth, DavAuthError, DavAuthenticator};

    struct TestAuth;

    impl DavAuthenticator for TestAuth {
        fn resolve_login(&self, username: &str, password: &str) -> Option<AuthContext> {
            if username == "alice@proton.me" && password == "secret" {
                Some(AuthContext {
                    account_id: "uid-1".to_string(),
                    primary_email: "alice@proton.me".to_string(),
                })
            } else {
                None
            }
        }
    }

    #[test]
    fn resolves_valid_basic_auth_header() {
        let mut headers = HashMap::new();
        let encoded = BASE64_STANDARD.encode("alice@proton.me:secret");
        headers.insert("authorization".to_string(), format!("Basic {encoded}"));

        let context = resolve_basic_auth(&headers, &TestAuth).expect("auth should pass");
        assert_eq!(context.account_id, "uid-1");
    }

    #[test]
    fn rejects_missing_header() {
        let headers = HashMap::new();
        let err = resolve_basic_auth(&headers, &TestAuth).unwrap_err();
        assert_eq!(err, DavAuthError::MissingAuthorization);
    }
}
