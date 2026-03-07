use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::bridge::auth_router::AuthRoute;
use crate::bridge::auth_router::AuthRouter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavAuthError {
    MissingAuthorization,
    InvalidAuthorization,
    InvalidCredentials,
}

pub fn resolve_basic_auth(
    headers: &HashMap<String, String>,
    auth_router: &AuthRouter,
) -> std::result::Result<AuthRoute, DavAuthError> {
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

    let route = auth_router
        .resolve_login(username, password)
        .ok_or(DavAuthError::InvalidCredentials);
    match &route {
        Ok(resolved) => tracing::trace!(
            username = username,
            account_id = resolved.account_id.0,
            "dav auth check: credentials resolved"
        ),
        Err(_) => tracing::trace!(
            username = username,
            "dav auth check: credentials did not match any active account"
        ),
    }
    route
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;

    use crate::api::types::Session;
    use crate::bridge::accounts::AccountRegistry;
    use crate::bridge::auth_router::AuthRouter;

    use super::{resolve_basic_auth, DavAuthError};

    fn session(uid: &str, email: &str, bridge_password: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: String::new(),
            refresh_token: "refresh-token".to_string(),
            email: email.to_string(),
            display_name: email.to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some(bridge_password.to_string()),
        }
    }

    #[test]
    fn resolves_valid_basic_auth_header() {
        let router = AuthRouter::new(AccountRegistry::from_single_session(session(
            "uid-1",
            "alice@proton.me",
            "secret",
        )));
        let mut headers = HashMap::new();
        let encoded = BASE64_STANDARD.encode("alice@proton.me:secret");
        headers.insert("authorization".to_string(), format!("Basic {encoded}"));

        let route = resolve_basic_auth(&headers, &router).expect("auth should pass");
        assert_eq!(route.account_id.0, "uid-1");
    }

    #[test]
    fn rejects_missing_header() {
        let router = AuthRouter::default();
        let headers = HashMap::new();
        let err = resolve_basic_auth(&headers, &router).unwrap_err();
        assert_eq!(err, DavAuthError::MissingAuthorization);
    }
}
