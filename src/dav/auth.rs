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
    let authorization = headers
        .get("authorization")
        .ok_or(DavAuthError::MissingAuthorization)?;

    let encoded = authorization
        .strip_prefix("Basic ")
        .or_else(|| authorization.strip_prefix("basic "))
        .ok_or(DavAuthError::InvalidAuthorization)?
        .trim();

    let decoded = BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| DavAuthError::InvalidAuthorization)?;
    let decoded = String::from_utf8(decoded).map_err(|_| DavAuthError::InvalidAuthorization)?;
    let (username, password) = decoded
        .split_once(':')
        .ok_or(DavAuthError::InvalidAuthorization)?;

    auth_router
        .resolve_login(username, password)
        .ok_or(DavAuthError::InvalidCredentials)
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
