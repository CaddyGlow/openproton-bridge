use rand::distributions::Alphanumeric;
use rand::Rng as _;
use serde_json::json;
use tracing::{debug, info};

use super::client::{check_api_response, ProtonClient};
use super::error::Result;
use super::srp;
use super::types::{AuthInfoResponse, AuthResponse, RefreshResponse, TwoFactorResponse};

/// Perform SRP login against the Proton API.
///
/// Returns AuthResponse with session credentials. The client's auth headers
/// are set upon successful login.
pub async fn login(
    client: &mut ProtonClient,
    username: &str,
    password: &str,
) -> Result<AuthResponse> {
    // Step 1: Get auth info (salt, server ephemeral, modulus)
    info!(username = ?username, "fetching auth info");
    let info_body = json!({ "Username": username });

    let info_resp = client.post("/auth/v4/info").json(&info_body).send().await?;
    let info_json: serde_json::Value = info_resp.json().await?;
    check_api_response(&info_json)?;

    let auth_info: AuthInfoResponse = serde_json::from_value(info_json)?;
    debug!(version = ?auth_info.version, "SRP version");

    // Step 2: Decode modulus, hash password, compute SRP proof
    let (modulus, modulus_le) = srp::decode_modulus(&auth_info.modulus)?;
    let hashed = srp::hash_password(password, &auth_info.salt, &modulus_le)?;
    let (client_ephemeral, client_proof, expected_server_proof) =
        srp::compute_srp_proof(&hashed, &auth_info.server_ephemeral, &modulus)?;

    // Step 3: Submit auth request
    info!("submitting SRP auth");
    let auth_body = json!({
        "Username": username,
        "ClientEphemeral": client_ephemeral,
        "ClientProof": client_proof,
        "SRPSession": auth_info.srp_session,
    });

    let auth_resp = client.post("/auth/v4").json(&auth_body).send().await?;
    let auth_json: serde_json::Value = auth_resp.json().await?;
    check_api_response(&auth_json)?;

    let auth: AuthResponse = serde_json::from_value(auth_json)?;

    // Step 4: Verify server proof
    srp::verify_server_proof(&expected_server_proof, &auth.server_proof)?;
    info!("server proof verified");

    // Set auth credentials on the client
    client.set_auth(&auth.uid, &auth.access_token);

    Ok(auth)
}

fn build_refresh_body(
    uid: &str,
    refresh_token: &str,
    access_token: Option<&str>,
) -> serde_json::Value {
    let state: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let mut body = json!({
        "UID": uid,
        "RefreshToken": refresh_token,
        "GrantType": "refresh_token",
        "ResponseType": "token",
        "RedirectURI": "https://protonmail.ch",
        "State": state,
    });

    if let Some(token) = access_token.filter(|token| !token.is_empty()) {
        body["AccessToken"] = json!(token);
    }

    body
}

/// Refresh an expired access token using the refresh token.
///
/// On success, updates the client's auth credentials in-place
/// and returns the new access/refresh token pair.
pub async fn refresh_auth(
    client: &mut ProtonClient,
    uid: &str,
    refresh_token: &str,
    access_token: Option<&str>,
) -> Result<RefreshResponse> {
    let body = build_refresh_body(uid, refresh_token, access_token);

    let resp = client.post("/auth/v4/refresh").json(&body).send().await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;

    let mut auth: RefreshResponse = serde_json::from_value(json)?;
    if auth.uid.is_empty() {
        auth.uid = uid.to_string();
    }
    client.set_auth(&auth.uid, &auth.access_token);

    Ok(auth)
}

#[cfg(test)]
mod tests {
    use super::build_refresh_body;

    #[test]
    fn test_build_refresh_body_without_access_token() {
        let body = build_refresh_body("uid-1", "refresh-1", None);
        assert_eq!(body["UID"], "uid-1");
        assert_eq!(body["RefreshToken"], "refresh-1");
        assert_eq!(body["GrantType"], "refresh_token");
        assert_eq!(body["ResponseType"], "token");
        assert_eq!(body["RedirectURI"], "https://protonmail.ch");
        assert!(body.get("AccessToken").is_none());
        assert_eq!(
            body["State"]
                .as_str()
                .expect("state should be present")
                .len(),
            32
        );
    }

    #[test]
    fn test_build_refresh_body_with_access_token() {
        let body = build_refresh_body("uid-1", "refresh-1", Some("access-1"));
        assert_eq!(body["AccessToken"], "access-1");
    }
}

/// Submit TOTP 2FA code.
pub async fn submit_2fa(client: &ProtonClient, code: &str) -> Result<TwoFactorResponse> {
    info!("submitting 2FA code");
    let body = json!({ "TwoFactorCode": code });

    let resp = client.post("/auth/v4/2fa").json(&body).send().await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;

    let result: TwoFactorResponse = serde_json::from_value(json)?;
    info!("2FA accepted");
    Ok(result)
}
