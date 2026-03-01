use base64::engine::general_purpose::{
    STANDARD as BASE64, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use rand::distributions::Alphanumeric;
use rand::Rng as _;
use serde_json::{json, Value};
use tracing::{debug, info};

use super::client::{check_api_response, ProtonClient};
use super::error::Result;
use super::srp;
use super::types::{
    AuthInfoResponse, AuthResponse, HumanVerificationDetails, RefreshResponse, TwoFactorResponse,
};

const HV_TOKEN_HEADER: &str = "x-pm-human-verification-token";
const HV_TOKEN_TYPE_HEADER: &str = "x-pm-human-verification-token-type";

fn with_hv_headers(
    req: reqwest::RequestBuilder,
    hv_details: Option<&HumanVerificationDetails>,
) -> reqwest::RequestBuilder {
    let Some(hv) = hv_details.filter(|hv| hv.is_usable()) else {
        return req;
    };
    req.header(HV_TOKEN_HEADER, &hv.human_verification_token)
        .header(
            HV_TOKEN_TYPE_HEADER,
            hv.human_verification_methods.join(","),
        )
}

/// Perform SRP login against the Proton API.
///
/// Returns AuthResponse with session credentials. The client's auth headers
/// are set upon successful login.
pub async fn login(
    client: &mut ProtonClient,
    username: &str,
    password: &str,
    hv_details: Option<&HumanVerificationDetails>,
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
    if let Some(hv) = hv_details.filter(|hv| hv.is_usable()) {
        info!(
            methods = ?hv.human_verification_methods,
            token_len = hv.human_verification_token.len(),
            "submitting SRP auth with human verification headers"
        );
    } else {
        info!("submitting SRP auth");
    }
    let auth_body = json!({
        "Username": username,
        "ClientEphemeral": client_ephemeral,
        "ClientProof": client_proof,
        "SRPSession": auth_info.srp_session,
    });

    let auth_resp = with_hv_headers(client.post("/auth/v4"), hv_details)
        .json(&auth_body)
        .send()
        .await?;
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

/// Submit FIDO2 assertion payload for second-factor authentication.
///
/// `assertion_payload` accepts either a direct payload with
/// `clientData`/`authenticatorData`/`signature`/`credentialId` fields,
/// or a WebAuthn-style object containing `rawId` and `response`.
pub async fn submit_fido_2fa(
    client: &ProtonClient,
    authentication_options: &Value,
    assertion_payload: &[u8],
) -> Result<TwoFactorResponse> {
    info!("submitting FIDO2 assertion");

    let payload: Value = serde_json::from_slice(assertion_payload).map_err(|e| {
        super::error::ApiError::Auth(format!("invalid FIDO assertion payload: {e}"))
    })?;

    let client_data = extract_first_binary(
        &payload,
        &[
            &["clientData"],
            &["ClientData"],
            &["clientDataJSON"],
            &["response", "clientDataJSON"],
            &["response", "clientData"],
        ],
        "clientData",
    )?;
    let authenticator_data = extract_first_binary(
        &payload,
        &[
            &["authenticatorData"],
            &["AuthenticatorData"],
            &["response", "authenticatorData"],
        ],
        "authenticatorData",
    )?;
    let signature = extract_first_binary(
        &payload,
        &[&["signature"], &["Signature"], &["response", "signature"]],
        "signature",
    )?;
    let credential_id = extract_first_binary(
        &payload,
        &[
            &["credentialId"],
            &["credentialID"],
            &["CredentialID"],
            &["rawId"],
            &["RawId"],
            &["id"],
        ],
        "credentialId",
    )?;

    let credential_id_ints: Vec<i32> = credential_id.into_iter().map(i32::from).collect();
    let body = json!({
        "FIDO2": {
            "AuthenticationOptions": authentication_options,
            "ClientData": BASE64.encode(client_data),
            "AuthenticatorData": BASE64.encode(authenticator_data),
            "Signature": BASE64.encode(signature),
            "CredentialID": credential_id_ints,
        }
    });

    let resp = client.post("/auth/v4/2fa").json(&body).send().await?;
    let json: Value = resp.json().await?;
    check_api_response(&json)?;

    let result: TwoFactorResponse = serde_json::from_value(json)?;
    info!("FIDO2 assertion accepted");
    Ok(result)
}

fn extract_first_binary(payload: &Value, paths: &[&[&str]], field_name: &str) -> Result<Vec<u8>> {
    for path in paths {
        if let Some(value) = value_at_path(payload, path) {
            return decode_fido_binary(value, field_name);
        }
    }
    Err(super::error::ApiError::Auth(format!(
        "missing required FIDO assertion field: {field_name}"
    )))
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn decode_fido_binary(value: &Value, field_name: &str) -> Result<Vec<u8>> {
    match value {
        Value::String(data) => decode_base64_flexible(data).map_err(|err| {
            super::error::ApiError::Auth(format!(
                "invalid base64 encoding for FIDO field {field_name}: {err}"
            ))
        }),
        Value::Array(values) => {
            let mut bytes = Vec::with_capacity(values.len());
            for item in values {
                let Some(number) = item.as_u64() else {
                    return Err(super::error::ApiError::Auth(format!(
                        "invalid integer array for FIDO field {field_name}"
                    )));
                };
                let Ok(byte) = u8::try_from(number) else {
                    return Err(super::error::ApiError::Auth(format!(
                        "invalid byte value in FIDO field {field_name}"
                    )));
                };
                bytes.push(byte);
            }
            Ok(bytes)
        }
        _ => Err(super::error::ApiError::Auth(format!(
            "invalid value type for FIDO field {field_name}"
        ))),
    }
}

fn decode_base64_flexible(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    BASE64
        .decode(input)
        .or_else(|_| URL_SAFE_NO_PAD.decode(input))
        .or_else(|_| URL_SAFE.decode(input))
        .or_else(|_| STANDARD_NO_PAD.decode(input))
}

#[cfg(test)]
mod tests {
    use super::{build_refresh_body, decode_base64_flexible, extract_first_binary};
    use serde_json::json;

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

    #[test]
    fn test_extract_fido_binary_from_webauthn_shape() {
        let payload = json!({
            "rawId": "AQID",
            "response": {
                "clientDataJSON": "BAUG",
                "authenticatorData": "BwgJ",
                "signature": "CgsM"
            }
        });

        let client_data =
            extract_first_binary(&payload, &[&["response", "clientDataJSON"]], "clientData")
                .unwrap();
        let credential_id = extract_first_binary(&payload, &[&["rawId"]], "credentialId").unwrap();

        assert_eq!(client_data, vec![4, 5, 6]);
        assert_eq!(credential_id, vec![1, 2, 3]);
    }

    #[test]
    fn test_decode_base64_flexible_accepts_url_safe_no_pad() {
        let encoded = "AQIDBA";
        let decoded = decode_base64_flexible(encoded).unwrap();
        assert_eq!(decoded, vec![1, 2, 3, 4]);
    }
}
