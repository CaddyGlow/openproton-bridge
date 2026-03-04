use tracing::info;

use super::client::{check_api_response, send_logged, ProtonClient};
use super::error::Result;
use super::types::PublicKeysResponse;

/// Fetch public keys for a recipient email address.
///
/// Reference: go-proton-api/keys.go GetPublicKeys
pub async fn get_public_keys(client: &ProtonClient, email: &str) -> Result<PublicKeysResponse> {
    info!(email = %email, "fetching public keys");
    let path = format!("/core/v4/keys?Email={}", email);
    let resp = send_logged(client.get(&path)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let keys_resp: PublicKeysResponse = serde_json::from_value(json)?;
    Ok(keys_resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_authenticated_client(server: &MockServer) -> ProtonClient {
        ProtonClient::authenticated(&server.uri(), "test-uid", "test-token").unwrap()
    }

    #[tokio::test]
    async fn test_get_public_keys_internal() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/keys"))
            .and(query_param("Email", "internal@proton.me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Keys": [{
                    "Flags": 3,
                    "PublicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfakekey\n-----END PGP PUBLIC KEY BLOCK-----"
                }],
                "RecipientType": 1
            })))
            .mount(&server)
            .await;

        let resp = get_public_keys(&client, "internal@proton.me")
            .await
            .unwrap();
        assert_eq!(resp.recipient_type, 1);
        assert_eq!(resp.keys.len(), 1);
        assert_eq!(resp.keys[0].flags, 3);
        assert!(resp.keys[0].public_key.contains("PGP PUBLIC KEY"));
    }

    #[tokio::test]
    async fn test_get_public_keys_external() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/keys"))
            .and(query_param("Email", "external@gmail.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Keys": [],
                "RecipientType": 2
            })))
            .mount(&server)
            .await;

        let resp = get_public_keys(&client, "external@gmail.com")
            .await
            .unwrap();
        assert_eq!(resp.recipient_type, 2);
        assert!(resp.keys.is_empty());
    }

    #[tokio::test]
    async fn test_get_public_keys_api_error() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 33101,
                "Error": "Invalid email address"
            })))
            .mount(&server)
            .await;

        let err = get_public_keys(&client, "bad").await.unwrap_err();
        assert!(err.to_string().contains("Invalid email address"));
    }
}
