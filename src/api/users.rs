use tracing::info;

use super::client::{check_api_response, send_logged, ProtonClient};
use super::error::Result;
use super::types::{AddressesResponse, SaltsResponse, UserResponse};

/// Fetch the authenticated user's info.
pub async fn get_user(client: &ProtonClient) -> Result<UserResponse> {
    info!("fetching user info");
    let resp = send_logged(client.get("/core/v4/users")).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let user_resp: UserResponse = serde_json::from_value(json)?;
    Ok(user_resp)
}

/// Fetch the authenticated user's addresses.
pub async fn get_addresses(client: &ProtonClient) -> Result<AddressesResponse> {
    info!("fetching addresses");
    let resp = send_logged(client.get("/core/v4/addresses")).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let addr_resp: AddressesResponse = serde_json::from_value(json)?;
    Ok(addr_resp)
}

/// Fetch key salts for the authenticated user.
pub async fn get_salts(client: &ProtonClient) -> Result<SaltsResponse> {
    info!("fetching key salts");
    let resp = send_logged(client.get("/core/v4/keys/salts")).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let salts_resp: SaltsResponse = serde_json::from_value(json)?;
    Ok(salts_resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_authenticated_client(server: &MockServer) -> ProtonClient {
        ProtonClient::authenticated(&server.uri(), "test-uid", "test-token").unwrap()
    }

    #[tokio::test]
    async fn test_get_user() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .and(header("x-pm-uid", "test-uid"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "User": {
                    "ID": "user-123",
                    "Name": "testuser",
                    "DisplayName": "Test User",
                    "Email": "test@proton.me",
                    "UsedSpace": 1024,
                    "MaxSpace": 2048,
                    "MaxUpload": 512,
                    "Credit": 42,
                    "Currency": "EUR",
                    "ProductUsedSpace": {
                        "Calendar": 11,
                        "Contact": 12,
                        "Drive": 13,
                        "Mail": 14,
                        "Pass": 15
                    },
                    "Keys": []
                }
            })))
            .mount(&server)
            .await;

        let resp = get_user(&client).await.unwrap();
        assert_eq!(resp.user.id, "user-123");
        assert_eq!(resp.user.name, "testuser");
        assert_eq!(resp.user.email, "test@proton.me");
        assert_eq!(resp.user.used_space, 1024);
        assert_eq!(resp.user.max_space, 2048);
        assert_eq!(resp.user.max_upload, 512);
        assert_eq!(resp.user.credit, 42);
        assert_eq!(resp.user.currency, "EUR");
        assert_eq!(resp.user.product_used_space.calendar, 11);
        assert_eq!(resp.user.product_used_space.contact, 12);
        assert_eq!(resp.user.product_used_space.drive, 13);
        assert_eq!(resp.user.product_used_space.mail, 14);
        assert_eq!(resp.user.product_used_space.pass, 15);
    }

    #[tokio::test]
    async fn test_get_user_api_error() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 401,
                "Error": "Invalid access token"
            })))
            .mount(&server)
            .await;

        let err = get_user(&client).await.unwrap_err();
        assert!(err.to_string().contains("Invalid access token"));
    }

    #[tokio::test]
    async fn test_get_addresses() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/addresses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Addresses": [{
                    "ID": "addr-1",
                    "Email": "test@proton.me",
                    "Status": 1,
                    "Receive": 1,
                    "Send": 1,
                    "Type": 1,
                    "DisplayName": "Test User",
                    "Keys": []
                }]
            })))
            .mount(&server)
            .await;

        let resp = get_addresses(&client).await.unwrap();
        assert_eq!(resp.addresses.len(), 1);
        assert_eq!(resp.addresses[0].email, "test@proton.me");
    }

    #[tokio::test]
    async fn test_get_salts() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/core/v4/keys/salts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "KeySalts": [
                    { "ID": "key-1", "KeySalt": "c2FsdDEyMw==" },
                    { "ID": "key-2", "KeySalt": null }
                ]
            })))
            .mount(&server)
            .await;

        let resp = get_salts(&client).await.unwrap();
        assert_eq!(resp.key_salts.len(), 2);
        assert_eq!(resp.key_salts[0].key_salt.as_deref(), Some("c2FsdDEyMw=="));
        assert!(resp.key_salts[1].key_salt.is_none());
    }
}
