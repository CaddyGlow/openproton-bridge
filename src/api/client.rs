use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;

use super::error::{ApiError, Result};
use super::types::HumanVerificationDetails;

const BASE_URL: &str = "https://mail-api.proton.me";
const APP_VERSION: &str = "web-mail@5.0.103.3";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// HTTP client preconfigured with Proton API headers.
#[derive(Debug, Clone)]
pub struct ProtonClient {
    client: Client,
    base_url: String,
    uid: Option<String>,
    access_token: Option<String>,
    hv_token: Option<String>,
    hv_methods: Option<String>,
}

impl ProtonClient {
    /// Create unauthenticated client (for login).
    pub fn new() -> Result<Self> {
        Self::with_base_url(BASE_URL)
    }

    /// Create client pointing at a custom base URL (for testing with wiremock).
    pub fn with_base_url(base_url: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("x-pm-appversion", HeaderValue::from_static(APP_VERSION));
        headers.insert("User-Agent", HeaderValue::from_static(USER_AGENT));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(ApiError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
            uid: None,
            access_token: None,
            hv_token: None,
            hv_methods: None,
        })
    }

    /// Create authenticated client from saved session.
    pub fn authenticated(base_url: &str, uid: &str, access_token: &str) -> Result<Self> {
        let mut client = Self::with_base_url(base_url)?;
        client.set_auth(uid, access_token);
        Ok(client)
    }

    /// Set auth credentials after login.
    pub fn set_auth(&mut self, uid: &str, access_token: &str) {
        self.uid = Some(uid.to_string());
        self.access_token = Some(access_token.to_string());
    }

    /// Set or clear human verification headers used for CAPTCHA challenges.
    pub fn set_human_verification(&mut self, details: Option<&HumanVerificationDetails>) {
        if let Some(details) = details {
            if details.is_usable() {
                self.hv_token = Some(details.human_verification_token.clone());
                self.hv_methods = Some(details.human_verification_methods.join(","));
                return;
            }
        }
        self.hv_token = None;
        self.hv_methods = None;
    }

    /// Build a GET request with auth headers.
    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url);
        req = self.add_auth_headers(req);
        req
    }

    /// Build a POST request with auth headers.
    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.post(&url);
        req = self.add_auth_headers(req);
        req
    }

    /// Build a PUT request with auth headers.
    pub fn put(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.put(&url);
        req = self.add_auth_headers(req);
        req
    }

    /// Build a DELETE request with auth headers.
    pub fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.delete(&url);
        req = self.add_auth_headers(req);
        req
    }

    fn add_auth_headers(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(uid) = &self.uid {
            req = req.header("x-pm-uid", uid);
        }
        if let Some(token) = &self.access_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(hv_token) = &self.hv_token {
            req = req.header("x-pm-human-verification-token", hv_token);
        }
        if let Some(hv_methods) = &self.hv_methods {
            req = req.header("x-pm-human-verification-token-type", hv_methods);
        }
        req
    }
}

/// Check API response JSON for error codes.
/// Proton API returns Code: 1000 for success.
pub fn check_api_response(json: &serde_json::Value) -> Result<()> {
    if let Some(code) = json.get("Code").and_then(|c| c.as_i64()) {
        if code != 1000 {
            let message = json
                .get("Error")
                .and_then(|e| e.as_str())
                .unwrap_or("Unknown API error")
                .to_string();
            let details = json.get("Details").cloned();
            return Err(ApiError::Api {
                code,
                message,
                details,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_api_response_success() {
        let json = serde_json::json!({"Code": 1000});
        check_api_response(&json).unwrap();
    }

    #[test]
    fn test_check_api_response_error() {
        let json = serde_json::json!({"Code": 8002, "Error": "Invalid credentials"});
        let err = check_api_response(&json).unwrap_err();
        match err {
            ApiError::Api {
                code,
                message,
                details,
            } => {
                assert_eq!(code, 8002);
                assert_eq!(message, "Invalid credentials");
                assert_eq!(details, None);
            }
            _ => panic!("expected ApiError::Api"),
        }
    }

    #[test]
    fn test_check_api_response_error_no_message() {
        let json = serde_json::json!({"Code": 9999});
        let err = check_api_response(&json).unwrap_err();
        match err {
            ApiError::Api {
                code,
                message,
                details,
            } => {
                assert_eq!(code, 9999);
                assert_eq!(message, "Unknown API error");
                assert_eq!(details, None);
            }
            _ => panic!("expected ApiError::Api"),
        }
    }

    #[test]
    fn test_check_api_response_error_with_details() {
        let json = serde_json::json!({
            "Code": 9001,
            "Error": "Human verification required",
            "Details": {
                "HumanVerificationMethods": ["captcha"],
                "HumanVerificationToken": "token-123"
            }
        });
        let err = check_api_response(&json).unwrap_err();
        match err {
            ApiError::Api {
                code,
                message,
                details,
            } => {
                assert_eq!(code, 9001);
                assert_eq!(message, "Human verification required");
                assert!(details.is_some());
            }
            _ => panic!("expected ApiError::Api"),
        }
    }

    #[test]
    fn test_check_api_response_no_code() {
        let json = serde_json::json!({"Data": "something"});
        check_api_response(&json).unwrap();
    }

    #[test]
    fn test_proton_client_new() {
        let client = ProtonClient::new().unwrap();
        assert!(client.uid.is_none());
        assert!(client.access_token.is_none());
    }

    #[test]
    fn test_proton_client_set_auth() {
        let mut client = ProtonClient::new().unwrap();
        client.set_auth("test-uid", "test-token");
        assert_eq!(client.uid.as_deref(), Some("test-uid"));
        assert_eq!(client.access_token.as_deref(), Some("test-token"));
    }

    #[test]
    fn test_proton_client_with_base_url() {
        let client = ProtonClient::with_base_url("http://localhost:9999").unwrap();
        assert_eq!(client.base_url, "http://localhost:9999");
    }
}
