use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;

use super::error::{ApiError, Result};
use super::types::ApiMode;

const DEFAULT_BRIDGE_APP_VERSION: &str = "3.22.0+git";
const DEFAULT_WEBMAIL_APP_VERSION: &str = "web-mail@5.0.103.3";
const DEFAULT_WEBMAIL_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

fn bridge_app_version() -> String {
    let bridge_version = std::env::var("OPENPROTON_PM_APP_VERSION")
        .unwrap_or_else(|_| DEFAULT_BRIDGE_APP_VERSION.to_string());
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        _ => "linux",
    };
    format!("{os}-bridge@{bridge_version}")
}

fn bridge_user_agent() -> String {
    if let Ok(user_agent) = std::env::var("OPENPROTON_PM_USER_AGENT") {
        if !user_agent.trim().is_empty() {
            return user_agent;
        }
    }
    let bridge_version = std::env::var("OPENPROTON_PM_APP_VERSION")
        .unwrap_or_else(|_| DEFAULT_BRIDGE_APP_VERSION.to_string());
    format!("ProtonMailBridge/{bridge_version}")
}

fn webmail_app_version() -> String {
    std::env::var("OPENPROTON_PM_WEBMAIL_APP_VERSION")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| DEFAULT_WEBMAIL_APP_VERSION.to_string())
}

fn webmail_user_agent() -> String {
    std::env::var("OPENPROTON_PM_WEBMAIL_USER_AGENT")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| DEFAULT_WEBMAIL_USER_AGENT.to_string())
}

fn mode_app_version(api_mode: ApiMode) -> String {
    match api_mode {
        ApiMode::Bridge => bridge_app_version(),
        ApiMode::Webmail => webmail_app_version(),
    }
}

fn mode_user_agent(api_mode: ApiMode) -> String {
    match api_mode {
        ApiMode::Bridge => bridge_user_agent(),
        ApiMode::Webmail => webmail_user_agent(),
    }
}

/// HTTP client preconfigured with Proton API headers.
#[derive(Debug, Clone)]
pub struct ProtonClient {
    client: Client,
    base_url: String,
    uid: Option<String>,
    access_token: Option<String>,
}

impl ProtonClient {
    /// Create unauthenticated client (for login).
    pub fn new() -> Result<Self> {
        Self::with_api_mode(ApiMode::Bridge)
    }

    /// Create unauthenticated client with a specific API mode.
    pub fn with_api_mode(api_mode: ApiMode) -> Result<Self> {
        Self::with_base_url_and_mode(api_mode.base_url(), api_mode)
    }

    /// Create client pointing at a custom base URL (for testing with wiremock).
    pub fn with_base_url(base_url: &str) -> Result<Self> {
        Self::with_base_url_and_mode(base_url, ApiMode::Bridge)
    }

    /// Create client pointing at a custom base URL and API mode.
    pub fn with_base_url_and_mode(base_url: &str, api_mode: ApiMode) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let app_version = mode_app_version(api_mode);
        let app_version_header = HeaderValue::from_str(&app_version)
            .map_err(|err| ApiError::Auth(format!("invalid app version header value: {err}")))?;
        headers.insert("x-pm-appversion", app_version_header);
        let user_agent = mode_user_agent(api_mode);
        let user_agent_header = HeaderValue::from_str(&user_agent)
            .map_err(|err| ApiError::Auth(format!("invalid user agent header value: {err}")))?;
        headers.insert("User-Agent", user_agent_header);

        let client = Client::builder()
            .default_headers(headers)
            .cookie_store(true)
            .build()
            .map_err(ApiError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
            uid: None,
            access_token: None,
        })
    }

    /// Create authenticated client from saved session.
    pub fn authenticated(base_url: &str, uid: &str, access_token: &str) -> Result<Self> {
        Self::authenticated_with_mode(base_url, ApiMode::Bridge, uid, access_token)
    }

    /// Create authenticated client from saved session with explicit API mode.
    pub fn authenticated_with_mode(
        base_url: &str,
        api_mode: ApiMode,
        uid: &str,
        access_token: &str,
    ) -> Result<Self> {
        let mut client = Self::with_base_url_and_mode(base_url, api_mode)?;
        client.set_auth(uid, access_token);
        Ok(client)
    }

    /// Set auth credentials after login.
    pub fn set_auth(&mut self, uid: &str, access_token: &str) {
        self.uid = Some(uid.to_string());
        self.access_token = Some(access_token.to_string());
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[tokio::test]
    async fn test_proton_client_persists_cookies_between_requests() {
        let server = MockServer::start().await;
        let client = ProtonClient::with_base_url(&server.uri()).unwrap();

        Mock::given(method("POST"))
            .and(path("/set-cookie"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Set-Cookie", "Session-Id=test-session; Path=/"),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/needs-cookie"))
            .and(header("cookie", "Session-Id=test-session"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        client.post("/set-cookie").send().await.unwrap();
        let response = client.post("/needs-cookie").send().await.unwrap();

        assert_eq!(response.status().as_u16(), 204);
    }
}
