use anyhow::Context;
use serde::Deserialize;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Request;

use crate::paths::RuntimePaths;

use super::pb;

const SERVER_TOKEN_METADATA_KEY: &str = "server-token";

#[derive(Debug, Clone, Deserialize)]
struct CliGrpcServerConfig {
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "cert")]
    cert: String,
    #[serde(rename = "token")]
    token: String,
}

pub struct CliGrpcClient {
    inner: pb::bridge_client::BridgeClient<Channel>,
    server_token: String,
}

impl CliGrpcClient {
    pub async fn connect(runtime_paths: &RuntimePaths) -> anyhow::Result<Self> {
        let server_config_path = runtime_paths.grpc_server_config_path();
        let payload = std::fs::read(&server_config_path)
            .with_context(|| format!("failed to read {}", server_config_path.display()))?;
        let config = parse_server_config(&payload).with_context(|| {
            format!(
                "invalid grpc server config {}",
                server_config_path.display()
            )
        })?;

        let endpoint = Endpoint::from_shared(format!("https://localhost:{}", config.port))
            .context("failed to build grpc endpoint URL")?
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(config.cert.clone()))
                    .domain_name("localhost"),
            )
            .context("failed to configure grpc TLS client")?;
        let channel = endpoint
            .connect()
            .await
            .context("failed to connect to grpc frontend service")?;

        Ok(Self {
            inner: pb::bridge_client::BridgeClient::new(channel),
            server_token: config.token,
        })
    }

    fn request_with_token<T>(&self, payload: T) -> anyhow::Result<Request<T>> {
        let request = Request::new(payload);
        attach_server_token(request, self.server_token.as_str())
    }

    pub async fn get_user_list(&mut self) -> anyhow::Result<Vec<pb::User>> {
        let request = self.request_with_token(())?;
        let response = self
            .inner
            .get_user_list(request)
            .await
            .map_err(|status| anyhow::anyhow!("grpc get_user_list failed: {status}"))?;
        Ok(response.into_inner().users)
    }

    pub async fn mail_server_settings(&mut self) -> anyhow::Result<pb::ImapSmtpSettings> {
        let request = self.request_with_token(())?;
        let response = self
            .inner
            .mail_server_settings(request)
            .await
            .map_err(|status| anyhow::anyhow!("grpc mail_server_settings failed: {status}"))?;
        Ok(response.into_inner())
    }

    pub async fn logout_user(&mut self, user_id: &str) -> anyhow::Result<()> {
        let request = self.request_with_token(user_id.to_string())?;
        self.inner
            .logout_user(request)
            .await
            .map_err(|status| anyhow::anyhow!("grpc logout_user failed: {status}"))?;
        Ok(())
    }

    pub async fn render_mutt_config(
        &mut self,
        account_selector: Option<&str>,
        address_override: Option<&str>,
        include_password: bool,
    ) -> anyhow::Result<String> {
        let request = self.request_with_token(pb::RenderMuttConfigRequest {
            account_selector: account_selector.unwrap_or_default().to_string(),
            address_override: address_override.unwrap_or_default().to_string(),
            include_password,
        })?;
        let response = self
            .inner
            .render_mutt_config(request)
            .await
            .map_err(|status| anyhow::anyhow!("grpc render_mutt_config failed: {status}"))?;
        Ok(response.into_inner().rendered_config)
    }
}

fn parse_server_config(payload: &[u8]) -> anyhow::Result<CliGrpcServerConfig> {
    let config: CliGrpcServerConfig =
        serde_json::from_slice(payload).context("failed to decode grpc server config json")?;
    validate_server_config(&config)?;
    Ok(config)
}

fn validate_server_config(config: &CliGrpcServerConfig) -> anyhow::Result<()> {
    if config.port == 0 {
        anyhow::bail!("grpc config port must be between 1 and 65535");
    }
    if config.cert.trim().is_empty() {
        anyhow::bail!("grpc config cert is missing");
    }
    if config.token.trim().is_empty() {
        anyhow::bail!("grpc config token is missing");
    }
    Ok(())
}

fn attach_server_token<T>(mut request: Request<T>, token: &str) -> anyhow::Result<Request<T>> {
    let value = MetadataValue::try_from(token)
        .context("grpc server token contains invalid metadata characters")?;
    request
        .metadata_mut()
        .insert(SERVER_TOKEN_METADATA_KEY, value);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_config_accepts_valid_payload() {
        let payload = serde_json::json!({
            "port": 1234,
            "cert": "pem",
            "token": "token-123"
        })
        .to_string();
        let parsed = parse_server_config(payload.as_bytes()).unwrap();
        assert_eq!(parsed.port, 1234);
        assert_eq!(parsed.cert, "pem");
        assert_eq!(parsed.token, "token-123");
    }

    #[test]
    fn parse_server_config_rejects_missing_token() {
        let payload = serde_json::json!({
            "port": 1234,
            "cert": "pem",
            "token": ""
        })
        .to_string();
        let err = parse_server_config(payload.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("token is missing"));
    }

    #[test]
    fn parse_server_config_rejects_zero_port() {
        let payload = serde_json::json!({
            "port": 0,
            "cert": "pem",
            "token": "token-123"
        })
        .to_string();
        let err = parse_server_config(payload.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("port must be between 1 and 65535"));
    }

    #[test]
    fn attach_server_token_sets_request_metadata() {
        let request = attach_server_token(Request::new(()), "abc123").unwrap();
        let stored = request
            .metadata()
            .get(SERVER_TOKEN_METADATA_KEY)
            .expect("server token metadata");
        assert_eq!(stored.to_str().unwrap(), "abc123");
    }
}
