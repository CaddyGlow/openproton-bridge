use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct GrpcServerConfig {
    pub port: Option<u16>,
    pub cert: String,
    pub token: String,
    #[serde(rename = "fileSocketPath")]
    pub file_socket_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct GrpcClientTokenConfig<'a> {
    token: &'a str,
}

impl GrpcServerConfig {
    pub fn from_json_file(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

        serde_json::from_str(&data)
            .map_err(|err| format!("invalid config {}: {err}", path.display()))
    }
}

pub fn resolve_server_config_path(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return if path.exists() {
            Ok(path.to_path_buf())
        } else {
            Err(format!("config path does not exist: {}", path.display()))
        };
    }

    let mut candidates = Vec::new();

    if let Ok(path) = std::env::var("OPENPROTON_BRIDGE_GRPC_CONFIG") {
        candidates.push(PathBuf::from(path));
    }

    if let Some(config_home) = dirs::config_dir() {
        candidates.push(
            config_home
                .join("openproton-bridge")
                .join("grpcServerConfig.json"),
        );
        candidates.push(
            config_home
                .join("protonmail")
                .join("bridge-v3")
                .join("grpcServerConfig.json"),
        );
    }

    candidates.push(PathBuf::from("grpcServerConfig.json"));

    candidates
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| "could not resolve grpcServerConfig.json path".to_string())
}

pub fn write_temp_client_token_file(token: &str) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!("bridge-ui-grpc-client-{}.json", Uuid::new_v4()));
    let json = serde_json::to_string(&GrpcClientTokenConfig { token })
        .map_err(|err| format!("failed to encode client token config: {err}"))?;

    fs::write(&path, json).map_err(|err| {
        format!(
            "failed to write temporary token file {}: {err}",
            path.display()
        )
    })?;

    Ok(path)
}
