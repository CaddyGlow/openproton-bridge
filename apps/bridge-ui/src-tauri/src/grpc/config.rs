use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const BRIDGE_GRPC_CONFIG_FILE: &str = "grpcServerConfig.json";
const FOCUS_GRPC_CONFIG_FILE: &str = "grpcFocusServerConfig.json";

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
    let mut paths = resolve_server_config_paths(explicit)?;
    Ok(paths.remove(0))
}

pub fn resolve_server_config_paths(explicit: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = explicit {
        return if path.exists() {
            Ok(vec![path.to_path_buf()])
        } else {
            Err(format!("config path does not exist: {}", path.display()))
        };
    }

    let candidates = resolve_server_config_candidates(None);
    let mut existing = Vec::new();
    for path in candidates {
        if path.exists() && !existing.iter().any(|candidate| candidate == &path) {
            existing.push(path);
        }
    }

    if !existing.is_empty() {
        return Ok(existing);
    }

    let mut focus_only = Vec::new();
    for path in default_focus_config_candidates() {
        if path.exists() && !focus_only.iter().any(|candidate| candidate == &path) {
            focus_only.push(path);
        }
    }

    if !focus_only.is_empty() {
        let found = focus_only
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "found {FOCUS_GRPC_CONFIG_FILE} ({found}) but missing {BRIDGE_GRPC_CONFIG_FILE}; focus config does not expose the bridge API"
        ));
    }

    Err(format!("could not resolve {BRIDGE_GRPC_CONFIG_FILE} path"))
}

pub fn resolve_server_config_candidates(explicit: Option<&Path>) -> Vec<PathBuf> {
    if let Some(path) = explicit {
        return vec![path.to_path_buf()];
    }
    dedupe_paths(default_bridge_config_candidates())
}

fn default_bridge_config_candidates() -> Vec<PathBuf> {
    default_config_candidates_for(BRIDGE_GRPC_CONFIG_FILE)
}

fn default_focus_config_candidates() -> Vec<PathBuf> {
    default_config_candidates_for(FOCUS_GRPC_CONFIG_FILE)
}

fn default_config_candidates_for(file_name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(path) = std::env::var("OPENPROTON_BRIDGE_GRPC_CONFIG") {
        candidates.push(PathBuf::from(path));
    }

    if let Some(config_home) = dirs::config_dir() {
        // Prefer the Proton Bridge runtime path to avoid stale legacy openproton config files.
        candidates.push(
            config_home
                .join("protonmail")
                .join("bridge-v3")
                .join(file_name),
        );
        candidates.push(config_home.join("openproton-bridge").join(file_name));
    }

    candidates.push(PathBuf::from(file_name));
    candidates
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.iter().any(|candidate| candidate == &path) {
            deduped.push(path);
        }
    }
    deduped
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
