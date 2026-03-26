use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SyncStateFile {
    version: i32,
    data: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncStateStatus {
    pub has_labels: bool,
    pub has_messages: bool,
    pub has_message_count: bool,
    #[serde(default)]
    pub failed_message_i_ds: HashSet<String>,
    #[serde(rename = "LastSyncedMessageID")]
    #[serde(default)]
    pub last_synced_message_id: String,
    pub num_synced_messages: i64,
    pub total_message_count: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SyncStateData {
    status: SyncStateStatus,
}

fn sync_state_path(settings_dir: &Path, user_id: &str) -> std::path::PathBuf {
    settings_dir
        .join("imap-sync")
        .join(format!("sync-{user_id}"))
}

pub fn clear_sync_state(settings_dir: &Path, user_id: &str) -> Result<(), SyncStateError> {
    let path = sync_state_path(settings_dir, user_id);
    if path.exists() {
        fs::remove_file(&path).map_err(SyncStateError::Io)?;
    }
    Ok(())
}

pub fn load_sync_state(
    settings_dir: &Path,
    user_id: &str,
) -> Result<SyncStateStatus, SyncStateError> {
    let path = sync_state_path(settings_dir, user_id);
    if !path.exists() {
        return Ok(SyncStateStatus::default());
    }
    let raw = fs::read_to_string(&path).map_err(SyncStateError::Io)?;
    let file: SyncStateFile = serde_json::from_str(&raw).map_err(SyncStateError::Json)?;
    let data: SyncStateData = serde_json::from_str(&file.data).map_err(SyncStateError::Json)?;
    debug!(user_id = %user_id, num_synced = data.status.num_synced_messages, "loaded sync state");
    Ok(data.status)
}

pub fn save_sync_state(
    settings_dir: &Path,
    user_id: &str,
    status: &SyncStateStatus,
) -> Result<(), SyncStateError> {
    let dir = settings_dir.join("imap-sync");
    fs::create_dir_all(&dir).map_err(SyncStateError::Io)?;

    let data = SyncStateData {
        status: status.clone(),
    };
    let data_json = serde_json::to_string(&data).map_err(SyncStateError::Json)?;
    let file = SyncStateFile {
        version: 1,
        data: data_json,
    };
    let json = serde_json::to_string(&file).map_err(SyncStateError::Json)?;

    let path = sync_state_path(settings_dir, user_id);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json.as_bytes()).map_err(SyncStateError::Io)?;
    fs::rename(&tmp, &path).map_err(SyncStateError::Io)?;

    debug!(
        user_id = %user_id,
        num_synced = status.num_synced_messages,
        last_id = %status.last_synced_message_id,
        "saved sync state"
    );
    Ok(())
}

#[derive(Debug)]
pub enum SyncStateError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for SyncStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "sync state I/O error: {e}"),
            Self::Json(e) => write!(f, "sync state JSON error: {e}"),
        }
    }
}

impl std::error::Error for SyncStateError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_roundtrip_sync_state() {
        let dir = TempDir::new().unwrap();
        let user_id = "abc123";

        let mut status = SyncStateStatus::default();
        status.has_labels = true;
        status.num_synced_messages = 42;
        status.total_message_count = 100;
        status.last_synced_message_id = "msg-42".to_string();

        save_sync_state(dir.path(), user_id, &status).unwrap();
        let loaded = load_sync_state(dir.path(), user_id).unwrap();

        assert_eq!(loaded.has_labels, true);
        assert_eq!(loaded.num_synced_messages, 42);
        assert_eq!(loaded.total_message_count, 100);
        assert_eq!(loaded.last_synced_message_id, "msg-42");
        assert_eq!(loaded.has_messages, false);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let dir = TempDir::new().unwrap();
        let status = load_sync_state(dir.path(), "no-such-user").unwrap();
        assert_eq!(status.num_synced_messages, 0);
        assert_eq!(status.last_synced_message_id, "");
    }

    #[test]
    fn test_go_bridge_format_compat() {
        let dir = TempDir::new().unwrap();
        let user_id = "user-1";

        // Write in Go bridge format
        let go_json = r#"{"Version":1,"Data":"{\"Status\":{\"HasLabels\":true,\"HasMessages\":false,\"HasMessageCount\":true,\"FailedMessageIDs\":[],\"LastSyncedMessageID\":\"msg-768\",\"NumSyncedMessages\":768,\"TotalMessageCount\":3957}}"}"#;
        let sync_dir = dir.path().join("imap-sync");
        fs::create_dir_all(&sync_dir).unwrap();
        fs::write(sync_dir.join(format!("sync-{user_id}")), go_json).unwrap();

        let status = load_sync_state(dir.path(), user_id).unwrap();
        assert_eq!(status.has_labels, true);
        assert_eq!(status.has_messages, false);
        assert_eq!(status.has_message_count, true);
        assert_eq!(status.last_synced_message_id, "msg-768");
        assert_eq!(status.num_synced_messages, 768);
        assert_eq!(status.total_message_count, 3957);
    }
}
