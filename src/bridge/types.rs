use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointSyncState {
    BaselineCursor,
    CursorResetResync,
    RefreshResync,
    Refresh,
    More,
    Ok,
}

impl CheckpointSyncState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BaselineCursor => "baseline_cursor",
            Self::CursorResetResync => "cursor_reset_resync",
            Self::RefreshResync => "refresh_resync",
            Self::Refresh => "refresh",
            Self::More => "more",
            Self::Ok => "ok",
        }
    }
}

impl std::fmt::Display for CheckpointSyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCheckpoint {
    pub last_event_id: String,
    pub last_event_ts: Option<i64>,
    pub sync_state: Option<CheckpointSyncState>,
}

pub trait EventCheckpointStore: Send + Sync {
    type Error;

    fn load_checkpoint(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<Option<EventCheckpoint>, Self::Error>;

    fn save_checkpoint(
        &self,
        account_id: &AccountId,
        checkpoint: &EventCheckpoint,
    ) -> std::result::Result<(), Self::Error>;
}
