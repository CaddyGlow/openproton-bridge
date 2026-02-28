use serde::{Deserialize, Serialize};

use crate::api::types::Session;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCheckpoint {
    pub last_event_id: String,
    pub last_event_ts: Option<i64>,
    pub sync_state: Option<String>,
}

pub trait SessionProvider: Send + Sync {
    fn list_sessions(&self) -> crate::vault::Result<Vec<Session>>;
    fn load_session_by_email(&self, email: &str) -> crate::vault::Result<Session>;
    fn save_session(&self, session: &Session) -> crate::vault::Result<()>;
}

pub trait AccountResolver: Send + Sync {
    fn resolve_account_id(&self, email: &str) -> Option<AccountId>;
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
