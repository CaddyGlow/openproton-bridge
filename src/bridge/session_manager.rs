use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::api::types::Session;

use super::accounts::{AccountRuntimeError, RuntimeAccountInfo, RuntimeAccountRegistry};
use super::types::AccountId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshReason {
    MissingAccessToken,
    ExplicitRefresh,
    AuthFailure { stale_access_token: Option<String> },
    StartupBootstrap,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("account unavailable: {0}")]
    AccountUnavailable(String),
    #[error("refresh failed: {0}")]
    Refresh(crate::api::error::ApiError),
    #[error("persistence failed: {0}")]
    Persistence(crate::vault::VaultError),
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
}

#[allow(async_fn_in_trait)]
pub trait RuntimeSessionProvider {
    async fn session(&self, account_id: &AccountId) -> Option<Session>;
    async fn valid_session(&self, account_id: &AccountId) -> Result<Session, SessionError>;
    async fn refresh_session(
        &self,
        account_id: &AccountId,
        reason: RefreshReason,
    ) -> Result<Session, SessionError>;
}

#[derive(Debug)]
pub struct SessionManager {
    runtime_accounts: Arc<RuntimeAccountRegistry>,
    vault_dir: Option<PathBuf>,
}

impl SessionManager {
    pub fn new(vault_dir: PathBuf) -> Self {
        Self {
            runtime_accounts: Arc::new(RuntimeAccountRegistry::new(Vec::new(), vault_dir.clone())),
            vault_dir: Some(vault_dir),
        }
    }

    #[cfg(test)]
    pub fn in_memory(sessions: Vec<Session>) -> Self {
        Self {
            runtime_accounts: Arc::new(RuntimeAccountRegistry::in_memory(sessions)),
            vault_dir: None,
        }
    }

    pub fn runtime_accounts(&self) -> Arc<RuntimeAccountRegistry> {
        self.runtime_accounts.clone()
    }

    pub async fn active_sessions(&self) -> Vec<Session> {
        self.load_sessions_from_vault().await.unwrap_or_default()
    }

    pub async fn session(&self, account_id: &AccountId) -> Option<Session> {
        self.runtime_accounts.get_session(account_id).await
    }

    pub async fn upsert_session(&self, session: Session) -> Result<Session, SessionError> {
        self.seed_session(session).await
    }

    pub async fn load_or_seed_session(&self, session: Session) -> Result<Session, SessionError> {
        if session.uid.trim().is_empty() {
            return Err(SessionError::InvalidState("session uid is empty"));
        }
        if session.refresh_token.trim().is_empty() {
            return Err(SessionError::InvalidState("session refresh token is empty"));
        }

        self.runtime_accounts
            .load_or_seed_session(session)
            .await
            .map_err(SessionError::from)
    }

    pub async fn load_sessions_from_vault(&self) -> Result<Vec<Session>, SessionError> {
        let Some(vault_dir) = self.vault_dir.as_deref() else {
            return Ok(self.runtime_accounts.active_sessions().await);
        };

        let sessions = crate::vault::list_sessions(vault_dir).map_err(SessionError::Persistence)?;
        for session in sessions {
            self.seed_session(session).await?;
        }
        Ok(self.runtime_accounts.active_sessions().await)
    }

    pub async fn has_sessions(&self) -> Result<bool, SessionError> {
        Ok(!self.load_sessions_from_vault().await?.is_empty())
    }

    pub async fn seed_session(&self, session: Session) -> Result<Session, SessionError> {
        if session.uid.trim().is_empty() {
            return Err(SessionError::InvalidState("session uid is empty"));
        }
        if session.refresh_token.trim().is_empty() {
            return Err(SessionError::InvalidState("session refresh token is empty"));
        }

        let account_id = AccountId(session.uid.clone());
        let merged = match self.runtime_accounts.get_session(&account_id).await {
            Some(existing) => merge_session_snapshot(existing, session),
            None => session,
        };
        self.runtime_accounts
            .upsert_session(merged.clone())
            .await
            .map_err(SessionError::from)?;
        Ok(merged)
    }

    pub async fn persist_session(
        &self,
        session: Session,
        canonical_user_id: Option<&str>,
    ) -> Result<Session, SessionError> {
        if let Some(vault_dir) = self.vault_dir.as_deref() {
            crate::vault::save_session_with_user_id(&session, canonical_user_id, vault_dir)
                .map_err(SessionError::Persistence)?;
        }
        self.seed_session(session).await
    }

    pub async fn snapshot(&self) -> Vec<RuntimeAccountInfo> {
        self.runtime_accounts.snapshot().await
    }

    pub async fn remove_session(&self, account_id: &AccountId) -> Result<(), SessionError> {
        self.runtime_accounts
            .remove_session(account_id)
            .await
            .map_err(SessionError::from)
    }

    pub async fn remove_all_sessions(&self) {
        self.runtime_accounts.remove_all_sessions().await;
    }

    pub async fn with_valid_access_token(
        &self,
        account_id: &AccountId,
    ) -> Result<Session, SessionError> {
        self.valid_session(account_id).await
    }

    pub async fn valid_session(&self, account_id: &AccountId) -> Result<Session, SessionError> {
        self.runtime_accounts
            .with_valid_access_token(account_id)
            .await
            .map_err(SessionError::from)
    }

    pub async fn refresh_session(
        &self,
        account_id: &AccountId,
        reason: RefreshReason,
    ) -> Result<Session, SessionError> {
        let result = match reason {
            RefreshReason::MissingAccessToken | RefreshReason::StartupBootstrap => {
                self.runtime_accounts
                    .refresh_session_if_stale(account_id, Some(""))
                    .await
            }
            RefreshReason::ExplicitRefresh => {
                self.runtime_accounts.refresh_session(account_id).await
            }
            RefreshReason::AuthFailure { stale_access_token } => {
                self.runtime_accounts
                    .refresh_session_if_stale(account_id, stale_access_token.as_deref())
                    .await
            }
        };

        result.map_err(SessionError::from)
    }

    pub async fn refresh_session_if_stale(
        &self,
        account_id: &AccountId,
        stale_access_token: Option<&str>,
    ) -> Result<Session, SessionError> {
        self.refresh_session(
            account_id,
            RefreshReason::AuthFailure {
                stale_access_token: stale_access_token.map(str::to_string),
            },
        )
        .await
    }

    pub async fn refresh_and_persist_session(
        session: Session,
        settings_dir: &Path,
    ) -> Result<Session, SessionError> {
        let manager = Self::new(settings_dir.to_path_buf());
        let account_id = AccountId(session.uid.clone());
        manager.seed_session(session).await?;
        manager
            .refresh_session(&account_id, RefreshReason::ExplicitRefresh)
            .await
    }
}

impl RuntimeSessionProvider for SessionManager {
    async fn session(&self, account_id: &AccountId) -> Option<Session> {
        SessionManager::session(self, account_id).await
    }

    async fn valid_session(&self, account_id: &AccountId) -> Result<Session, SessionError> {
        SessionManager::valid_session(self, account_id).await
    }

    async fn refresh_session(
        &self,
        account_id: &AccountId,
        reason: RefreshReason,
    ) -> Result<Session, SessionError> {
        SessionManager::refresh_session(self, account_id, reason).await
    }
}

impl From<AccountRuntimeError> for SessionError {
    fn from(value: AccountRuntimeError) -> Self {
        match value {
            AccountRuntimeError::AccountNotFound(account_id) => Self::AccountNotFound(account_id),
            AccountRuntimeError::AccountUnavailable(account_id) => {
                Self::AccountUnavailable(account_id)
            }
            AccountRuntimeError::Api(err) => Self::Refresh(err),
            AccountRuntimeError::Vault(err) => Self::Persistence(err),
        }
    }
}

fn merge_session_snapshot(existing: Session, incoming: Session) -> Session {
    Session {
        uid: incoming.uid,
        access_token: if incoming.access_token.trim().is_empty() {
            existing.access_token
        } else {
            incoming.access_token
        },
        refresh_token: if incoming.refresh_token.trim().is_empty() {
            existing.refresh_token
        } else {
            incoming.refresh_token
        },
        email: if incoming.email.trim().is_empty() {
            existing.email
        } else {
            incoming.email
        },
        display_name: if incoming.display_name.trim().is_empty() {
            existing.display_name
        } else {
            incoming.display_name
        },
        api_mode: incoming.api_mode,
        key_passphrase: incoming.key_passphrase.or(existing.key_passphrase),
        bridge_password: incoming.bridge_password.or(existing.bridge_password),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(uid: &str, access_token: &str, refresh_token: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: access_token.to_string(),
            refresh_token: refresh_token.to_string(),
            email: format!("{uid}@example.com"),
            display_name: uid.to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-password".to_string()),
        }
    }

    #[tokio::test]
    async fn seed_session_preserves_runtime_access_token_when_vault_snapshot_is_empty() {
        let manager = SessionManager::in_memory(vec![session("uid-1", "live-token", "refresh-a")]);

        let merged = manager
            .seed_session(session("uid-1", "", "refresh-b"))
            .await
            .unwrap();

        assert_eq!(merged.access_token, "live-token");
        assert_eq!(merged.refresh_token, "refresh-b");
    }

    #[tokio::test]
    async fn load_or_seed_session_preserves_existing_runtime_tokens() {
        let manager =
            SessionManager::in_memory(vec![session("uid-1", "live-token", "refresh-new")]);

        let loaded = manager
            .load_or_seed_session(session("uid-1", "stale-token", "refresh-old"))
            .await
            .unwrap();

        assert_eq!(loaded.access_token, "live-token");
        assert_eq!(loaded.refresh_token, "refresh-new");
        assert_eq!(
            manager
                .session(&AccountId("uid-1".to_string()))
                .await
                .unwrap()
                .access_token,
            "live-token"
        );
    }

    #[tokio::test]
    async fn load_or_seed_session_seeds_missing_runtime_session() {
        let manager = SessionManager::in_memory(Vec::new());
        let incoming = session("uid-1", "seed-token", "refresh-a");

        let loaded = manager
            .load_or_seed_session(incoming.clone())
            .await
            .unwrap();

        assert_eq!(loaded.uid, incoming.uid);
        assert_eq!(loaded.access_token, incoming.access_token);
        assert_eq!(loaded.refresh_token, incoming.refresh_token);

        let stored = manager
            .session(&AccountId("uid-1".to_string()))
            .await
            .unwrap();
        assert_eq!(stored.uid, "uid-1");
        assert_eq!(stored.access_token, "seed-token");
        assert_eq!(stored.refresh_token, "refresh-a");
    }
}
